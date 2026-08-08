from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shared.artifact_contracts import new_artifact_envelope, validate_receipt
from shared.artifact_custody import ArtifactCustody, CustodyError
from shared.trust_contracts import (
    ContractError,
    build_signed_artifact,
    build_signing_request,
    canonical_json_line,
    signing_bytes,
)

SCHEMA_REF = "issue-291-phase-b-test-payload-v1"
SCHEMAS = {
    SCHEMA_REF: {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "required": ["value", "production", "live", "countable_forward"],
        "properties": {
            "value": {"type": "integer"},
            "production": {"const": False},
            "live": {"const": False},
            "countable_forward": {"const": False},
        },
    }
}


def artifact(
    value: int = 1,
    *,
    predecessors: list[dict[str, str]] | None = None,
    lineage: list[str] | None = None,
    live: bool = False,
) -> dict:
    return new_artifact_envelope(
        artifact_type="test-evidence",
        trust_domain="research",
        producer_id="unit-test",
        producer_version="v1",
        schema_ref=SCHEMA_REF,
        payload={
            "value": value,
            "production": False,
            "live": live,
            "countable_forward": False,
        },
        generated_at="2026-08-05T00:00:00Z",
        scope={"production": False, "live": False, "countable_forward": False},
        predecessor_refs=predecessors or [],
        lineage=lineage or [],
    )


def custody(root: Path, epoch: int = 1) -> ArtifactCustody:
    return ArtifactCustody(
        root,
        writer_id="custody-a",
        writer_epoch=epoch,
        schema_registry=SCHEMAS,
        clock=lambda: "2026-08-05T00:00:01Z",
    )


def test_publish_install_consume_revoke_are_append_only_and_idempotent(
    tmp_path: Path,
) -> None:
    root = tmp_path / "custody"
    item = artifact()
    with custody(root) as store:
        published = store.publish(
            item,
            actor_id="producer",
            idempotency_key="pub-1",
            correlation_id="corr-1",
            expected_version=0,
        )
        assert published["receipt_type"] == "publish"
        assert (
            store.publish(
                item,
                actor_id="producer",
                idempotency_key="pub-1",
                correlation_id="corr-1",
                expected_version=0,
            )
            == published
        )
        installed = store.record(
            "install",
            item["artifact_id"],
            actor_id="installer",
            idempotency_key="install-1",
            correlation_id="corr-1",
            expected_version=1,
        )
        consumed = store.record(
            "consume",
            item["artifact_id"],
            actor_id="consumer",
            idempotency_key="consume-1",
            correlation_id="corr-1",
            expected_version=2,
        )
        revoked = store.record(
            "revoke",
            item["artifact_id"],
            actor_id="custodian",
            idempotency_key="revoke-1",
            correlation_id="corr-1",
            expected_version=3,
        )
        assert [
            published["resulting_version"],
            installed["resulting_version"],
            consumed["resulting_version"],
            revoked["resulting_version"],
        ] == [1, 2, 3, 4]
        assert revoked["status"] == "revoked"
        assert store.audit() == {
            "version": 4,
            "artifact_count": 1,
            "receipt_count": 4,
            "previous_record_sha256": store.audit()["previous_record_sha256"],
            "production": False,
            "live": False,
            "countable_forward": False,
        }
        with pytest.raises(CustodyError, match="CUSTODY_CONSUME_TRANSITION_INVALID"):
            store.record(
                "consume",
                item["artifact_id"],
                actor_id="consumer",
                idempotency_key="consume-2",
                correlation_id="corr-2",
                expected_version=4,
            )

    with custody(root, epoch=2) as reopened:
        assert reopened.audit()["version"] == 4


def test_predecessor_and_transitive_lineage_are_exact(tmp_path: Path) -> None:
    root = tmp_path / "custody"
    parent = artifact(1)
    predecessor = [
        {
            "artifact_id": parent["artifact_id"],
            "canonical_sha256": parent["canonical_sha256"],
        }
    ]
    child = artifact(2, predecessors=predecessor, lineage=[parent["canonical_sha256"]])
    bad = artifact(3, predecessors=predecessor, lineage=[])
    with custody(root) as store:
        store.publish(
            parent,
            actor_id="producer",
            idempotency_key="p1",
            correlation_id="c1",
            expected_version=0,
        )
        store.publish(
            child,
            actor_id="producer",
            idempotency_key="p2",
            correlation_id="c2",
            expected_version=1,
        )
        with pytest.raises(CustodyError, match="CUSTODY_LINEAGE_MISMATCH"):
            store.publish(
                bad,
                actor_id="producer",
                idempotency_key="p3",
                correlation_id="c3",
                expected_version=2,
            )


def test_unknown_schema_authority_escalation_and_replay_conflict_fail_closed(
    tmp_path: Path,
) -> None:
    root = tmp_path / "custody"
    item = artifact()
    with custody(root) as store:
        store.publish(
            item,
            actor_id="producer",
            idempotency_key="same",
            correlation_id="c1",
            expected_version=0,
        )
        with pytest.raises(CustodyError, match="CUSTODY_IDEMPOTENCY_CONFLICT"):
            store.publish(
                artifact(2),
                actor_id="producer",
                idempotency_key="same",
                correlation_id="c2",
                expected_version=1,
            )
        with pytest.raises(CustodyError, match="CUSTODY_ARTIFACT_INVALID"):
            store.publish(
                artifact(3, live=True),
                actor_id="producer",
                idempotency_key="live",
                correlation_id="c3",
                expected_version=1,
            )
        unknown = dict(artifact(4))
        unknown["schema_ref"] = "unknown-v1"
        with pytest.raises(CustodyError):
            store.publish(
                unknown,
                actor_id="producer",
                idempotency_key="unknown",
                correlation_id="c4",
                expected_version=1,
            )


def test_two_writers_and_stale_epoch_fail_closed(tmp_path: Path) -> None:
    root = tmp_path / "custody"
    first = custody(root)
    try:
        with pytest.raises(CustodyError, match="CUSTODY_WRITER_ALREADY_ACTIVE"):
            custody(root, epoch=2)
    finally:
        first.close()
    # A crashed/restarted process may safely resume its own fence after it has
    # reacquired the single-writer lock; rollback and a different writer may not.
    with custody(root, epoch=1):
        pass
    with custody(root, epoch=2):
        pass
    with pytest.raises(CustodyError, match="CUSTODY_WRITER_EPOCH_STALE"):
        custody(root, epoch=1)
    with pytest.raises(CustodyError, match="CUSTODY_WRITER_EPOCH_FORK"):
        ArtifactCustody(
            root, writer_id="custody-b", writer_epoch=1, schema_registry=SCHEMAS
        )


def test_expected_version_and_request_validation_happen_before_artifact_write(
    tmp_path: Path,
) -> None:
    root = tmp_path / "custody"
    item = artifact()
    with custody(root) as store:
        with pytest.raises(CustodyError, match="CUSTODY_EXPECTED_VERSION_MISMATCH"):
            store.publish(
                item,
                actor_id="producer",
                idempotency_key="p1",
                correlation_id="c1",
                expected_version=1,
            )
        with pytest.raises(CustodyError, match="CUSTODY_ACTOR_INVALID"):
            store.publish(
                item,
                actor_id="../bad",
                idempotency_key="p1",
                correlation_id="c1",
                expected_version=0,
            )
        assert list((root / "artifacts").iterdir()) == []

        receipt = store.publish(
            item,
            actor_id="producer",
            idempotency_key="p1",
            correlation_id="c1",
            expected_version=0,
        )
        with pytest.raises(ContractError, match="RECEIPT_FIELDS_INVALID"):
            validate_receipt(receipt | {"extra": False})


def test_publish_uses_single_receipt_commit_without_orphan_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "custody"
    item = artifact()
    with custody(root) as store:

        def fail_receipt(directory: str, final_name: str, raw: bytes) -> None:
            if directory == "receipts":
                raise OSError("simulated receipt write failure")

        monkeypatch.setattr(store, "_publish_create_only", fail_receipt)
        with pytest.raises(OSError, match="simulated receipt write failure"):
            store.publish(
                item,
                actor_id="producer",
                idempotency_key="p1",
                correlation_id="c1",
                expected_version=0,
            )
        assert list((root / "artifacts").iterdir()) == []


def test_tamper_and_symlink_swap_are_detected(tmp_path: Path) -> None:
    root = tmp_path / "custody"
    item = artifact()
    with custody(root) as store:
        store.publish(
            item,
            actor_id="producer",
            idempotency_key="p1",
            correlation_id="c1",
            expected_version=0,
        )
        stored = next((root / "receipts").iterdir())
        stored.write_text("{}\n", encoding="utf-8")
        with pytest.raises(CustodyError):
            store.audit()

    root2 = tmp_path / "custody2"
    with custody(root2) as store:
        store.publish(
            item,
            actor_id="producer",
            idempotency_key="p1",
            correlation_id="c1",
            expected_version=0,
        )
        stored = next((root2 / "receipts").iterdir())
        target = tmp_path / "replacement"
        target.write_bytes(stored.read_bytes())
        stored.unlink()
        stored.symlink_to(target)
        with pytest.raises(CustodyError):
            store.audit()


def test_crash_before_single_publish_commit_recovers_without_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "custody"
    item = artifact()
    with custody(root) as store:

        def crash(*args: object, **kwargs: object) -> dict:
            raise RuntimeError("simulated crash")

        monkeypatch.setattr(store, "_append", crash)
        with pytest.raises(RuntimeError, match="simulated crash"):
            store.publish(
                item,
                actor_id="producer",
                idempotency_key="p1",
                correlation_id="c1",
                expected_version=0,
            )
        assert list((root / "artifacts").iterdir()) == []
    monkeypatch.undo()
    with custody(root, epoch=2) as recovered:
        receipt = recovered.publish(
            item,
            actor_id="producer",
            idempotency_key="p1",
            correlation_id="c1",
            expected_version=0,
        )
        assert receipt["resulting_version"] == 1


def test_map_candidate_signed_acceptance_is_preserved_and_pinned_in_custody(
    tmp_path: Path,
) -> None:
    """E2E candidate -> signed runtime-style acceptance -> custody -> readback."""

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    keyring = {
        "schema_version": "web-bridge-trust-keyring-v1",
        "domain": "map_acceptance",
        "key_version": "v1",
        "keys": [
            {
                "key_id": "ephemeral-map-acceptance",
                "domain": "map_acceptance",
                "purpose": "map-acceptance-only",
                "public_key_base64": base64.b64encode(public).decode("ascii"),
                "status": "active",
            }
        ],
    }
    keyring_path = tmp_path / "ephemeral-map-keyring.json"
    keyring_raw = canonical_json_line(keyring)
    keyring_path.write_bytes(keyring_raw)
    candidate_raw = b'{"candidate_id":"map-candidate-1","signal":"RB"}'
    accepted = new_artifact_envelope(
        artifact_type="map-acceptance",
        trust_domain="map_acceptance",
        producer_id="runtime-style-acceptance",
        producer_version="v1",
        schema_ref=SCHEMA_REF,
        payload={
            "value": 1,
            "production": False,
            "live": False,
            "countable_forward": False,
        },
        generated_at="2026-08-05T00:00:00Z",
        scope={"candidate_sha256": hashlib.sha256(candidate_raw).hexdigest()},
        predecessor_refs=[],
        lineage=[],
    )
    request = build_signing_request(
        accepted,
        domain="map_acceptance",
        key_id="ephemeral-map-acceptance",
        key_version="v1",
        request_id="map-acceptance-1",
        requested_at="2026-08-01T00:00:00Z",
        expires_at="2099-01-01T00:00:00Z",
    )
    unsigned = {
        "schema_version": "web-bridge-signed-artifact-v1",
        "request_id": request["request_id"],
        "domain": request["domain"],
        "signer_key_id": request["key_id"],
        "signer_key_version": request["key_version"],
        "requested_at": request["requested_at"],
        "expires_at": request["expires_at"],
        "artifact": request["artifact"],
    }
    signed = build_signed_artifact(
        request,
        signature_base64=base64.b64encode(private.sign(signing_bytes(unsigned))).decode(
            "ascii"
        ),
    )
    root = tmp_path / "custody"
    with custody(root) as store:
        receipt = store.publish_signed(
            signed,
            keyring_path=keyring_path,
            expected_domain="map_acceptance",
            expected_key_purpose="map-acceptance-only",
            expected_keyring_raw_sha256=hashlib.sha256(keyring_raw).hexdigest(),
            actor_id="map-acceptance-runtime",
            idempotency_key="signed-map-acceptance-1",
            correlation_id="map-candidate-1",
            expected_version=0,
        )
        assert receipt["artifact_canonical_sha256"] == accepted["canonical_sha256"]
        assert receipt["artifact_raw_sha256"] == accepted["raw_sha256"]
        assert store.read_signed_artifact(accepted["artifact_id"]) == signed
        with pytest.raises(
            CustodyError, match="CUSTODY_SIGNED_ARTIFACT_TRUST_KEYRING_PIN_MISMATCH"
        ):
            store.publish_signed(
                signed,
                keyring_path=keyring_path,
                expected_domain="map_acceptance",
                expected_key_purpose="map-acceptance-only",
                expected_keyring_raw_sha256="0" * 64,
                actor_id="map-acceptance-runtime",
                idempotency_key="bad-pin",
                correlation_id="map-candidate-1",
                expected_version=1,
            )
        with pytest.raises(
            CustodyError,
            match="CUSTODY_SIGNED_ARTIFACT_SIGNED_ARTIFACT_KEY_PURPOSE_MISMATCH",
        ):
            store.publish_signed(
                signed,
                keyring_path=keyring_path,
                expected_domain="map_acceptance",
                expected_key_purpose="wrong-purpose",
                expected_keyring_raw_sha256=hashlib.sha256(keyring_raw).hexdigest(),
                actor_id="map-acceptance-runtime",
                idempotency_key="bad-purpose",
                correlation_id="map-candidate-1",
                expected_version=1,
            )


def test_signed_custody_audit_rejects_wrapper_snapshot_domain_and_pin_tamper_after_restart(
    tmp_path: Path,
) -> None:
    """Record hashes are mutable evidence; the retained signature is not."""

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    ring = {
        "schema_version": "web-bridge-trust-keyring-v1",
        "domain": "research",
        "key_version": "v1",
        "keys": [
            {
                "key_id": "research-audit",
                "domain": "research",
                "purpose": "research-only",
                "public_key_base64": base64.b64encode(public).decode("ascii"),
                "status": "active",
            }
        ],
    }
    ring_path = tmp_path / "research-keyring.json"
    ring_raw = canonical_json_line(ring)
    ring_path.write_bytes(ring_raw)
    envelope = artifact()
    request = build_signing_request(
        envelope,
        domain="research",
        key_id="research-audit",
        key_version="v1",
        request_id="research-audit-1",
        requested_at="2026-08-01T00:00:00Z",
        expires_at="2099-01-01T00:00:00Z",
    )
    unsigned = {
        "schema_version": "web-bridge-signed-artifact-v1",
        "request_id": request["request_id"],
        "domain": request["domain"],
        "signer_key_id": request["key_id"],
        "signer_key_version": request["key_version"],
        "requested_at": request["requested_at"],
        "expires_at": request["expires_at"],
        "artifact": request["artifact"],
    }
    signed = build_signed_artifact(
        request,
        signature_base64=base64.b64encode(private.sign(signing_bytes(unsigned))).decode(
            "ascii"
        ),
    )

    def publish(root: Path) -> None:
        with custody(root) as store:
            store.publish_signed(
                signed,
                keyring_path=ring_path,
                expected_domain="research",
                expected_key_purpose="research-only",
                expected_keyring_raw_sha256=hashlib.sha256(ring_raw).hexdigest(),
                actor_id="research-runtime",
                idempotency_key="signed-research-1",
                correlation_id="research-1",
                expected_version=0,
            )
            store.record(
                "install",
                envelope["artifact_id"],
                actor_id="research-installer",
                idempotency_key="install-research-1",
                correlation_id="research-1",
                expected_version=1,
            )

    def rewrite(root: Path, mutate: object) -> None:
        records = sorted((root / "receipts").iterdir())
        first = json.loads(records[0].read_text(encoding="utf-8"))
        assert callable(mutate)
        mutate(first)
        first_raw = canonical_json_line(first)
        records[0].write_bytes(first_raw)
        # An attacker can recompute every mutable chain field, but cannot make
        # the altered signed wrapper validate with the retained public key.
        second = json.loads(records[1].read_text(encoding="utf-8"))
        second["previous_record_sha256"] = hashlib.sha256(first_raw).hexdigest()
        records[1].write_bytes(canonical_json_line(second))

    mutations = {
        "wrapper": lambda record: (
            record["signed_artifact"].__setitem__(
                "request_id", "research-audit-tampered"
            ),
            record.__setitem__(
                "signed_artifact_sha256",
                hashlib.sha256(
                    canonical_json_line(record["signed_artifact"])
                ).hexdigest(),
            ),
        ),
        "keyring": lambda record: record["signed_artifact_keyring"]["keys"][
            0
        ].__setitem__("public_key_base64", base64.b64encode(b"x" * 32).decode("ascii")),
        "domain": lambda record: record.__setitem__(
            "signed_artifact_expected_domain", "map_acceptance"
        ),
        "pin": lambda record: record.__setitem__(
            "signed_artifact_keyring_raw_sha256", "0" * 64
        ),
    }
    for name, mutate in mutations.items():
        root = tmp_path / name
        publish(root)
        # A valid restart replays and verifies the retained snapshot first.
        with custody(root, epoch=2) as reopened:
            assert reopened.read_signed_artifact(envelope["artifact_id"]) == signed
        rewrite(root, mutate)
        with pytest.raises(CustodyError):
            custody(root, epoch=3)
