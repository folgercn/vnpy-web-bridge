from __future__ import annotations

import json
from pathlib import Path

import pytest

from shared.artifact_contracts import new_artifact_envelope
from shared.artifact_custody import ArtifactCustody, CustodyError

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
            item, actor_id="producer", idempotency_key="pub-1", correlation_id="corr-1"
        )
        assert published["receipt_type"] == "publish"
        assert (
            store.publish(
                item,
                actor_id="producer",
                idempotency_key="pub-1",
                correlation_id="corr-1",
            )
            == published
        )
        installed = store.record(
            "install",
            item["artifact_id"],
            actor_id="installer",
            idempotency_key="install-1",
            correlation_id="corr-1",
        )
        consumed = store.record(
            "consume",
            item["artifact_id"],
            actor_id="consumer",
            idempotency_key="consume-1",
            correlation_id="corr-1",
        )
        revoked = store.record(
            "revoke",
            item["artifact_id"],
            actor_id="custodian",
            idempotency_key="revoke-1",
            correlation_id="corr-1",
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
            parent, actor_id="producer", idempotency_key="p1", correlation_id="c1"
        )
        store.publish(
            child, actor_id="producer", idempotency_key="p2", correlation_id="c2"
        )
        with pytest.raises(CustodyError, match="CUSTODY_LINEAGE_MISMATCH"):
            store.publish(
                bad, actor_id="producer", idempotency_key="p3", correlation_id="c3"
            )


def test_unknown_schema_authority_escalation_and_replay_conflict_fail_closed(
    tmp_path: Path,
) -> None:
    root = tmp_path / "custody"
    item = artifact()
    with custody(root) as store:
        store.publish(
            item, actor_id="producer", idempotency_key="same", correlation_id="c1"
        )
        with pytest.raises(CustodyError, match="CUSTODY_IDEMPOTENCY_CONFLICT"):
            store.publish(
                artifact(2),
                actor_id="producer",
                idempotency_key="same",
                correlation_id="c2",
            )
        with pytest.raises(CustodyError, match="CUSTODY_ARTIFACT_INVALID"):
            store.publish(
                artifact(3, live=True),
                actor_id="producer",
                idempotency_key="live",
                correlation_id="c3",
            )
        unknown = dict(artifact(4))
        unknown["schema_ref"] = "unknown-v1"
        with pytest.raises(CustodyError):
            store.publish(
                unknown,
                actor_id="producer",
                idempotency_key="unknown",
                correlation_id="c4",
            )


def test_two_writers_and_stale_epoch_fail_closed(tmp_path: Path) -> None:
    root = tmp_path / "custody"
    first = custody(root)
    try:
        with pytest.raises(CustodyError, match="CUSTODY_WRITER_ALREADY_ACTIVE"):
            custody(root, epoch=2)
    finally:
        first.close()
    with pytest.raises(CustodyError, match="CUSTODY_WRITER_EPOCH_STALE"):
        custody(root, epoch=1)


def test_tamper_and_symlink_swap_are_detected(tmp_path: Path) -> None:
    root = tmp_path / "custody"
    item = artifact()
    with custody(root) as store:
        store.publish(
            item, actor_id="producer", idempotency_key="p1", correlation_id="c1"
        )
        stored = root / "artifacts" / f"{item['artifact_id']}.json"
        stored.write_text("{}\n", encoding="utf-8")
        with pytest.raises(CustodyError):
            store.audit()

    root2 = tmp_path / "custody2"
    with custody(root2) as store:
        store.publish(
            item, actor_id="producer", idempotency_key="p1", correlation_id="c1"
        )
        stored = root2 / "artifacts" / f"{item['artifact_id']}.json"
        target = tmp_path / "replacement"
        target.write_text(json.dumps(item), encoding="utf-8")
        stored.unlink()
        stored.symlink_to(target)
        with pytest.raises(CustodyError):
            store.audit()


def test_crash_after_artifact_publish_recovers_without_overwrite(
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
                item, actor_id="producer", idempotency_key="p1", correlation_id="c1"
            )
    monkeypatch.undo()
    with custody(root, epoch=2) as recovered:
        receipt = recovered.publish(
            item, actor_id="producer", idempotency_key="p1", correlation_id="c1"
        )
        assert receipt["resulting_version"] == 1
