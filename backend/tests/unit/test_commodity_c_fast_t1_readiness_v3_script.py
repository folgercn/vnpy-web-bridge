from __future__ import annotations

import base64
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import runpy
from types import SimpleNamespace
import sys

import pytest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

import commodity_c_fast_readonly_deployment_outcome as outcome_module  # noqa: E402
import commodity_c_fast_t1_build_registry_provenance_v2 as provenance_module  # noqa: E402
import commodity_c_fast_t1_readiness_v3 as readiness_module  # noqa: E402


READ_PRODUCTION_PINS = readiness_module._read_production_pins
NOW = datetime(2026, 9, 1, 0, 30, tzinfo=timezone.utc)
T1_SOURCE = "1" * 40
SIGNER_SOURCE_COMMIT = "2" * 40
L3_SOURCE = "3" * 40
OUTCOME_SOURCE = "4" * 40
T1_IMAGE = "sha256:" + "5" * 64
QUESTDB_IMAGE = "sha256:" + "6" * 64
SIGNER_SOURCE_SHA256 = "7" * 64
T1_PUBLIC = b"T" * 32
L3_PUBLIC = b"L" * 32
PROVENANCE_PUBLIC = b"P" * 32
OUTCOME_PUBLIC = b"O" * 32
T1_PUBLIC_SHA256 = hashlib.sha256(T1_PUBLIC).hexdigest()
L3_PUBLIC_SHA256 = hashlib.sha256(L3_PUBLIC).hexdigest()
PROVENANCE_PUBLIC_SHA256 = hashlib.sha256(PROVENANCE_PUBLIC).hexdigest()
OUTCOME_PUBLIC_SHA256 = hashlib.sha256(OUTCOME_PUBLIC).hexdigest()


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_bytes(path: Path, raw: bytes, *, mode: int = 0o600) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)
    return path


def canonical(payload: dict) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def write_json(path: Path, payload: dict) -> Path:
    return write_bytes(path, canonical(payload))


def keyring(version: str, purpose: str, entries: list[tuple[str, bytes]]) -> dict:
    return {
        "schema_version": version,
        "keys": [
            {
                "key_id": key_id,
                "purpose": purpose,
                "public_key_base64": base64.b64encode(material).decode("ascii"),
            }
            for key_id, material in entries
        ],
    }


def build_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> dict:
    custody = tmp_path / "readiness-v3-custody"
    custody.mkdir(mode=0o700, parents=True)
    custody_identity = {
        "schema_version": readiness_module.CUSTODY_IDENTITY_VERSION,
        "custody_id": "readiness-v3-custody-a01",
    }
    write_json(
        custody / readiness_module.CUSTODY_IDENTITY_FILENAME,
        custody_identity,
    )
    external = write_bytes(tmp_path / "external.json", b"external-evidence")
    source_bundle = write_bytes(
        tmp_path / "query-v3-source.tar",
        b"bounded-source-bundle",
    )
    oci = write_bytes(tmp_path / "runtime.oci.tar", b"oci-layout")
    content = {
        "source_commit_sha": T1_SOURCE,
        "external_evidence_sha256": sha256(external.read_bytes()),
        "source_bundle_archive_sha256": sha256(source_bundle.read_bytes()),
        "source_manifest_raw_sha256": "8" * 64,
        "source_manifest_canonical_sha256": "9" * 64,
        "oci_layout_archive_sha256": sha256(oci.read_bytes()),
        "image_reference": f"registry.example/c-fast@{T1_IMAGE}",
        "image_digest": T1_IMAGE,
        "image_id": "sha256:" + "a" * 64,
        "runtime_bundle_index_sha256": "b" * 64,
        "verifier_sha256": "c" * 64,
        "attestation_schema_sha256": "d" * 64,
        "source_manifest_schema_sha256": "e" * 64,
        "checks": {
            "source_commit_assertion_bound": True,
            "git_binary_required": False,
            "git_commit_independently_resolved": False,
            "runtime_bundle_matches_source_bundle": True,
        },
    }
    content_path = write_json(tmp_path / "content.json", content)
    provenance_keyring = keyring(
        provenance_module.KEYRING_VERSION,
        provenance_module.KEY_PURPOSE,
        [("c-fast-provenance-a01", PROVENANCE_PUBLIC)],
    )
    outcome_keyring = keyring(
        outcome_module.OUTCOME_KEYRING_VERSION,
        outcome_module.OUTCOME_KEY_PURPOSE,
        [("c-fast-outcome-a01", OUTCOME_PUBLIC)],
    )
    t1_keyring = keyring(
        provenance_module.T1_KEYRING_VERSION,
        provenance_module.T1_KEY_PURPOSE,
        [("c-fast-t1-a0001", T1_PUBLIC)],
    )
    l3_keyring = keyring(
        provenance_module.L3_KEYRING_VERSION,
        provenance_module.L3_KEY_PURPOSE,
        [("c-fast-l3-a0001", L3_PUBLIC)],
    )
    provenance_keyring_path = write_json(
        tmp_path / "provenance-keyring.json",
        provenance_keyring,
    )
    outcome_keyring_path = write_json(
        tmp_path / "outcome-keyring.json",
        outcome_keyring,
    )
    t1_keyring_path = write_json(
        tmp_path / "t1-keyring.json",
        t1_keyring,
    )
    l3_keyring_path = write_json(
        tmp_path / "l3-keyring.json",
        l3_keyring,
    )
    outcome_source_paths = SimpleNamespace(
        release_keyring=l3_keyring_path,
    )
    inputs = readiness_module.ReadinessInputs(
        external_image_evidence=external,
        source_bundle_archive=source_bundle,
        oci_layout_archive=oci,
        content_attestation=content_path,
        provenance=tmp_path / "provenance-v2.json",
        provenance_keyring=provenance_keyring_path,
        t1_keyring=t1_keyring_path,
        outcome=tmp_path / "outcome.json",
        outcome_keyring=outcome_keyring_path,
        outcome_source=outcome_source_paths,
        post_evidence=SimpleNamespace(),
        t1_runtime_source_commit_sha=T1_SOURCE,
        t1_runtime_image_digest=T1_IMAGE,
        l3_contract_source_commit_sha=L3_SOURCE,
        outcome_contract_source_commit_assertion=OUTCOME_SOURCE,
        questdb_image_digest=QUESTDB_IMAGE,
    )
    content_raw_sha256 = sha256(content_path.read_bytes())
    provenance_receipt = {
        "signed_provenance_raw_sha256": "1" * 64,
        "signed_provenance_canonical_sha256": "2" * 64,
        "content_attestation_raw_sha256": content_raw_sha256,
        "content_attestation_canonical_sha256": sha256(canonical(content)),
        "runtime_source_commit_sha": T1_SOURCE,
        "source_bundle_archive_sha256": sha256(source_bundle.read_bytes()),
        "source_manifest_canonical_sha256": "9" * 64,
        "image_reference": content["image_reference"],
        "image_digest": T1_IMAGE,
        "signer_key_id": "c-fast-provenance-a01",
        "signer_public_key_sha256": PROVENANCE_PUBLIC_SHA256,
        "signing_tool_source_sha256": SIGNER_SOURCE_SHA256,
        "signing_tool_source_commit_sha": SIGNER_SOURCE_COMMIT,
        "signing_tool_source_pin_verified": True,
        "signing_tool_source_bytes_revalidated_at_runtime": False,
        "signing_tool_execution_independently_verified": False,
        "signed_build_assertion_verified": True,
        "signed_registry_assertion_verified": True,
        "external_facts_independently_reverified": False,
        "excluded_authority_public_key_sha256s": sorted(
            [T1_PUBLIC_SHA256, L3_PUBLIC_SHA256]
        ),
    }
    outcome_payload = {
        "questdb_image_digest": QUESTDB_IMAGE,
        "release_source_commit_sha": L3_SOURCE,
        "outcome_contract_source_commit_assertion": OUTCOME_SOURCE,
        "issued_at": "2026-09-01T00:20:00+00:00",
        "deployment_ended_at": "2026-09-01T00:15:00+00:00",
        "release_id": "c-fast-readonly-release-a01",
        "attempt_id": "attempt-" + "3" * 64,
        "questdb_target_identity_sha256": "4" * 64,
        "signer_key_id": "c-fast-outcome-a01",
    }
    verified_outcome = SimpleNamespace(
        payload=outcome_payload,
        raw_sha256="5" * 64,
        canonical_sha256="6" * 64,
        outcome_signer_public_key_sha256=OUTCOME_PUBLIC_SHA256,
        source=SimpleNamespace(
            release_raw_sha256="7" * 64,
            release_canonical_sha256="8" * 64,
            consume_raw_sha256="9" * 64,
            receipt_raw_sha256="a" * 64,
            pre_evidence_bundle_index_sha256="b" * 64,
        ),
        post=SimpleNamespace(bundle_index_sha256="c" * 64),
    )
    (
        custody_id,
        custody_identity_sha256,
        custody_directory_identity_sha256,
    ) = readiness_module._read_packet_custody_facts(custody)
    evidence_join_identity_sha256 = (
        readiness_module._evidence_join_identity_sha256(
            inputs,
            content,
            provenance_receipt,
            outcome_payload,
            verified_outcome.canonical_sha256,
        )
    )
    pins = readiness_module.ReadinessPins(
        pin_set_generation_id="readiness-v3-pin-generation-a01",
        pin_set_manifest_sha256="d" * 64,
        pin_root_identity_sha256="e" * 64,
        provenance_keyring_sha256=sha256(canonical(provenance_keyring)),
        provenance_signing_tool_source_sha256=SIGNER_SOURCE_SHA256,
        provenance_signing_tool_source_commit_sha=SIGNER_SOURCE_COMMIT,
        t1_authority_keyring_sha256=sha256(canonical(t1_keyring)),
        l3_authority_keyring_sha256=sha256(canonical(l3_keyring)),
        outcome_keyring_sha256=sha256(canonical(outcome_keyring)),
        packet_custody_path=custody,
        packet_custody_id=custody_id,
        packet_custody_identity_sha256=custody_identity_sha256,
        packet_custody_directory_identity_sha256=(
            custody_directory_identity_sha256
        ),
        evidence_join_identity_sha256=evidence_join_identity_sha256,
    )
    monkeypatch.setattr(
        readiness_module,
        "_read_production_pins",
        lambda: pins,
    )

    def verify_image(
        evidence_path: Path,
        source_bundle_path: Path,
        oci_path: Path,
        expected_source_commit_sha: str,
    ) -> dict:
        assert evidence_path == inputs.external_image_evidence
        assert source_bundle_path == inputs.source_bundle_archive
        assert oci_path == inputs.oci_layout_archive
        assert expected_source_commit_sha == T1_SOURCE
        return dict(content)

    monkeypatch.setattr(
        readiness_module,
        "verify_query_v3_image_evidence",
        verify_image,
    )

    def load_excluded(
        *,
        t1_keyring_path: Path,
        expected_t1_keyring_sha256: str,
        l3_keyring_path: Path,
        expected_l3_keyring_sha256: str,
    ) -> tuple[list[str], dict[str, str]]:
        assert t1_keyring_path == inputs.t1_keyring
        assert l3_keyring_path == inputs.outcome_source.release_keyring
        assert expected_t1_keyring_sha256 == pins.t1_authority_keyring_sha256
        assert expected_l3_keyring_sha256 == pins.l3_authority_keyring_sha256
        return (
            sorted([T1_PUBLIC_SHA256, L3_PUBLIC_SHA256]),
            {
                "t1_release_keyring_sha256": (
                    pins.t1_authority_keyring_sha256
                ),
                "l3_release_keyring_sha256": (
                    pins.l3_authority_keyring_sha256
                ),
            },
        )

    monkeypatch.setattr(
        readiness_module,
        "load_excluded_authority_key_facts",
        load_excluded,
    )

    def verify_provenance(
        provenance_path: Path,
        trusted_keyring_path: Path,
        content_attestation_path: Path,
        *,
        expected_trusted_keyring_sha256: str,
        expected_runtime_source_commit_sha: str,
        expected_image_digest: str,
        expected_signing_tool_source_sha256: str,
        expected_signing_tool_source_commit_sha: str,
        excluded_authority_key_hashes: list[str],
        excluded_authority_keyring_sha256s: dict[str, str],
        now: datetime,
    ) -> dict:
        assert provenance_path == inputs.provenance
        assert trusted_keyring_path == inputs.provenance_keyring
        assert content_attestation_path == inputs.content_attestation
        assert expected_trusted_keyring_sha256 == pins.provenance_keyring_sha256
        assert expected_runtime_source_commit_sha == T1_SOURCE
        assert expected_image_digest == T1_IMAGE
        assert expected_signing_tool_source_sha256 == SIGNER_SOURCE_SHA256
        assert expected_signing_tool_source_commit_sha == SIGNER_SOURCE_COMMIT
        assert excluded_authority_key_hashes == sorted(
            [T1_PUBLIC_SHA256, L3_PUBLIC_SHA256]
        )
        assert excluded_authority_keyring_sha256s == {
            "t1_release_keyring_sha256": pins.t1_authority_keyring_sha256,
            "l3_release_keyring_sha256": pins.l3_authority_keyring_sha256,
        }
        assert now == NOW
        return dict(provenance_receipt)

    monkeypatch.setattr(
        readiness_module,
        "verify_provenance",
        verify_provenance,
    )

    def verify_outcome(
        outcome_path: Path,
        outcome_keyring_path: Path,
        t1_keyring_path: Path,
        source_paths: object,
        post_paths: object,
        *,
        expected_outcome_keyring_sha256: str,
        expected_release_keyring_sha256: str,
        expected_t1_keyring_sha256: str,
        expected_outcome_source_commit_sha: str,
        expected_release_source_commit_sha: str,
        expected_questdb_image_digest: str,
        now: datetime,
    ) -> SimpleNamespace:
        assert outcome_path == inputs.outcome
        assert outcome_keyring_path == inputs.outcome_keyring
        assert t1_keyring_path == inputs.t1_keyring
        assert source_paths is inputs.outcome_source
        assert post_paths is inputs.post_evidence
        assert expected_outcome_keyring_sha256 == pins.outcome_keyring_sha256
        assert expected_release_keyring_sha256 == pins.l3_authority_keyring_sha256
        assert expected_t1_keyring_sha256 == pins.t1_authority_keyring_sha256
        assert expected_outcome_source_commit_sha == OUTCOME_SOURCE
        assert expected_release_source_commit_sha == L3_SOURCE
        assert expected_questdb_image_digest == QUESTDB_IMAGE
        assert now == NOW
        return verified_outcome

    monkeypatch.setattr(
        readiness_module,
        "verify_signed_outcome",
        verify_outcome,
    )
    return {
        "inputs": inputs,
        "pins": pins,
        "content": content,
        "provenance_receipt": provenance_receipt,
        "outcome": verified_outcome,
        "keyrings": {
            "provenance": provenance_keyring,
            "t1": t1_keyring,
            "l3": l3_keyring,
            "outcome": outcome_keyring,
        },
    }


def derive(values: dict) -> dict:
    return readiness_module.derive_readiness_packet(
        values["inputs"],
        values["pins"],
        now=NOW,
    )


def pin_manifest(pins: readiness_module.ReadinessPins) -> dict:
    return {
        "schema_version": readiness_module.PIN_MANIFEST_VERSION,
        "generation_id": pins.pin_set_generation_id,
        "provenance_keyring_sha256": pins.provenance_keyring_sha256,
        "provenance_signing_tool_source_sha256": (
            pins.provenance_signing_tool_source_sha256
        ),
        "provenance_signing_tool_source_commit_sha": (
            pins.provenance_signing_tool_source_commit_sha
        ),
        "t1_authority_keyring_sha256": (
            pins.t1_authority_keyring_sha256
        ),
        "l3_authority_keyring_sha256": (
            pins.l3_authority_keyring_sha256
        ),
        "outcome_keyring_sha256": pins.outcome_keyring_sha256,
        "packet_custody_path": str(pins.packet_custody_path),
        "packet_custody_id": pins.packet_custody_id,
        "packet_custody_identity_sha256": (
            pins.packet_custody_identity_sha256
        ),
        "evidence_join_identity_sha256": (
            pins.evidence_join_identity_sha256
        ),
    }


def test_deny_matrix_covers_upstream_contracts() -> None:
    assert set(outcome_module.OUTCOME_FALSE_FIELDS).issubset(
        readiness_module.FALSE_AUTHORITY_FIELDS
    )
    assert set(outcome_module.OUTCOME_ZERO_FIELDS).issubset(
        readiness_module.ZERO_FACT_FIELDS
    )
    assert set(provenance_module.FALSE_AUTHORITY_FIELDS).issubset(
        readiness_module.FALSE_AUTHORITY_FIELDS
    )
    assert set(provenance_module.ZERO_FACT_FIELDS).issubset(
        readiness_module.ZERO_FACT_FIELDS
    )
    assert readiness_module.READINESS_V3_REQUIRED_FALSE_FIELDS.issubset(
        readiness_module.FALSE_AUTHORITY_FIELDS
    )


def test_success_packet_is_evidence_only_and_binds_v3_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    packet = derive(values)

    assert packet["schema_version"] == readiness_module.SCHEMA_VERSION
    assert packet["status"] == readiness_module.STATUS
    assert packet["packet_id"].startswith("readiness-v3-")
    assert (
        packet["pin_set_generation_id"]
        == values["pins"].pin_set_generation_id
    )
    assert packet["packet_custody_id"] == values["pins"].packet_custody_id
    assert (
        packet["packet_custody_identity_sha256"]
        == values["pins"].packet_custody_identity_sha256
    )
    assert (
        packet["packet_custody_directory_identity_sha256"]
        == values["pins"].packet_custody_directory_identity_sha256
    )
    assert (
        packet["evidence_join_identity_sha256"]
        == values["pins"].evidence_join_identity_sha256
    )
    assert packet["ready_for_query_release_v4_human_signature_only"] is True
    assert packet["requirements"] == {
        "requires_query_release_v4": True,
        "query_release_v3_accepted": False,
        "readiness_v2_accepted": False,
        "raw_readiness_packet_binding_required": True,
        "human_signature_required": True,
        "one_shot_runtime_required": True,
    }
    assert packet["t1_runtime"]["source_bundle_archive_raw_sha256"] == sha256(
        values["inputs"].source_bundle_archive.read_bytes()
    )
    assert packet["t1_runtime"]["git_binary_required"] is False
    assert packet["t1_runtime"]["source_root_required"] is False
    assert packet["build_registry_provenance"][
        "provenance_signing_tool_source_sha256"
    ] == SIGNER_SOURCE_SHA256
    for field in readiness_module.FALSE_AUTHORITY_FIELDS:
        assert packet[field] is False
    for field in readiness_module.ZERO_FACT_FIELDS:
        assert packet[field] == 0


def test_v3_has_no_git_subprocess_or_source_root_interface() -> None:
    source = readiness_module.VERIFIER_PATH.read_text(encoding="utf-8")
    assert "subprocess" not in source
    assert "--source-root" not in source
    assert "verify_image_evidence" not in source
    parser = readiness_module.parse_args
    assert parser is not None


def test_supplied_content_must_equal_exact_rerun(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    fabricated = dict(values["content"])
    fabricated["image_id"] = "sha256:" + "f" * 64
    monkeypatch.setattr(
        readiness_module,
        "verify_query_v3_image_evidence",
        lambda *_args, **_kwargs: fabricated,
    )
    with pytest.raises(
        readiness_module.ReadinessV3Error,
        match="exact regenerated report",
    ):
        derive(values)


@pytest.mark.parametrize(
    ("input_field", "message"),
    [
        ("external_image_evidence", "raw binding mismatch"),
        ("source_bundle_archive", "raw binding mismatch"),
        ("oci_layout_archive", "raw binding mismatch"),
    ],
)
def test_raw_content_inputs_cannot_be_spliced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    input_field: str,
    message: str,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    path = getattr(values["inputs"], input_field)
    path.write_bytes(path.read_bytes() + b"-spliced")
    with pytest.raises(readiness_module.ReadinessV3Error, match=message):
        derive(values)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("release_id", "c-fast-readonly-release-b02"),
        ("attempt_id", "attempt-" + "d" * 64),
        ("questdb_target_identity_sha256", "e" * 64),
    ],
)
def test_content_provenance_and_outcome_join_cannot_be_spliced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    replacement: str,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    values["outcome"].payload[field] = replacement
    with pytest.raises(
        readiness_module.ReadinessV3Error,
        match="root-pinned evidence join identity",
    ):
        derive(values)


@pytest.mark.parametrize(
    "field",
    [
        "content_attestation_raw_sha256",
        "content_attestation_canonical_sha256",
        "source_bundle_archive_sha256",
        "source_manifest_canonical_sha256",
        "runtime_source_commit_sha",
        "image_digest",
        "signing_tool_source_sha256",
        "signing_tool_source_commit_sha",
    ],
)
def test_provenance_v2_must_bind_exact_runtime_and_signer_pins(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    receipt = dict(values["provenance_receipt"])
    receipt[field] = "0" * (40 if field.endswith("commit_sha") else 64)
    monkeypatch.setattr(
        readiness_module,
        "verify_provenance",
        lambda *_args, **_kwargs: receipt,
    )
    with pytest.raises(
        readiness_module.ReadinessV3Error,
        match="exact query-v3 runtime",
    ):
        derive(values)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("signing_tool_source_pin_verified", False),
        ("signing_tool_source_bytes_revalidated_at_runtime", True),
        ("signing_tool_execution_independently_verified", True),
        ("signed_build_assertion_verified", False),
        ("signed_registry_assertion_verified", False),
        ("external_facts_independently_reverified", True),
    ],
)
def test_provenance_v2_semantic_flags_cannot_be_promoted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: bool,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    receipt = dict(values["provenance_receipt"])
    receipt[field] = value
    monkeypatch.setattr(
        readiness_module,
        "verify_provenance",
        lambda *_args, **_kwargs: receipt,
    )
    with pytest.raises(
        readiness_module.ReadinessV3Error,
        match="exact query-v3 runtime",
    ):
        derive(values)


def test_provenance_v2_failure_is_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)

    def fail(*_args, **_kwargs):
        raise provenance_module.BuildRegistryProvenanceV2Error(
            "provenance-v1 downgrade is forbidden"
        )

    monkeypatch.setattr(readiness_module, "verify_provenance", fail)
    with pytest.raises(
        readiness_module.ReadinessV3Error,
        match="downgrade is forbidden",
    ):
        derive(values)


def test_complete_provenance_and_outcome_keysets_must_be_disjoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    calls = 0

    def overlapping(*_args, **_kwargs) -> frozenset[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return frozenset({PROVENANCE_PUBLIC_SHA256, "1" * 64})
        return frozenset({OUTCOME_PUBLIC_SHA256, "1" * 64})

    monkeypatch.setattr(
        readiness_module,
        "_load_keyring_public_hashes",
        overlapping,
    )
    with pytest.raises(
        readiness_module.ReadinessV3Error,
        match="key domains must be disjoint",
    ):
        derive(values)


def test_unused_outcome_key_cannot_reuse_t1_or_l3_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    calls = 0

    def colliding(*_args, **_kwargs) -> frozenset[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return frozenset({PROVENANCE_PUBLIC_SHA256})
        return frozenset({OUTCOME_PUBLIC_SHA256, T1_PUBLIC_SHA256})

    monkeypatch.setattr(
        readiness_module,
        "_load_keyring_public_hashes",
        colliding,
    )
    with pytest.raises(
        readiness_module.ReadinessV3Error,
        match="key domains must be disjoint",
    ):
        derive(values)


def test_invalid_or_duplicate_keyring_material_fails_closed(
    tmp_path: Path,
) -> None:
    duplicate = keyring(
        provenance_module.KEYRING_VERSION,
        provenance_module.KEY_PURPOSE,
        [("key-a0001", PROVENANCE_PUBLIC), ("key-b0001", PROVENANCE_PUBLIC)],
    )
    path = write_json(tmp_path / "duplicate.json", duplicate)
    with pytest.raises(
        readiness_module.ReadinessV3Error,
        match="duplicates public key material",
    ):
        readiness_module._load_keyring_public_hashes(
            path,
            sha256(canonical(duplicate)),
            expected_schema_version=provenance_module.KEYRING_VERSION,
            expected_purpose=provenance_module.KEY_PURPOSE,
            label="duplicate keyring",
        )


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("provenance", "t1"),
        ("provenance", "l3"),
        ("provenance", "outcome"),
        ("t1", "l3"),
        ("t1", "outcome"),
        ("l3", "outcome"),
    ],
)
def test_all_four_real_keyrings_reject_each_pairwise_collision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    left: str,
    right: str,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    materials = {
        "provenance": b"A" * 32,
        "t1": b"B" * 32,
        "l3": b"C" * 32,
        "outcome": b"D" * 32,
    }
    collision = b"X" * 32
    materials[left] = collision
    materials[right] = collision
    definitions = {
        "provenance": (
            values["inputs"].provenance_keyring,
            provenance_module.KEYRING_VERSION,
            provenance_module.KEY_PURPOSE,
            "c-fast-provenance-z01",
        ),
        "t1": (
            values["inputs"].t1_keyring,
            provenance_module.T1_KEYRING_VERSION,
            provenance_module.T1_KEY_PURPOSE,
            "c-fast-t1-z0001",
        ),
        "l3": (
            values["inputs"].outcome_source.release_keyring,
            provenance_module.L3_KEYRING_VERSION,
            provenance_module.L3_KEY_PURPOSE,
            "c-fast-l3-z0001",
        ),
        "outcome": (
            values["inputs"].outcome_keyring,
            outcome_module.OUTCOME_KEYRING_VERSION,
            outcome_module.OUTCOME_KEY_PURPOSE,
            "c-fast-outcome-z01",
        ),
    }
    hashes: dict[str, str] = {}
    for domain, (path, version, purpose, key_id) in definitions.items():
        payload = keyring(
            version,
            purpose,
            [(key_id, materials[domain])],
        )
        write_json(path, payload)
        hashes[domain] = sha256(canonical(payload))
    pins = replace(
        values["pins"],
        provenance_keyring_sha256=hashes["provenance"],
        t1_authority_keyring_sha256=hashes["t1"],
        l3_authority_keyring_sha256=hashes["l3"],
        outcome_keyring_sha256=hashes["outcome"],
    )
    receipt = dict(values["provenance_receipt"])
    receipt["signer_public_key_sha256"] = sha256(
        materials["provenance"]
    )
    receipt["excluded_authority_public_key_sha256s"] = sorted(
        {
            sha256(materials["t1"]),
            sha256(materials["l3"]),
        }
    )
    with pytest.raises(
        readiness_module.ReadinessV3Error,
        match="key domains must be disjoint",
    ):
        readiness_module._validate_complete_key_domains(
            values["inputs"],
            pins,
            receipt,
            sha256(materials["outcome"]),
        )


def test_stale_or_mismatched_outcome_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    values["outcome"].payload["issued_at"] = "2026-08-31T22:00:00+00:00"
    values["outcome"].payload["deployment_ended_at"] = (
        "2026-08-31T21:55:00+00:00"
    )
    with pytest.raises(
        readiness_module.ReadinessV3Error,
        match="stale or has an invalid time relation",
    ):
        derive(values)

    values = build_fixture(tmp_path / "namespace", monkeypatch)
    values["outcome"].payload["questdb_image_digest"] = T1_IMAGE
    with pytest.raises(
        readiness_module.ReadinessV3Error,
        match="signer or namespace mismatch",
    ):
        derive(values)


def test_symlink_input_is_rejected_before_packet_derivation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    external = values["inputs"].external_image_evidence
    target = write_bytes(tmp_path / "external-target.json", external.read_bytes())
    external.unlink()
    external.symlink_to(target)
    with pytest.raises(readiness_module.ReadinessV3Error, match="symlink"):
        derive(values)


def test_invalid_pin_naive_time_and_authority_tamper_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    bad_pins = replace(
        values["pins"],
        provenance_signing_tool_source_commit_sha="0" * 39,
    )
    with pytest.raises(readiness_module.ReadinessV3Error, match="invalid"):
        readiness_module.derive_readiness_packet(
            values["inputs"],
            bad_pins,
            now=NOW,
        )
    with pytest.raises(
        readiness_module.ReadinessV3Error,
        match="timezone-aware",
    ):
        readiness_module.derive_readiness_packet(
            values["inputs"],
            values["pins"],
            now=datetime(2026, 9, 1, 0, 30),
        )
    packet = derive(values)
    packet["production_query_authorized"] = True
    with pytest.raises(
        readiness_module.ReadinessV3Error,
        match="schema validation failed",
    ):
        readiness_module._validate_packet(packet)


@pytest.mark.parametrize(
    "field",
    sorted(readiness_module.READINESS_V3_REQUIRED_FALSE_FIELDS),
)
def test_readiness_v3_specific_authorities_are_schema_const_false(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    packet = derive(values)
    assert packet[field] is False
    packet[field] = True
    with pytest.raises(
        readiness_module.ReadinessV3Error,
        match="schema validation failed",
    ):
        readiness_module._validate_packet(packet)


def test_atomic_pin_manifest_rejects_mixed_generation_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    manifest = pin_manifest(values["pins"])
    raw = canonical(manifest)
    individual = {
        field: str(manifest[field])
        for field in readiness_module.PIN_MANIFEST_VALUE_FIELDS
    }
    individual["outcome_keyring_sha256"] = "f" * 64
    monkeypatch.setattr(
        readiness_module,
        "_pin_root_identity_sha256",
        lambda: "1" * 64,
    )
    monkeypatch.setattr(
        readiness_module,
        "_read_root_owned_pin_manifest",
        lambda: (raw, dict(manifest)),
    )
    monkeypatch.setattr(
        readiness_module,
        "read_root_owned_deployment_pin",
        lambda _path, label: individual[label],
    )
    monkeypatch.setattr(
        readiness_module,
        "_read_packet_custody_facts",
        lambda _path: (
            values["pins"].packet_custody_id,
            values["pins"].packet_custody_identity_sha256,
            values["pins"].packet_custody_directory_identity_sha256,
        ),
    )
    with pytest.raises(
        readiness_module.ReadinessV3Error,
        match="one atomic generation",
    ):
        READ_PRODUCTION_PINS()


def test_atomic_pin_manifest_rotation_during_snapshot_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    before = pin_manifest(values["pins"])
    after = dict(before)
    after["generation_id"] = "readiness-v3-pin-generation-b02"
    snapshots = iter(
        [
            (canonical(before), before),
            (canonical(after), after),
        ]
    )
    individual = {
        field: str(before[field])
        for field in readiness_module.PIN_MANIFEST_VALUE_FIELDS
    }
    monkeypatch.setattr(
        readiness_module,
        "_pin_root_identity_sha256",
        lambda: "1" * 64,
    )
    monkeypatch.setattr(
        readiness_module,
        "_read_root_owned_pin_manifest",
        lambda: next(snapshots),
    )
    monkeypatch.setattr(
        readiness_module,
        "read_root_owned_deployment_pin",
        lambda _path, label: individual[label],
    )
    monkeypatch.setattr(
        readiness_module,
        "_read_packet_custody_facts",
        lambda _path: (
            values["pins"].packet_custody_id,
            values["pins"].packet_custody_identity_sha256,
            values["pins"].packet_custody_directory_identity_sha256,
        ),
    )
    with pytest.raises(
        readiness_module.ReadinessV3Error,
        match="snapshot changed",
    ):
        READ_PRODUCTION_PINS()


def test_readiness_v2_packet_cannot_be_reinterpreted_as_v3(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    packet = derive(values)
    packet["schema_version"] = "commodity_c_fast_t1_readiness_v2"
    packet["packet_id"] = "readiness-v2-" + "0" * 64
    with pytest.raises(
        readiness_module.ReadinessV3Error,
        match="schema validation failed",
    ):
        readiness_module._validate_packet(packet)


def test_real_readiness_v2_packet_file_is_rejected_as_downgrade(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path / "v3", monkeypatch)
    v2_tests = runpy.run_path(
        str(
            ROOT
            / "backend/tests/unit/"
            "test_commodity_c_fast_t1_readiness_v2_script.py"
        )
    )
    v2_values = v2_tests["build_fixture"](
        tmp_path / "v2",
        monkeypatch,
    )
    v2_packet = v2_tests["derive"](v2_values)
    assert v2_packet["schema_version"] == (
        "commodity_c_fast_t1_readiness_v2"
    )
    legacy_path = (
        values["pins"].packet_custody_path / "legacy-readiness-v2.json"
    )
    write_bytes(
        legacy_path,
        json.dumps(
            v2_packet,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
        + b"\n",
    )
    with pytest.raises(
        readiness_module.ReadinessV3Error,
        match="schema validation failed",
    ):
        readiness_module.verify_existing_readiness_packet(
            values["inputs"],
            values["pins"],
            legacy_path,
            require_root_owned_parent=False,
            now=NOW,
        )


def test_packet_is_create_only_and_active_pin_rotation_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    packet = derive(values)
    output = values["pins"].packet_custody_path / (
        f"{packet['packet_id']}.json"
    )
    raw_sha256 = readiness_module.write_packet_create_only(
        packet,
        values["pins"],
        output,
        require_root_owned_parent=False,
        now=NOW,
    )
    assert raw_sha256 == sha256(output.read_bytes())
    assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(readiness_module.ReadinessV3Error):
        readiness_module.write_packet_create_only(
            packet,
            values["pins"],
            output,
            require_root_owned_parent=False,
            now=NOW,
        )

    output.unlink()
    rotated = replace(
        values["pins"],
        provenance_signing_tool_source_sha256="1" * 64,
    )
    monkeypatch.setattr(
        readiness_module,
        "_read_production_pins",
        lambda: rotated,
    )
    with pytest.raises(
        readiness_module.ReadinessV3Error,
        match="active readiness-v3 pins changed",
    ):
        readiness_module.write_packet_create_only(
            packet,
            values["pins"],
            output,
            require_root_owned_parent=False,
            now=NOW,
        )
    assert not output.exists()


def test_pin_rotation_during_write_removes_new_packet(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    packet = derive(values)
    output = values["pins"].packet_custody_path / (
        f"{packet['packet_id']}.json"
    )
    rotated = replace(
        values["pins"],
        pin_set_generation_id="readiness-v3-pin-generation-b02",
    )
    snapshots = iter([values["pins"], rotated])
    monkeypatch.setattr(
        readiness_module,
        "_read_production_pins",
        lambda: next(snapshots),
    )
    with pytest.raises(
        readiness_module.ReadinessV3Error,
        match="active readiness-v3 pins changed",
    ):
        readiness_module.write_packet_create_only(
            packet,
            values["pins"],
            output,
            require_root_owned_parent=False,
            now=NOW,
        )
    assert not output.exists()


def test_same_path_custody_rebuild_rejects_old_write_and_copied_packet(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    packet = derive(values)
    custody = values["pins"].packet_custody_path
    output = custody / f"{packet['packet_id']}.json"
    readiness_module.write_packet_create_only(
        packet,
        values["pins"],
        output,
        require_root_owned_parent=False,
        now=NOW,
    )
    old_raw = output.read_bytes()
    old_identity_raw = (
        custody / readiness_module.CUSTODY_IDENTITY_FILENAME
    ).read_bytes()
    custody.rename(tmp_path / "retired-readiness-v3-custody")
    custody.mkdir(mode=0o700)
    write_bytes(
        custody / readiness_module.CUSTODY_IDENTITY_FILENAME,
        old_identity_raw,
    )
    (
        custody_id,
        custody_identity_sha256,
        new_directory_identity_sha256,
    ) = readiness_module._read_packet_custody_facts(custody)
    assert new_directory_identity_sha256 != (
        values["pins"].packet_custody_directory_identity_sha256
    )
    active_pins = replace(
        values["pins"],
        packet_custody_id=custody_id,
        packet_custody_identity_sha256=custody_identity_sha256,
        packet_custody_directory_identity_sha256=(
            new_directory_identity_sha256
        ),
    )
    monkeypatch.setattr(
        readiness_module,
        "_read_production_pins",
        lambda: active_pins,
    )
    with pytest.raises(
        readiness_module.ReadinessV3Error,
        match="active readiness-v3 pins changed",
    ):
        readiness_module.write_packet_create_only(
            packet,
            values["pins"],
            output,
            require_root_owned_parent=False,
            now=NOW,
        )
    assert not output.exists()

    write_bytes(output, old_raw)
    with pytest.raises(
        readiness_module.ReadinessV3Error,
        match="active pins and custody",
    ):
        readiness_module.verify_existing_readiness_packet(
            values["inputs"],
            active_pins,
            output,
            require_root_owned_parent=False,
            now=NOW,
        )


def test_existing_packet_is_exactly_rederived_and_expires(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    packet = derive(values)
    output = values["pins"].packet_custody_path / (
        f"{packet['packet_id']}.json"
    )
    raw_sha256 = readiness_module.write_packet_create_only(
        packet,
        values["pins"],
        output,
        require_root_owned_parent=False,
        now=NOW,
    )
    verified = readiness_module.verify_existing_readiness_packet(
        values["inputs"],
        values["pins"],
        output,
        require_root_owned_parent=False,
        now=NOW,
    )
    assert verified.payload == packet
    assert verified.raw_sha256 == raw_sha256
    with pytest.raises(
        readiness_module.ReadinessV3Error,
        match="not currently active",
    ):
        readiness_module.verify_existing_readiness_packet(
            values["inputs"],
            values["pins"],
            output,
            require_root_owned_parent=False,
            now=NOW + readiness_module.PACKET_TTL,
        )


def test_verify_existing_rechecks_pin_generation_before_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    packet = derive(values)
    output = values["pins"].packet_custody_path / (
        f"{packet['packet_id']}.json"
    )
    readiness_module.write_packet_create_only(
        packet,
        values["pins"],
        output,
        require_root_owned_parent=False,
        now=NOW,
    )
    rotated = replace(
        values["pins"],
        pin_set_generation_id="readiness-v3-pin-generation-c03",
    )
    snapshots = iter([values["pins"], values["pins"], rotated])
    monkeypatch.setattr(
        readiness_module,
        "_read_production_pins",
        lambda: next(snapshots),
    )
    with pytest.raises(
        readiness_module.ReadinessV3Error,
        match="active readiness-v3 pins changed",
    ):
        readiness_module.verify_existing_readiness_packet(
            values["inputs"],
            values["pins"],
            output,
            require_root_owned_parent=False,
            now=NOW,
        )


def test_existing_packet_whitespace_rewrite_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    packet = derive(values)
    output = values["pins"].packet_custody_path / (
        f"{packet['packet_id']}.json"
    )
    readiness_module.write_packet_create_only(
        packet,
        values["pins"],
        output,
        require_root_owned_parent=False,
        now=NOW,
    )
    output.write_text(
        json.dumps(
            packet,
            ensure_ascii=False,
            indent=4,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n",
        encoding="utf-8",
    )
    output.chmod(0o600)
    with pytest.raises(
        readiness_module.ReadinessV3Error,
        match="exact canonical storage encoding",
    ):
        readiness_module.verify_existing_readiness_packet(
            values["inputs"],
            values["pins"],
            output,
            require_root_owned_parent=False,
            now=NOW,
        )


def test_pending_template_is_not_a_readiness_packet() -> None:
    template_path = (
        ROOT / "docs/operations/c-fast-t1-readiness-v3.template.json"
    )
    template = json.loads(template_path.read_text(encoding="utf-8"))
    assert template["template_only_not_accepted_as_packet_input"] is True
    assert "PENDING_" in template_path.read_text(encoding="utf-8")
    with pytest.raises(
        readiness_module.ReadinessV3Error,
        match="schema validation failed",
    ):
        readiness_module._validate_packet(template)
