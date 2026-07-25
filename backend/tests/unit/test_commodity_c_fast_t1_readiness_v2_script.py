from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

import commodity_c_fast_t1_build_registry_provenance as provenance_module  # noqa: E402
import commodity_c_fast_t1_readiness_v2 as readiness_module  # noqa: E402
import commodity_c_fast_readonly_deployment_outcome as outcome_module  # noqa: E402


NOW = datetime(2026, 9, 1, 0, 30, tzinfo=timezone.utc)
T1_SOURCE = "1" * 40
L3_SOURCE = "2" * 40
OUTCOME_SOURCE = "3" * 40
T1_IMAGE = "sha256:" + "4" * 64
QUESTDB_IMAGE = "sha256:" + "5" * 64
T1_AUTHORITY_PUBLIC_KEY_SHA256 = hashlib.sha256(
    b"mock-t1-authority-public-key"
).hexdigest()
L3_AUTHORITY_PUBLIC_KEY_SHA256 = hashlib.sha256(
    b"mock-l3-authority-public-key"
).hexdigest()
PROVENANCE_SIGNER_PUBLIC_KEY_SHA256 = hashlib.sha256(
    b"mock-provenance-signer-public-key"
).hexdigest()
OUTCOME_SIGNER_PUBLIC_KEY_SHA256 = hashlib.sha256(
    b"mock-outcome-signer-public-key"
).hexdigest()


def write_bytes(path: Path, raw: bytes, *, mode: int = 0o600) -> Path:
    path.write_bytes(raw)
    path.chmod(mode)
    return path


def write_json(path: Path, payload: dict) -> Path:
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return write_bytes(path, raw)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def build_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> dict:
    custody = tmp_path / "readiness-custody"
    custody.mkdir(mode=0o700, parents=True)
    external = write_bytes(tmp_path / "external.json", b"external-evidence")
    oci = write_bytes(tmp_path / "runtime.oci.tar", b"oci-layout")
    content = {
        "source_commit_sha": T1_SOURCE,
        "external_evidence_sha256": sha256(external.read_bytes()),
        "oci_layout_archive_sha256": sha256(oci.read_bytes()),
        "image_reference": f"registry.example/c-fast@{T1_IMAGE}",
        "image_digest": T1_IMAGE,
        "image_id": "sha256:" + "6" * 64,
        "runtime_bundle_sha256": {
            "/opt/c-fast-t1/runtime.py": "7" * 64,
        },
        "verifier_sha256": "8" * 64,
    }
    content_path = write_json(tmp_path / "content.json", content)
    content_raw_sha256 = sha256(content_path.read_bytes())
    pins = readiness_module.ReadinessPins(
        provenance_keyring_sha256="9" * 64,
        t1_authority_keyring_sha256="a" * 64,
        l3_authority_keyring_sha256="b" * 64,
        outcome_keyring_sha256="c" * 64,
        packet_custody_path=custody,
    )
    outcome_source_paths = SimpleNamespace(
        release_keyring=tmp_path / "l3-keyring.json",
    )
    inputs = readiness_module.ReadinessInputs(
        external_image_evidence=external,
        oci_layout_archive=oci,
        source_root=tmp_path,
        content_attestation=content_path,
        provenance=tmp_path / "provenance.json",
        provenance_keyring=tmp_path / "provenance-keyring.json",
        t1_keyring=tmp_path / "t1-keyring.json",
        outcome=tmp_path / "outcome.json",
        outcome_keyring=tmp_path / "outcome-keyring.json",
        outcome_source=outcome_source_paths,
        post_evidence=SimpleNamespace(),
        t1_runtime_source_commit_sha=T1_SOURCE,
        t1_runtime_image_digest=T1_IMAGE,
        l3_contract_source_commit_sha=L3_SOURCE,
        outcome_contract_source_commit_assertion=OUTCOME_SOURCE,
        questdb_image_digest=QUESTDB_IMAGE,
    )
    provenance_receipt = {
        "signed_provenance_raw_sha256": "d" * 64,
        "signed_provenance_canonical_sha256": "e" * 64,
        "content_attestation_raw_sha256": content_raw_sha256,
        "runtime_source_commit_sha": T1_SOURCE,
        "image_digest": T1_IMAGE,
        "signer_key_id": "c-fast-provenance-signer-a01",
        "signer_public_key_sha256": (
            PROVENANCE_SIGNER_PUBLIC_KEY_SHA256
        ),
    }
    outcome_payload = {
        "questdb_image_digest": QUESTDB_IMAGE,
        "release_source_commit_sha": L3_SOURCE,
        "outcome_contract_source_commit_assertion": OUTCOME_SOURCE,
        "issued_at": "2026-09-01T00:20:00+00:00",
        "deployment_ended_at": "2026-09-01T00:15:00+00:00",
        "release_id": "c-fast-readonly-release-a01",
        "attempt_id": "attempt-" + "f" * 64,
        "questdb_target_identity_sha256": "0" * 64,
        "signer_key_id": "c-fast-outcome-signer-a01",
    }
    verified_outcome = SimpleNamespace(
        payload=outcome_payload,
        raw_sha256="1" * 64,
        canonical_sha256="2" * 64,
        outcome_signer_public_key_sha256=(
            OUTCOME_SIGNER_PUBLIC_KEY_SHA256
        ),
        source=SimpleNamespace(
            release_raw_sha256="3" * 64,
            release_canonical_sha256="4" * 64,
            consume_raw_sha256="5" * 64,
            receipt_raw_sha256="6" * 64,
            pre_evidence_bundle_index_sha256="7" * 64,
        ),
        post=SimpleNamespace(bundle_index_sha256="8" * 64),
    )
    def verify_image_evidence(
        evidence_path: Path,
        oci_layout_archive_path: Path,
        source_root: Path,
        expected_source_commit_sha: str,
    ) -> dict:
        assert evidence_path == external
        assert oci_layout_archive_path == oci
        assert source_root == tmp_path
        assert readiness_module.COMMIT_PATTERN.fullmatch(
            expected_source_commit_sha
        )
        return dict(content)

    monkeypatch.setattr(
        readiness_module,
        "verify_image_evidence",
        verify_image_evidence,
    )

    def load_excluded_authority_key_facts(
        *,
        t1_keyring_path: Path,
        expected_t1_keyring_sha256: str,
        l3_keyring_path: Path,
        expected_l3_keyring_sha256: str,
    ) -> tuple[list[str], dict[str, str]]:
        assert t1_keyring_path == inputs.t1_keyring
        assert l3_keyring_path == inputs.outcome_source.release_keyring
        assert (
            expected_t1_keyring_sha256
            == pins.t1_authority_keyring_sha256
        )
        assert (
            expected_l3_keyring_sha256
            == pins.l3_authority_keyring_sha256
        )
        return (
            [
                T1_AUTHORITY_PUBLIC_KEY_SHA256,
                L3_AUTHORITY_PUBLIC_KEY_SHA256,
            ],
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
        load_excluded_authority_key_facts,
    )

    def verify_provenance(
        provenance_path: Path,
        trusted_keyring_path: Path,
        content_attestation_path: Path,
        *,
        expected_trusted_keyring_sha256: str,
        expected_runtime_source_commit_sha: str,
        expected_image_digest: str,
        excluded_authority_key_hashes: list[str],
        excluded_authority_keyring_sha256s: dict[str, str],
        now: datetime,
    ) -> dict:
        assert provenance_path == inputs.provenance
        assert trusted_keyring_path == inputs.provenance_keyring
        assert content_attestation_path == inputs.content_attestation
        assert (
            expected_trusted_keyring_sha256
            == pins.provenance_keyring_sha256
        )
        assert expected_runtime_source_commit_sha == T1_SOURCE
        assert expected_image_digest == T1_IMAGE
        assert excluded_authority_key_hashes == [
            T1_AUTHORITY_PUBLIC_KEY_SHA256,
            L3_AUTHORITY_PUBLIC_KEY_SHA256,
        ]
        assert excluded_authority_keyring_sha256s == {
            "t1_release_keyring_sha256": (
                pins.t1_authority_keyring_sha256
            ),
            "l3_release_keyring_sha256": (
                pins.l3_authority_keyring_sha256
            ),
        }
        assert now == NOW
        return dict(provenance_receipt)

    monkeypatch.setattr(
        readiness_module,
        "verify_provenance",
        verify_provenance,
    )

    def verify_signed_outcome(
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
        assert (
            expected_outcome_keyring_sha256
            == pins.outcome_keyring_sha256
        )
        assert (
            expected_release_keyring_sha256
            == pins.l3_authority_keyring_sha256
        )
        assert (
            expected_t1_keyring_sha256
            == pins.t1_authority_keyring_sha256
        )
        assert expected_outcome_source_commit_sha == OUTCOME_SOURCE
        assert expected_release_source_commit_sha == L3_SOURCE
        assert expected_questdb_image_digest == QUESTDB_IMAGE
        assert now == NOW
        return verified_outcome

    monkeypatch.setattr(
        readiness_module,
        "verify_signed_outcome",
        verify_signed_outcome,
    )
    return {
        "inputs": inputs,
        "pins": pins,
        "content": content,
        "provenance_receipt": provenance_receipt,
        "outcome": verified_outcome,
    }


def derive(values: dict) -> dict:
    return readiness_module.derive_readiness_packet(
        values["inputs"],
        values["pins"],
        now=NOW,
    )


def test_deny_matrix_covers_deployment_outcome_contract() -> None:
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


def test_success_packet_keeps_all_authority_closed_and_namespaces_separate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    packet = derive(values)

    assert packet["status"] == readiness_module.STATUS
    assert packet["blocking_reasons"] == []
    assert packet["requirements"]["requires_t1_release_v2"] is True
    assert packet["requirements"]["t1_release_v1_accepted"] is False
    assert packet["source_namespaces"] == {
        "t1_runtime_source_commit_sha": T1_SOURCE,
        "l3_contract_source_commit_sha": L3_SOURCE,
        "outcome_contract_source_commit_assertion": OUTCOME_SOURCE,
    }
    assert packet["digest_namespaces"] == {
        "t1_runtime_image_digest": T1_IMAGE,
        "questdb_image_digest": QUESTDB_IMAGE,
    }
    assert packet["build_registry_provenance"][
        "signer_public_key_sha256"
    ] == PROVENANCE_SIGNER_PUBLIC_KEY_SHA256
    assert packet["readonly_deployment_outcome"][
        "signer_public_key_sha256"
    ] == OUTCOME_SIGNER_PUBLIC_KEY_SHA256
    for field in readiness_module.FALSE_AUTHORITY_FIELDS:
        assert packet[field] is False
    for field in readiness_module.ZERO_FACT_FIELDS:
        assert packet[field] == 0


def test_supplied_content_report_must_equal_rerun_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    fabricated = dict(values["content"])
    fabricated["image_id"] = "sha256:" + "9" * 64
    monkeypatch.setattr(
        readiness_module,
        "verify_image_evidence",
        lambda *_args, **_kwargs: fabricated,
    )
    with pytest.raises(
        readiness_module.ReadinessV2Error,
        match="exact regenerated report",
    ):
        derive(values)


def test_provenance_must_bind_exact_content_raw_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    receipt = dict(values["provenance_receipt"])
    receipt["content_attestation_raw_sha256"] = "0" * 64
    monkeypatch.setattr(
        readiness_module,
        "verify_provenance",
        lambda *_args, **_kwargs: receipt,
    )
    with pytest.raises(
        readiness_module.ReadinessV2Error,
        match="exact T1 runtime report",
    ):
        derive(values)


def test_signature_or_authority_verifier_failure_is_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)

    def fail(*_args, **_kwargs):
        raise provenance_module.BuildRegistryProvenanceError(
            "provenance signature is invalid"
        )

    monkeypatch.setattr(readiness_module, "verify_provenance", fail)
    with pytest.raises(
        readiness_module.ReadinessV2Error,
        match="signature is invalid",
    ):
        derive(values)


def test_provenance_and_outcome_signers_must_be_distinct(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    values["outcome"].outcome_signer_public_key_sha256 = (
        PROVENANCE_SIGNER_PUBLIC_KEY_SHA256
    )
    with pytest.raises(
        readiness_module.ReadinessV2Error,
        match="require distinct signer keys",
    ):
        derive(values)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        (
            "t1_runtime_image_digest",
            "sha256:" + "0" * 64,
            "T1 runtime image digest namespace mismatch",
        ),
        (
            "t1_runtime_source_commit_sha",
            "0" * 40,
            "T1 runtime source namespace mismatch",
        ),
    ],
)
def test_runtime_source_and_digest_namespaces_cannot_be_conflated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
    message: str,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    values["inputs"] = replace(values["inputs"], **{field: value})
    with pytest.raises(readiness_module.ReadinessV2Error, match=message):
        derive(values)


def test_outcome_namespace_mismatch_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    values["outcome"].payload["questdb_image_digest"] = T1_IMAGE
    with pytest.raises(
        readiness_module.ReadinessV2Error,
        match="deployment outcome namespace mismatch",
    ):
        derive(values)


def test_stale_deployment_outcome_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    values["outcome"].payload["issued_at"] = "2026-08-31T22:00:00+00:00"
    values["outcome"].payload["deployment_ended_at"] = (
        "2026-08-31T21:55:00+00:00"
    )
    with pytest.raises(
        readiness_module.ReadinessV2Error,
        match="stale or has an invalid time relation",
    ):
        derive(values)


def test_old_deployment_with_fresh_delayed_signature_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    values["outcome"].payload["issued_at"] = (
        "2026-09-01T00:20:00+00:00"
    )
    values["outcome"].payload["deployment_ended_at"] = (
        "2026-08-31T01:20:00+00:00"
    )
    with pytest.raises(
        readiness_module.ReadinessV2Error,
        match="stale or has an invalid time relation",
    ):
        derive(values)


def test_invalid_pin_and_naive_time_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    values["pins"] = replace(
        values["pins"],
        provenance_keyring_sha256="f" * 63,
    )
    with pytest.raises(readiness_module.ReadinessV2Error, match="lowercase"):
        derive(values)

    values = build_fixture(tmp_path / "naive", monkeypatch)
    with pytest.raises(
        readiness_module.ReadinessV2Error,
        match="timezone-aware",
    ):
        readiness_module.derive_readiness_packet(
            values["inputs"],
            values["pins"],
            now=datetime(2026, 9, 1, 0, 30),
        )


def test_caller_cannot_turn_packet_into_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    packet = derive(values)
    packet["production_query_authorized"] = True
    with pytest.raises(
        readiness_module.ReadinessV2Error,
        match="schema validation failed",
    ):
        readiness_module._validate_packet(packet)

    packet = derive(values)
    packet["caller_ready_override"] = True
    with pytest.raises(
        readiness_module.ReadinessV2Error,
        match="schema validation failed",
    ):
        readiness_module._validate_packet(packet)

    packet = derive(values)
    packet["t1_runtime"]["image_id"] = "sha256:" + "f" * 64
    with pytest.raises(
        readiness_module.ReadinessV2Error,
        match="packet ID does not bind exact facts",
    ):
        readiness_module._validate_packet(packet)

    packet = derive(values)
    packet["generated_at"] = "2026-09-01T00:31:00+00:00"
    packet["expires_at"] = "2026-09-01T00:46:00+00:00"
    with pytest.raises(
        readiness_module.ReadinessV2Error,
        match="packet ID does not bind exact facts",
    ):
        readiness_module._validate_packet(packet)


def test_packet_is_create_only_in_exact_pinned_custody(
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
    with pytest.raises(readiness_module.ReadinessV2Error):
        readiness_module.write_packet_create_only(
            packet,
            values["pins"],
            output,
            require_root_owned_parent=False,
            now=NOW,
        )

    wrong = values["pins"].packet_custody_path / "caller-ready.json"
    with pytest.raises(
        readiness_module.ReadinessV2Error,
        match="exact pinned custody",
    ):
        readiness_module.write_packet_create_only(
            packet,
            values["pins"],
            wrong,
            require_root_owned_parent=False,
            now=NOW,
        )

    alternate_custody = tmp_path / "alternate-custody"
    alternate_custody.mkdir(mode=0o700)
    alternate_pins = replace(
        values["pins"],
        packet_custody_path=alternate_custody,
    )
    alternate_output = alternate_custody / f"{packet['packet_id']}.json"
    with pytest.raises(
        readiness_module.ReadinessV2Error,
        match="does not bind the active pins and custody",
    ):
        readiness_module.write_packet_create_only(
            packet,
            alternate_pins,
            alternate_output,
            require_root_owned_parent=False,
            now=NOW,
        )
    assert not alternate_output.exists()

    substituted_keyring_pins = replace(
        values["pins"],
        outcome_keyring_sha256="e" * 64,
    )
    with pytest.raises(
        readiness_module.ReadinessV2Error,
        match="does not bind the active pins and custody",
    ):
        readiness_module.write_packet_create_only(
            packet,
            substituted_keyring_pins,
            output,
            require_root_owned_parent=False,
            now=NOW,
        )


def test_expired_packet_cannot_be_written(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = build_fixture(tmp_path, monkeypatch)
    packet = derive(values)
    output = values["pins"].packet_custody_path / (
        f"{packet['packet_id']}.json"
    )
    with pytest.raises(
        readiness_module.ReadinessV2Error,
        match="not current at create-only write time",
    ):
        readiness_module.write_packet_create_only(
            packet,
            values["pins"],
            output,
            require_root_owned_parent=False,
            now=NOW + readiness_module.PACKET_TTL,
        )
    assert not output.exists()
