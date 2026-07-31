from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import commodity_c_fast_t1_p0_preflight as subject  # noqa: E402
from c_fast_t1.validate_query_v4_runtime import validate_package  # noqa: E402
from commodity_c_fast_t1_readiness_v3 import (  # noqa: E402
    VerifiedReadinessPacket,
)


SHA = "a" * 64
COMMIT = "b" * 40
OCI_DIGEST = "sha256:" + "c" * 64
NOW = datetime(2026, 7, 31, 3, 0, tzinfo=timezone.utc)


def _readiness(
    *,
    source_commit: str = COMMIT,
) -> VerifiedReadinessPacket:
    payload = {
        "packet_id": "readiness-v3-" + "d" * 64,
        "expires_at": (
            NOW + timedelta(minutes=10)
        ).isoformat().replace("+00:00", "Z"),
        "source_namespaces": {
            "t1_runtime_source_commit_sha": source_commit,
        },
        "digest_namespaces": {
            "questdb_image_digest": OCI_DIGEST,
        },
        "readonly_deployment_outcome": {
            "signed_outcome_raw_sha256": "e" * 64,
            "signed_outcome_canonical_sha256": "f" * 64,
            "questdb_target_identity_sha256": "1" * 64,
        },
    }
    return VerifiedReadinessPacket(
        payload=payload,
        raw_sha256="2" * 64,
        canonical_sha256="3" * 64,
    )


def _attestation(
    *,
    source_commit: str = COMMIT,
) -> dict:
    return {
        "schema_version": (
            "commodity_c_fast_t1_query_v4_image_attestation_v1"
        ),
        "status": (
            "QUERY_V4_SOURCE_BUNDLE_AND_OCI_CONTENT_VERIFIED_"
            "NO_BUILD_OR_REGISTRY_PROVENANCE"
        ),
        "source_commit_sha": source_commit,
        "source_bundle_archive_sha256": "4" * 64,
        "verifier_sha256": "5" * 64,
        "delegate_verifier_sha256": "9" * 64,
        "image_reference": (
            "registry.invalid/c-fast/query-v4@" + OCI_DIGEST
        ),
        "image_digest": OCI_DIGEST,
        "image_id": "sha256:" + "6" * 64,
        "runtime_bundle_index_sha256": "7" * 64,
        "containerfile_sha256": validate_package()["containerfile"][
            "containerfile_sha256"
        ],
        "authority_granted": False,
        "production_query_authorized": False,
        "database_mutations": 0,
        "orders_sent": 0,
        "positions_modified": 0,
    }


def _dsn(tmp_path: Path) -> tuple[Path, dict]:
    path = tmp_path / "readonly.dsn"
    path.write_text("postgresql://readonly:redacted@questdb.invalid:8812/qdb")
    path.chmod(0o600)
    return path, subject.readonly_dsn_metadata(path)


def test_preflight_binds_exact_v4_readiness_l3_and_dsn_without_authority(
    tmp_path: Path,
) -> None:
    dsn_path, dsn = _dsn(tmp_path)
    attestation = _attestation()
    raw = subject.canonical_json(attestation)
    packet = subject.build_preflight(
        _readiness(),
        attestation,
        raw,
        validate_package(),
        dsn,
        now=NOW,
    )

    assert packet["status"] == subject.STATUS
    assert packet["query_v4"]["source_commit_sha"] == COMMIT
    assert packet["upstream_readiness"]["shared_source_commit_sha"] == COMMIT
    assert packet["readonly_dsn"] == dsn
    assert packet["readonly_dsn"]["content_read"] is False
    assert packet["ready_for_human_query_release_only"] is False
    assert packet["production_query_attempted"] is False
    assert packet["production_query_completed"] is False
    assert packet["p0_verdict"] == "NOT_RUN"
    assert packet["authority_granted"] is False
    assert packet["network_authorized"] is False
    assert packet["orders_sent"] == 0
    assert str(dsn_path) not in json.dumps(packet)


def test_source_commit_splice_fails_closed(tmp_path: Path) -> None:
    _path, dsn = _dsn(tmp_path)
    with pytest.raises(
        subject.T1P0PreflightError,
        match="source commit",
    ):
        subject.build_preflight(
            _readiness(source_commit="8" * 40),
            _attestation(source_commit="9" * 40),
            b"{}",
            validate_package(),
            dsn,
            now=NOW,
        )


def test_containerfile_splice_fails_closed(tmp_path: Path) -> None:
    _path, dsn = _dsn(tmp_path)
    attestation = _attestation()
    attestation["containerfile_sha256"] = "0" * 64
    with pytest.raises(
        subject.T1P0PreflightError,
        match="packaging",
    ):
        subject.build_preflight(
            _readiness(),
            attestation,
            b"{}",
            validate_package(),
            dsn,
            now=NOW,
        )


@pytest.mark.parametrize("mode", [0o604, 0o640, 0o644])
def test_readonly_dsn_must_be_private(
    tmp_path: Path,
    mode: int,
) -> None:
    path = tmp_path / f"readonly-{mode:o}.dsn"
    path.write_text("postgresql://readonly:redacted@questdb.invalid:8812/qdb")
    path.chmod(mode)
    with pytest.raises(
        subject.T1P0PreflightError,
        match="0600",
    ):
        subject.readonly_dsn_metadata(path)


def test_readonly_dsn_symlink_is_rejected(tmp_path: Path) -> None:
    target, _metadata = _dsn(tmp_path)
    link = tmp_path / "readonly-link.dsn"
    link.symlink_to(target)
    with pytest.raises(
        subject.T1P0PreflightError,
        match="non-symlink",
    ):
        subject.readonly_dsn_metadata(link)


def test_output_is_private_create_only(tmp_path: Path) -> None:
    _path, dsn = _dsn(tmp_path)
    packet = subject.build_preflight(
        _readiness(),
        _attestation(),
        b"{}",
        validate_package(),
        dsn,
        now=NOW,
    )
    output = (tmp_path / "preflight.json").resolve()

    digest = subject.write_create_only(output, packet)

    assert len(digest) == 64
    assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(
        subject.T1P0PreflightError,
        match="cannot create",
    ):
        subject.write_create_only(output, packet)


def test_no_secret_or_network_read_primitive_enters_preflight() -> None:
    source = subject.Path(subject.__file__).read_text(encoding="utf-8")
    dsn_function = source[
        source.index("def readonly_dsn_metadata"):
        source.index("def _preflight_identity")
    ]
    assert ".read_text(" not in dsn_function
    assert ".read_bytes(" not in dsn_function
    assert "socket" not in source
    assert "psycopg" not in source
    assert "subprocess" not in source
    assert "requests" not in source
