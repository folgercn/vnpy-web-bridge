from __future__ import annotations

import base64
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import commodity_c_fast_t1_query_v5_release as subject  # noqa: E402
import commodity_c_fast_t1_query_v5_sign as signer  # noqa: E402


NOW = datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc)
SOURCE_COMMIT = subprocess.run(
    ["git", "rev-parse", "HEAD"],
    cwd=ROOT,
    check=True,
    capture_output=True,
    text=True,
).stdout.strip()
ATTESTATION_RUNTIME_DIGEST = "sha256:" + "4" * 64
IMAGE_ATTESTATION_TEST_HELPER = (
    ROOT / "backend/tests/unit/test_c_fast_t1_query_v5_image_attestation.py"
)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return subject.canonical_json(payload) + b"\n"


def _image_attestation_helper() -> Any:
    name = "_query_v5_release_image_attestation_test_helper"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, IMAGE_ATTESTATION_TEST_HELPER)
    assert spec is not None and spec.loader is not None
    helper = importlib.util.module_from_spec(spec)
    sys.modules[name] = helper
    spec.loader.exec_module(helper)
    return helper


def _test_runtime_identity() -> Any:
    verifier = subject.composition_verifier
    values = {
        field: _sha(("query-v5-release-test:" + field).encode("utf-8"))
        for field in verifier.QueryV5AttestationRuntimeIdentity.__dataclass_fields__
        if field.endswith("_sha256")
    }
    values.update(
        {
            "launcher_sha256": _sha(
                (
                    ROOT
                    / "scripts/"
                    "commodity_c_fast_t1_query_v5_image_attestation_launcher.py"
                ).read_bytes()
            ),
            "verifier_sha256": _sha(Path(verifier.__file__).read_bytes()),
            "query_v4_verifier_sha256": _sha(
                Path(verifier.query_v4.__file__).read_bytes()
            ),
            "query_v4_delegate_sha256": _sha(
                Path(verifier._delegate.__file__).read_bytes()
            ),
            "query_v5_validator_sha256": _sha(
                (ROOT / "scripts/c_fast_t1/validate_query_v5_runtime.py").read_bytes()
            ),
            "query_v4_validator_sha256": _sha(
                (ROOT / "scripts/c_fast_t1/validate_query_v4_runtime.py").read_bytes()
            ),
        }
    )
    return verifier.QueryV5AttestationRuntimeIdentity(
        runtime_image_digest="sha256:" + "a" * 64,
        **values,
        isolated_flags_verified=False,
        pre_import_runtime_verified=False,
        source_closure_retained=True,
        immutable_runtime_verified=False,
        external_runtime_identity_required=True,
    )


def _exact_composition_artifacts(tmp_path: Path) -> dict[str, Any]:
    helper = _image_attestation_helper()
    verifier = subject.composition_verifier
    identity = _test_runtime_identity()
    verifier._ACTIVE_RUNTIME_IDENTITY = identity
    verifier._ACTIVE_RUNTIME_REVALIDATOR = (
        lambda: subject._revalidate_composition_verifier_sources(identity)
    )
    artifacts = helper._artifacts(tmp_path, SOURCE_COMMIT)
    evidence = json.loads(artifacts["evidence"].read_text(encoding="utf-8"))
    evidence["captured_at"] = "2026-08-01T10:20:00+00:00"
    artifacts["evidence"].write_bytes(subject.canonical_json(evidence))
    composition = helper._verify(artifacts, SOURCE_COMMIT)
    replay = subject.CompositionReplayInputs(
        query_v4_external_image_evidence_path=artifacts["v4_evidence"],
        query_v4_source_bundle_path=artifacts["v4_bundle"],
        query_v4_oci_layout_archive_path=artifacts["v4_oci"],
        query_v4_content_attestation_path=artifacts["v4_report"],
        expected_query_v4_source_commit_sha=SOURCE_COMMIT,
        external_image_evidence_path=artifacts["evidence"],
        source_bundle_path=artifacts["bundle"],
        final_oci_layout_path=artifacts["oci"],
    )
    return {"composition": composition, "replay": replay, **artifacts}


def _tar(entries: list[tuple[str, bytes]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:", format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in entries:
            member = tarfile.TarInfo(name)
            member.mode = 0o644
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            member.mtime = 0
            member.size = len(raw)
            member.type = tarfile.REGTYPE
            archive.addfile(member, io.BytesIO(raw))
    return output.getvalue()


def _final_oci_fixture() -> tuple[bytes, str, str, list[str], list[str]]:
    layer_raw = _tar([])
    layer_digest = "sha256:" + _sha(layer_raw)
    diff_id = layer_digest
    config_raw = subject.canonical_json(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {},
            "rootfs": {"type": "layers", "diff_ids": [diff_id]},
        }
    )
    config_digest = "sha256:" + _sha(config_raw)
    manifest_raw = subject.canonical_json(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": len(config_raw),
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": layer_digest,
                    "size": len(layer_raw),
                }
            ],
        }
    )
    manifest_digest = "sha256:" + _sha(manifest_raw)
    index_raw = subject.canonical_json(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": manifest_digest,
                    "size": len(manifest_raw),
                    "platform": {"architecture": "amd64", "os": "linux"},
                }
            ],
        }
    )
    archive_raw = _tar(
        [
            ("oci-layout", subject.canonical_json({"imageLayoutVersion": "1.0.0"})),
            ("index.json", index_raw),
            (f"blobs/sha256/{config_digest[7:]}", config_raw),
            (f"blobs/sha256/{layer_digest[7:]}", layer_raw),
            (f"blobs/sha256/{manifest_digest[7:]}", manifest_raw),
        ]
    )
    return archive_raw, manifest_digest, config_digest, [layer_digest], [diff_id]


(
    FINAL_OCI_RAW,
    IMAGE_DIGEST,
    IMAGE_ID,
    ROOTFS_LAYER_DIGESTS,
    ROOTFS_DIFF_IDS,
) = _final_oci_fixture()
IMAGE_REFERENCE = f"registry.example.invalid/research/c-fast-query-v5@{IMAGE_DIGEST}"


def _write(path: Path, raw: bytes, *, private: bool = False) -> Path:
    path.write_bytes(raw)
    path.chmod(0o600 if private else 0o644)
    return path


def _keyring(
    key: Ed25519PrivateKey,
    *,
    schema_version: str,
    purpose: str,
    key_id: str,
) -> dict[str, Any]:
    raw = key.public_key().public_bytes_raw()
    return {
        "schema_version": schema_version,
        "keys": [
            {
                "key_id": key_id,
                "purpose": purpose,
                "public_key_base64": base64.b64encode(raw).decode("ascii"),
            }
        ],
    }


def _composition() -> dict[str, Any]:
    runtime = {
        "schema_version": (
            "commodity_c_fast_t1_query_v5_image_attestation_runtime_identity_v2"
        ),
        "runtime_image_digest": ATTESTATION_RUNTIME_DIGEST,
        "pin_manifest_sha256": "5" * 64,
        "launcher_sha256": "6" * 64,
        "verifier_sha256": "9" * 64,
        "query_v4_verifier_sha256": "8" * 64,
        "query_v4_delegate_sha256": "9" * 64,
        "query_v5_validator_sha256": "a" * 64,
        "query_v4_validator_sha256": "b" * 64,
        "bootstrap_pin_sha256": "c" * 64,
        "python_executable_path_sha256": "d" * 64,
        "python_executable_sha256": "e" * 64,
        "loaded_executable_sha256": "e" * 64,
        "python_runtime_root_path_sha256": "f" * 64,
        "python_runtime_closure_sha256": "0" * 64,
        "native_runtime_root_path_sha256": "1" * 64,
        "native_runtime_closure_sha256": "2" * 64,
        "source_root_path_sha256": "3" * 64,
        "source_root_identity_sha256": "4" * 64,
        "source_closure_manifest_sha256": "5" * 64,
        "bootstrap_source_closure_sha256": "6" * 64,
        "dependency_root_path_sha256": "7" * 64,
        "dependency_root_identity_sha256": "8" * 64,
        "dependency_closure_manifest_sha256": "9" * 64,
        "bootstrap_dependency_closure_sha256": "a" * 64,
        "isolated_flags_verified": False,
        "pre_import_runtime_verified": False,
        "source_closure_retained": True,
        "immutable_runtime_verified": False,
        "external_runtime_identity_required": True,
    }
    runtime["runtime_identity_sha256"] = _sha(subject.canonical_json(runtime))
    runtime_bundle = {
        "/opt/c-fast-query-v5/release/scripts/commodity_c_fast_t1_query_v5_launcher.py": (
            "b" * 64
        )
    }
    checks = {
        "query_v4_content_attestation_replayed": True,
        "query_v4_raw_oci_recomputed": True,
        "source_bundle_and_manifest_recomputed": True,
        "containerfile_instruction_contract_matched": True,
        "oci_manifest_config_and_layers_recomputed": True,
        "query_v4_layer_descriptor_prefix_verified": True,
        "query_v4_diff_id_prefix_verified": True,
        "inherited_oci_config_fields_frozen": True,
        "overlay_whiteouts_absent": True,
        "overlay_base_overwrites_absent": True,
        "overlay_path_allowlist_verified": True,
        "overlay_links_and_special_files_absent": True,
        "overlay_layers_strict_ustar_verified": True,
        "all_overlay_layer_contents_sensitive_free": True,
        "merged_python_execution_closure_frozen": True,
        "runtime_bundle_matches_source_bundle": True,
        "immutable_image_reference_matched": True,
        "attestation_runtime_externally_verified": False,
        "external_exact_runtime_image_required": True,
        "build_provenance_verified": False,
        "registry_provenance_verified": False,
    }
    return {
        "schema_version": subject.COMPOSITION_VERSION,
        "status": subject.COMPOSITION_STATUS,
        "query_v4_source_commit_sha": "0" * 40,
        "source_commit_sha": SOURCE_COMMIT,
        "query_v4_content_attestation_raw_sha256": "1" * 64,
        "query_v4_content_attestation_canonical_sha256": "2" * 64,
        "query_v4_oci_layout_archive_sha256": "3" * 64,
        "source_bundle_archive_sha256": "4" * 64,
        "source_manifest_raw_sha256": "5" * 64,
        "source_manifest_canonical_sha256": "6" * 64,
        "external_evidence_sha256": "7" * 64,
        "evidence_captured_at": "2026-08-01T10:20:00+00:00",
        "containerfile_sha256": "8" * 64,
        "verifier_sha256": "9" * 64,
        "attestation_runtime": runtime,
        "source_manifest_schema_sha256": "a" * 64,
        "evidence_schema_sha256": "b" * 64,
        "attestation_schema_sha256": subject._schema_sha256(
            subject.COMPOSITION_SCHEMA_PATH, "composition schema"
        ),
        "query_v4_image_reference": (
            "registry.example.invalid/research/c-fast-query-v4@sha256:" + "c" * 64
        ),
        "query_v4_image_digest": "sha256:" + "c" * 64,
        "query_v4_image_id": "sha256:" + "d" * 64,
        "image_reference": IMAGE_REFERENCE,
        "image_digest": IMAGE_DIGEST,
        "image_id": IMAGE_ID,
        "query_v4_rootfs_layer_digests": ["sha256:" + "e" * 64],
        "query_v4_rootfs_diff_ids": ["sha256:" + "f" * 64],
        "overlay_layer_digests": ["sha256:" + "0" * 64],
        "overlay_diff_ids": ["sha256:" + "1" * 64],
        "overlay_layer_header_contract_sha256": ["2" * 64],
        "rootfs_layer_digests": ROOTFS_LAYER_DIGESTS,
        "rootfs_diff_ids": ROOTFS_DIFF_IDS,
        "overlay_touched_paths": ["/opt/c-fast-query-v5"],
        "python_execution_closure_sha256": "3" * 64,
        "python_execution_closure_entries": 12,
        "runtime_bundle_sha256": runtime_bundle,
        "runtime_bundle_index_sha256": _sha(subject.canonical_json(runtime_bundle)),
        "checks": checks,
        "image_built_here": False,
        "cryptographic_approval_present": False,
        "sensitive_material_present": False,
        "authority_granted": False,
        "network_authorized": False,
        "production_query_authorized": False,
        "collection_authorized": False,
        "deployment_mutation_authorized": False,
        "runtime_activation_authorized": False,
        "order_authorized": False,
        "position_mutation_authorized": False,
        "dispatch_authorized": False,
        "trading_authorized": False,
        "production_authorized": False,
        "database_mutations": 0,
        "orders_sent": 0,
        "positions_modified": 0,
        "dispatch_changed": False,
    }


def _provenance_draft(
    composition: dict[str, Any],
    final_oci_raw: bytes,
) -> dict[str, Any]:
    runtime = composition["attestation_runtime"]
    payload = {
        "schema_version": subject.PROVENANCE_VERSION,
        "provenance_id": "query-v5-provenance-test-0001",
        "candidate_id": subject.CANDIDATE_ID,
        "purpose": subject.PROVENANCE_PURPOSE,
        "issued_at": "2026-08-01T10:32:00+00:00",
        "signer_key_id": "query-v5-provenance-key-1",
        "runtime_source_commit_sha": SOURCE_COMMIT,
        "composition_attestation_raw_sha256": _sha(_json_bytes(composition)),
        "composition_attestation_canonical_sha256": _sha(
            subject.canonical_json(composition)
        ),
        "composition_attestation_schema_sha256": composition[
            "attestation_schema_sha256"
        ],
        "composition_attestation_runtime_image_digest": runtime["runtime_image_digest"],
        "composition_attestation_runtime_identity_sha256": runtime[
            "runtime_identity_sha256"
        ],
        "composition_attestation_runtime_repo_digest_verified": True,
        "source_bundle_archive_sha256": composition["source_bundle_archive_sha256"],
        "source_manifest_raw_sha256": composition["source_manifest_raw_sha256"],
        "source_manifest_canonical_sha256": composition[
            "source_manifest_canonical_sha256"
        ],
        "source_manifest_schema_sha256": composition["source_manifest_schema_sha256"],
        "final_oci_layout_archive_sha256": _sha(final_oci_raw),
        "containerfile_sha256": composition["containerfile_sha256"],
        "image_reference": composition["image_reference"],
        "image_digest": composition["image_digest"],
        "image_id": composition["image_id"],
        "rootfs_layer_digests": composition["rootfs_layer_digests"],
        "rootfs_diff_ids": composition["rootfs_diff_ids"],
        "runtime_bundle_index_sha256": composition["runtime_bundle_index_sha256"],
        "build": {
            "builder_identity_sha256": "1" * 64,
            "build_invocation_sha256": "2" * 64,
            "build_log_archive_sha256": "3" * 64,
            "platform": "linux/amd64",
            "started_at": "2026-08-01T10:00:00+00:00",
            "completed_at": "2026-08-01T10:10:00+00:00",
            "exact_source_archive_used": True,
            "exact_containerfile_used": True,
            "build_exit_code": 0,
            "output_oci_layout_archive_sha256": _sha(final_oci_raw),
            "output_image_digest": composition["image_digest"],
            "output_image_id": composition["image_id"],
            "sensitive_material_present": False,
        },
        "registry": {
            "registry_identity_sha256": "4" * 64,
            "repository": composition["image_reference"].rsplit("@", 1)[0],
            "immutable_reference": composition["image_reference"],
            "manifest_digest": composition["image_digest"],
            "push_receipt_sha256": "5" * 64,
            "pushed_at": "2026-08-01T10:30:00+00:00",
            "observed_at": "2026-08-01T10:31:00+00:00",
            "digest_reference_resolved": True,
            "manifest_digest_matched": True,
            "mutable_tag_trusted": False,
            "sensitive_material_present": False,
        },
        "external_fact_scope": (
            "SIGNED_EXTERNAL_BUILD_REGISTRY_ASSERTION_NOT_REQUERIED_BY_OFFLINE_GATE"
        ),
        "signing_tool_source_commit_sha": SOURCE_COMMIT,
    }
    payload.update({field: False for field in subject.PROVENANCE_FALSE_FIELDS})
    payload.update({field: 0 for field in subject.PROVENANCE_ZERO_FIELDS})
    return payload


def _release_draft() -> dict[str, Any]:
    payload = {
        "schema_version": subject.RELEASE_VERSION,
        "purpose": subject.RELEASE_PURPOSE,
        "candidate_id": subject.CANDIDATE_ID,
        "parent_issue_number": 114,
        "issue_number": 216,
        "release_id": "query-v5-release-test-0001",
        "issued_at": "2026-08-01T11:59:00+00:00",
        "not_before": "2026-08-01T11:59:00+00:00",
        "expires_at": "2026-08-01T12:05:00+00:00",
        "signer_key_id": "query-v5-release-key-1",
        "signer_type": "human",
        "reviewer_role": "independent-release-reviewer",
        "human_signature": "human approved exact query-v5 release test",
        "maximum_release_ttl_seconds": 600,
        "minimum_launch_margin_seconds": 30,
    }
    payload.update({field: True for field in subject.RELEASE_TRUE_FIELDS})
    payload.update({field: False for field in subject.RELEASE_FALSE_FIELDS})
    return payload


def _fixture(tmp_path: Path) -> dict[str, Any]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    exact = _exact_composition_artifacts(tmp_path)
    composition = exact["composition"]
    composition_path = _write(tmp_path / "composition.json", _json_bytes(composition))
    final_oci_path = exact["oci"]
    final_oci_raw = final_oci_path.read_bytes()
    final_oci = subject.load_verified_final_oci(final_oci_path)
    provenance_key = Ed25519PrivateKey.generate()
    release_key = Ed25519PrivateKey.generate()
    provenance_keyring = _keyring(
        provenance_key,
        schema_version=subject.PROVENANCE_KEYRING_VERSION,
        purpose=subject.PROVENANCE_KEY_PURPOSE,
        key_id="query-v5-provenance-key-1",
    )
    release_keyring = _keyring(
        release_key,
        schema_version="commodity_c_fast_t1_query_v5_trusted_keys_v1",
        purpose=subject.RELEASE_KEY_PURPOSE,
        key_id="query-v5-release-key-1",
    )
    provenance_keyring_hash = _sha(subject.canonical_json(provenance_keyring))
    release_keyring_hash = _sha(subject.canonical_json(release_keyring))
    provenance_keyring_path = _write(
        tmp_path / "provenance-keyring.json",
        _json_bytes(provenance_keyring),
        private=True,
    )
    release_keyring_path = _write(
        tmp_path / "release-keyring.json",
        _json_bytes(release_keyring),
        private=True,
    )
    signed_provenance = signer.sign_provenance(
        _provenance_draft(composition, final_oci_raw),
        provenance_keyring,
        _json_bytes(composition),
        composition,
        final_oci,
        exact["replay"],
        provenance_key,
        expected_keyring_sha256=provenance_keyring_hash,
        expected_source_commit_sha=SOURCE_COMMIT,
        expected_image_digest=composition["image_digest"],
        now=NOW,
    )
    provenance_path = _write(
        tmp_path / "provenance.signed.json",
        _json_bytes(signed_provenance),
    )
    verified, materials = subject.verify_provenance(
        provenance_path,
        provenance_keyring_path,
        composition_path,
        final_oci_path,
        exact["replay"],
        expected_provenance_keyring_sha256=provenance_keyring_hash,
        expected_source_commit_sha=SOURCE_COMMIT,
        expected_image_digest=composition["image_digest"],
        now=NOW,
    )
    signed_release = signer.sign_release(
        _release_draft(),
        release_keyring,
        verified,
        materials,
        release_key,
        expected_keyring_sha256=release_keyring_hash,
        now=NOW,
    )
    release_path = _write(tmp_path / "release.signed.json", _json_bytes(signed_release))
    return {
        "composition": composition,
        "composition_path": composition_path,
        "final_oci_path": final_oci_path,
        "composition_replay": exact["replay"],
        "expected_image_digest": composition["image_digest"],
        "provenance": signed_provenance,
        "provenance_path": provenance_path,
        "provenance_keyring": provenance_keyring,
        "provenance_keyring_path": provenance_keyring_path,
        "provenance_keyring_hash": provenance_keyring_hash,
        "provenance_key": provenance_key,
        "verified_provenance": verified,
        "provenance_materials": materials,
        "release": signed_release,
        "release_path": release_path,
        "release_keyring": release_keyring,
        "release_keyring_path": release_keyring_path,
        "release_keyring_hash": release_keyring_hash,
        "exact_artifacts": exact,
    }


def _run_gate(tmp_path: Path, fixture: dict[str, Any]) -> dict[str, Any]:
    return subject.run_pre_dsn_gate(
        provenance_path=fixture["provenance_path"],
        provenance_keyring_path=fixture["provenance_keyring_path"],
        composition_path=fixture["composition_path"],
        final_oci_layout_path=fixture["final_oci_path"],
        composition_replay=fixture["composition_replay"],
        release_path=fixture["release_path"],
        release_keyring_path=fixture["release_keyring_path"],
        expected_provenance_keyring_sha256=fixture["provenance_keyring_hash"],
        expected_release_keyring_sha256=fixture["release_keyring_hash"],
        expected_source_commit_sha=SOURCE_COMMIT,
        expected_image_digest=fixture["expected_image_digest"],
        output_path=(tmp_path / "pre-dsn-receipt.json").resolve(),
        now=NOW,
    )


def test_round_trip_stops_before_dsn_and_has_no_authority(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    receipt = _run_gate(tmp_path, fixture)

    assert receipt["status"] == subject.RECEIPT_STATUS
    assert receipt["exact_registry_repo_digest_bound"] is True
    assert receipt["composition_attestation_runtime_repo_digest_verified"] is True
    assert (
        receipt["final_oci_layout_archive_sha256"]
        == fixture["provenance"]["final_oci_layout_archive_sha256"]
    )
    assert (
        receipt["registry_push_receipt_sha256"]
        == fixture["provenance"]["registry"]["push_receipt_sha256"]
    )
    assert receipt["release_consumed"] is False
    assert receipt["query_child_implemented"] is False
    assert receipt["dsn_read"] is False
    assert receipt["network_attempted"] is False
    assert receipt["production_query_attempted"] is False
    assert receipt["authority_granted"] is False
    assert receipt["database_mutations"] == 0
    assert receipt["orders_sent"] == 0
    output = tmp_path / "pre-dsn-receipt.json"
    assert output.stat().st_mode & 0o777 == 0o600


def test_gate_rejects_final_oci_archive_drift(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    fixture["final_oci_path"].write_bytes(b"different OCI archive")

    with pytest.raises(
        subject.QueryV5ReleaseError,
        match="composition exact replay failed",
    ):
        _run_gate(tmp_path, fixture)
    assert not (tmp_path / "pre-dsn-receipt.json").exists()


def test_provenance_rejects_valid_oci_content_identity_splice(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    composition = copy.deepcopy(fixture["composition"])
    composition["image_id"] = "sha256:" + "f" * 64
    final_oci = subject.load_verified_final_oci(fixture["final_oci_path"])
    payload = copy.deepcopy(fixture["provenance"])
    payload["composition_attestation_raw_sha256"] = _sha(_json_bytes(composition))
    payload["composition_attestation_canonical_sha256"] = _sha(
        subject.canonical_json(composition)
    )
    payload["image_id"] = composition["image_id"]
    payload["build"]["output_image_id"] = composition["image_id"]
    with pytest.raises(
        subject.QueryV5ReleaseError,
        match="final OCI config digest binding mismatch",
    ):
        subject.validate_provenance_semantics(
            payload,
            _json_bytes(composition),
            composition,
            final_oci,
            expected_source_commit_sha=SOURCE_COMMIT,
            expected_image_digest=fixture["expected_image_digest"],
            now=NOW,
        )


def test_signer_rejects_schema_valid_fake_composition_with_matching_oci(
    tmp_path: Path,
) -> None:
    exact = _exact_composition_artifacts(tmp_path)
    fake = copy.deepcopy(exact["composition"])
    fake["source_manifest_raw_sha256"] = "f" * 64
    final_raw = exact["oci"].read_bytes()
    final_oci = subject.load_verified_final_oci(exact["oci"])
    draft = _provenance_draft(fake, final_raw)
    key = Ed25519PrivateKey.generate()
    keyring = _keyring(
        key,
        schema_version=subject.PROVENANCE_KEYRING_VERSION,
        purpose=subject.PROVENANCE_KEY_PURPOSE,
        key_id="query-v5-provenance-key-1",
    )

    with pytest.raises(
        subject.QueryV5ReleaseError,
        match="supplied composition does not match exact #227 content replay",
    ):
        signer.sign_provenance(
            draft,
            keyring,
            _json_bytes(fake),
            fake,
            final_oci,
            exact["replay"],
            key,
            expected_keyring_sha256=_sha(subject.canonical_json(keyring)),
            expected_source_commit_sha=SOURCE_COMMIT,
            expected_image_digest=fake["image_digest"],
            now=NOW,
        )


def test_gate_rejects_composition_splice(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    spliced = copy.deepcopy(fixture["composition"])
    spliced["source_manifest_raw_sha256"] = "f" * 64
    fixture["composition_path"].write_bytes(_json_bytes(spliced))

    with pytest.raises(
        subject.QueryV5ReleaseError,
        match="supplied composition does not match exact #227 content replay",
    ):
        _run_gate(tmp_path, fixture)


def test_provenance_permission_floor_is_strict(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    draft = copy.deepcopy(fixture["provenance"])
    draft["network_authorized"] = True
    with pytest.raises(subject.QueryV5ReleaseError):
        subject.validate_provenance_semantics(
            draft,
            _json_bytes(fixture["composition"]),
            fixture["composition"],
            subject.load_verified_final_oci(fixture["final_oci_path"]),
            expected_source_commit_sha=SOURCE_COMMIT,
            expected_image_digest=fixture["expected_image_digest"],
            now=NOW,
        )


def test_release_rejects_v4_downgrade_and_expiry(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    downgraded = copy.deepcopy(fixture["release"])
    downgraded["schema_version"] = "commodity_c_fast_t1_one_shot_query_release_v4"
    fixture["release_path"].write_bytes(_json_bytes(downgraded))
    with pytest.raises(subject.QueryV5ReleaseError):
        _run_gate(tmp_path, fixture)

    fixture = _fixture(tmp_path / "expiry")
    with pytest.raises(
        subject.QueryV5ReleaseError, match="release time window is inactive"
    ):
        subject.run_pre_dsn_gate(
            provenance_path=fixture["provenance_path"],
            provenance_keyring_path=fixture["provenance_keyring_path"],
            composition_path=fixture["composition_path"],
            final_oci_layout_path=fixture["final_oci_path"],
            composition_replay=fixture["composition_replay"],
            release_path=fixture["release_path"],
            release_keyring_path=fixture["release_keyring_path"],
            expected_provenance_keyring_sha256=fixture["provenance_keyring_hash"],
            expected_release_keyring_sha256=fixture["release_keyring_hash"],
            expected_source_commit_sha=SOURCE_COMMIT,
            expected_image_digest=fixture["expected_image_digest"],
            output_path=(tmp_path / "expired.json").resolve(),
            now=datetime(2026, 8, 1, 12, 6, tzinfo=timezone.utc),
        )


def test_release_ttl_is_measured_from_issuance(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    stale = copy.deepcopy(fixture["release"])
    stale["issued_at"] = "2026-08-01T11:00:00+00:00"

    with pytest.raises(
        subject.QueryV5ReleaseError,
        match="release TTL exceeds ten minutes",
    ):
        subject.validate_release_semantics(
            stale,
            fixture["verified_provenance"],
            now=NOW,
        )


def test_release_cannot_predate_signed_provenance(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    predating = copy.deepcopy(fixture["release"])
    predating["issued_at"] = "2026-08-01T10:31:00+00:00"
    predating["not_before"] = "2026-08-01T10:31:00+00:00"
    predating["expires_at"] = "2026-08-01T10:40:00+00:00"

    with pytest.raises(
        subject.QueryV5ReleaseError,
        match="release predates its signed provenance",
    ):
        subject.validate_release_semantics(
            predating,
            fixture["verified_provenance"],
            now=datetime(2026, 8, 1, 10, 33, tzinfo=timezone.utc),
        )


def test_gate_revalidates_release_immediately_before_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path)
    original = subject.validate_release_semantics
    calls = 0

    def expire_on_final_check(
        payload: dict[str, Any],
        provenance: subject.VerifiedProvenance,
        *,
        now: datetime | None = None,
    ) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise subject.QueryV5ReleaseError("release expired before receipt write")
        original(payload, provenance, now=now)

    monkeypatch.setattr(subject, "validate_release_semantics", expire_on_final_check)
    with pytest.raises(
        subject.QueryV5ReleaseError,
        match="release expired before receipt write",
    ):
        _run_gate(tmp_path, fixture)

    assert calls == 2
    assert not (tmp_path / "pre-dsn-receipt.json").exists()


def test_release_and_provenance_keys_must_be_distinct(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    reused_keyring = _keyring(
        fixture["provenance_key"],
        schema_version="commodity_c_fast_t1_query_v5_trusted_keys_v1",
        purpose=subject.RELEASE_KEY_PURPOSE,
        key_id="query-v5-release-key-1",
    )
    reused_hash = _sha(subject.canonical_json(reused_keyring))

    with pytest.raises(
        subject.QueryV5ReleaseError,
        match="provenance and release key domains overlap",
    ):
        signer.sign_release(
            _release_draft(),
            reused_keyring,
            fixture["verified_provenance"],
            fixture["provenance_materials"],
            fixture["provenance_key"],
            expected_keyring_sha256=reused_hash,
            now=NOW,
        )


def test_pre_dsn_receipt_is_create_only(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    _run_gate(tmp_path, fixture)

    with pytest.raises(FileExistsError):
        _run_gate(tmp_path, fixture)


def test_gate_source_has_no_dsn_query_or_network_client() -> None:
    source = subject.VERIFIER_PATH.read_text(encoding="utf-8")
    forbidden = (
        "psycopg",
        "requests",
        "socket",
        "urllib",
        "read_dsn",
        "execute_sql",
    )
    assert all(token not in source for token in forbidden)


def test_operator_templates_are_unsigned_pending_and_fail_closed() -> None:
    provenance = subject.parse_json_bytes(
        (
            ROOT / "docs/operations/"
            "c-fast-t1-query-v5-build-registry-provenance-v1.template.json"
        ).read_bytes(),
        "query-v5 provenance template",
    )
    release = subject.parse_json_bytes(
        (
            ROOT / "docs/operations/c-fast-t1-query-v5-release-v5.template.json"
        ).read_bytes(),
        "query-v5 release template",
    )

    assert "signature" not in provenance
    assert "signature" not in release
    assert subject._contains_pending(provenance)
    assert subject._contains_pending(release)
    assert all(provenance[field] is False for field in subject.PROVENANCE_FALSE_FIELDS)
    assert all(release[field] is True for field in subject.RELEASE_TRUE_FIELDS)
    assert all(release[field] is False for field in subject.RELEASE_FALSE_FIELDS)
    with pytest.raises(subject.QueryV5ReleaseError):
        subject._validate_schema(
            provenance,
            subject.PROVENANCE_SCHEMA_PATH,
            "query-v5 provenance template",
        )
    with pytest.raises(subject.QueryV5ReleaseError):
        subject._validate_schema(
            release,
            subject.RELEASE_SCHEMA_PATH,
            "query-v5 release template",
        )
