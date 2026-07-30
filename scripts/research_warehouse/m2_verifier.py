"""Unique public verifier that performs M2 artifact I/O before final status."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from .errors import RegistryError
from .m2_deployment_assets import verify_deployment_assets
from .m2_isolation_audit import verify_isolation_evidence_semantics
from .m2_isolation_contracts import (
    IsolationPolicy,
    load_isolation_evidence,
    load_isolation_policy,
)
from .m2_release_artifacts import verify_release_artifacts
from .m2_release_lock import hold_release_verification_lock


def _verified_artifact_paths(
    policy: IsolationPolicy,
    release_root: Path,
    success_output: Path,
) -> tuple[Path, Path]:
    try:
        frozen_release = Path(policy.payload["release_root"]).resolve(strict=True)
        frozen_runtime = Path(policy.payload["runtime_root"]).resolve(strict=True)
        actual_release = release_root.resolve(strict=True)
        actual_output = success_output.resolve(strict=True)
    except OSError as exc:
        raise RegistryError("M2 artifact path is unavailable") from exc
    if actual_release != frozen_release or not actual_output.is_relative_to(
        frozen_runtime
    ):
        raise RegistryError("M2 artifact path is outside frozen deployment roots")
    return actual_release, actual_output


def verify_m2_isolation_files(
    *,
    policy_path: Path,
    deployment_directory: Path,
    evidence_path: Path,
    expected_evidence_raw_sha256: str,
    release_root: Path,
    release_tree_manifest_path: Path,
    expected_release_tree_manifest_raw_sha256: str,
    success_output_path: Path,
    expected_success_output_raw_sha256: str,
    now: datetime,
) -> dict[str, Any]:
    policy = load_isolation_policy(policy_path)
    evidence = load_isolation_evidence(
        evidence_path,
        expected_raw_sha256=expected_evidence_raw_sha256,
    )
    actual_release, actual_output = _verified_artifact_paths(
        policy,
        release_root,
        success_output_path,
    )
    assets = verify_deployment_assets(
        deployment_directory,
        policy=policy,
    )
    lock_path = Path(policy.payload["release_lock_path"])
    with hold_release_verification_lock(lock_path) as held_lock:
        if held_lock.identity is None:
            raise RegistryError("M2 release verification lock identity is missing")
        release_artifacts = verify_release_artifacts(
            policy=policy,
            release_root=actual_release,
            manifest_path=release_tree_manifest_path,
            expected_manifest_raw_sha256=(expected_release_tree_manifest_raw_sha256),
            output_path=actual_output,
            expected_output_raw_sha256=expected_success_output_raw_sha256,
            output_owner_uid=policy.uid,
            release_lock_identity=held_lock.identity,
        )
        semantics = verify_isolation_evidence_semantics(
            evidence,
            policy=policy,
            now=now,
            release_artifacts=release_artifacts,
        )
        held_lock.revalidate()
        return {
            **semantics,
            "schema_version": "vnpy_research_m2_isolation_result_v1",
            "status": "M2_RESEARCH_ISOLATION_VERIFIED",
            "deployment_assets": assets,
            "release_lock_identity": held_lock.identity.as_dict(),
        }
