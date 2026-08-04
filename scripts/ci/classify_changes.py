"""Classify changed paths for CI without broad, unauditable shell globs."""

from __future__ import annotations

import argparse
import fnmatch
import json
from pathlib import PurePosixPath

WORKFLOW_PREFIX = ".github/workflows/"
WINDOWS_FENCE_GLOBS = (
    "scripts/windows_rpc_*",
    "docs/schemas/windows-rpc-durable-fence-*.schema.json",
    "docs/operations/windows-rpc-durable-fence-*.md",
    "docs/architecture/windows-rpc-durable-fence-foundation-*.json",
    "backend/tests/unit/test_issue267_windows_fence_foundation_*.py",
    "backend/tests/unit/test_windows_rpc_deployment_snapshot_*.py",
    "backend/tests/unit/test_windows_rpc_durable_fence_*.py",
    "backend/tests/unit/test_windows_fence_foundation_*.py",
    "backend/tests/integration/test_windows_rpc_durable_fence_*.py",
    "backend/tests/integration/test_windows_fence_foundation_*.py",
)
WINDOWS_FENCE_PREFIXES = ("scripts/windows_fence_foundation/",)
QUERY_CLOSURE_FILES = {
    ".dockerignore",
    "scripts/c_fast_t1/Containerfile.query-v3",
    "scripts/c_fast_t1/Containerfile.query-v4",
    "scripts/c_fast_t1/Containerfile.query-v5",
    "scripts/c_fast_t1/ci_query_v5_real_oci_attestation.py",
    "scripts/c_fast_t1/create_query_v3_source_bundle.py",
    "scripts/c_fast_t1/create_query_v4_source_bundle.py",
    "scripts/c_fast_t1/create_query_v5_source_bundle.py",
    "scripts/c_fast_t1/validate_query_v3_runtime.py",
    "scripts/c_fast_t1/validate_query_v4_runtime.py",
    "scripts/c_fast_t1/validate_query_v5_runtime.py",
    "scripts/c_fast_t1/verify_image_attestation.py",
    "scripts/c_fast_t1/verify_query_v3_image_attestation.py",
    "scripts/c_fast_t1/verify_query_v4_image_attestation.py",
    "scripts/c_fast_t1/verify_query_v5_image_attestation.py",
    "scripts/commodity_c_fast_t1_query_v4.py",
    "scripts/commodity_c_fast_t1_query_child_v4.py",
    "scripts/commodity_c_fast_t1_one_shot.py",
    "scripts/commodity_c_fast_t1_readiness_v3.py",
    "scripts/commodity_c_fast_readonly_deployment_outcome.py",
    "scripts/commodity_c_fast_readonly_deployment_release.py",
    "scripts/commodity_c_fast_t1_build_registry_provenance_v2.py",
    "scripts/commodity_c_fast_l1_l5_audit_v4.py",
    "scripts/commodity_c_fast_l1_l5_audit.py",
    "scripts/commodity_c_fast_t1_query_v3.py",
    "scripts/commodity_c_fast_t1_query_child_v3.py",
    "scripts/commodity_c_fast_t1_readiness_v2.py",
    "scripts/commodity_c_fast_t1_release_v2_foundation.py",
    "scripts/commodity_c_fast_t1_build_registry_provenance.py",
    "scripts/commodity_c_fast_t1_query_v5_launcher.py",
    "scripts/commodity_c_fast_t1_query_v5_image_attestation_launcher.py",
    "docs/operations/c-fast-t1-query-v4-runtime.template.yml",
    "docs/operations/c-fast-t1-query-v5-image-attestation-pin-set.template.json",
    "docs/operations/c-fast-t1-query-v5-image-attestation-bootstrap-pin.template",
    "backend/tests/unit/test_c_fast_t1_query_v3_image_attestation.py",
    "backend/tests/unit/test_c_fast_t1_query_v4_image_attestation.py",
    "backend/tests/unit/test_c_fast_t1_query_v4_runtime_packaging.py",
    "backend/tests/unit/test_c_fast_t1_query_v5_image_attestation.py",
    "backend/tests/unit/test_c_fast_t1_query_v5_runtime_packaging.py",
    "scripts/ci/requirements-query-v5.txt",
}
QUERY_SCHEMA_NAMES = {
    "commodity-c-fast-l1-l5-audit-manifest-v2.schema.json",
    "commodity-c-fast-l1-l5-audit-v1.schema.json",
    "commodity-c-fast-l1-l5-audit-v2.schema.json",
    "commodity-c-fast-questdb-readonly-proof-v1.schema.json",
    "commodity-c-fast-t1-one-shot-query-release-v4.schema.json",
    "commodity-c-fast-t1-one-shot-query-release-v3.schema.json",
    "commodity-c-fast-t1-query-consume-v3.schema.json",
    "commodity-c-fast-t1-query-child-started-v3.schema.json",
    "commodity-c-fast-t1-query-terminal-v3.schema.json",
    "commodity-c-fast-t1-query-v3-trusted-keys-v1.schema.json",
    "commodity-c-fast-t1-query-consume-v4.schema.json",
    "commodity-c-fast-t1-query-child-started-v4.schema.json",
    "commodity-c-fast-t1-query-terminal-v4.schema.json",
    "commodity-c-fast-t1-query-v4-trusted-keys-v1.schema.json",
    "commodity-c-fast-t1-readiness-v3.schema.json",
    "commodity-c-fast-t1-readiness-v2.schema.json",
    "commodity-c-fast-t1-external-image-evidence-v1.schema.json",
    "commodity-c-fast-t1-image-attestation-v1.schema.json",
    "commodity-c-fast-t1-build-registry-provenance-v1.schema.json",
    "commodity-c-fast-t1-build-registry-provenance-receipt-v1.schema.json",
    "commodity-c-fast-t1-query-v3-source-manifest-v1.schema.json",
    "commodity-c-fast-t1-query-v3-external-image-evidence-v1.schema.json",
    "commodity-c-fast-t1-query-v3-image-attestation-v1.schema.json",
    "commodity-c-fast-t1-query-v4-source-manifest-v1.schema.json",
    "commodity-c-fast-t1-query-v4-external-image-evidence-v1.schema.json",
    "commodity-c-fast-t1-query-v4-image-attestation-v1.schema.json",
    "commodity-c-fast-t1-build-registry-provenance-v2.schema.json",
    "commodity-c-fast-t1-build-registry-provenance-receipt-v2.schema.json",
    "commodity-c-fast-readonly-deployment-release-v1.schema.json",
    "commodity-c-fast-readonly-deployment-consume-v1.schema.json",
    "commodity-c-fast-readonly-deployment-receipt-v1.schema.json",
    "commodity-c-fast-readonly-deployment-outcome-v1.schema.json",
    "commodity-c-fast-readonly-deployment-execution-v1.schema.json",
    "commodity-c-fast-readonly-deployment-writer-post-v1.schema.json",
    "commodity-c-fast-readonly-deployment-health-post-v1.schema.json",
    "commodity-c-fast-readonly-deployment-backlog-post-v1.schema.json",
    "commodity-c-fast-readonly-deployment-principal-secret-post-v1.schema.json",
    "commodity-c-fast-readonly-deployment-network-post-v1.schema.json",
    "commodity-c-fast-t1-query-v5-source-manifest-v1.schema.json",
    "commodity-c-fast-t1-query-v5-external-image-evidence-v1.schema.json",
    "commodity-c-fast-t1-query-v5-image-attestation-v1.schema.json",
    "commodity-c-fast-t1-query-v5-image-attestation-pin-set-v1.schema.json",
    "commodity-c-fast-t1-query-v5-build-registry-provenance-v1.schema.json",
}


def _is_under(path: str, prefix: str) -> bool:
    return path == prefix.rstrip("/") or path.startswith(prefix)


def _is_windows_fence_path(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in WINDOWS_FENCE_PREFIXES) or any(
        fnmatch.fnmatchcase(path, pattern) for pattern in WINDOWS_FENCE_GLOBS
    )


def classify(paths: list[str], *, force_all: bool = False) -> dict[str, bool]:
    result = {
        "backend_changed": force_all,
        "frontend_changed": force_all,
        "image_changed": force_all,
        "query_v5_changed": force_all,
        "windows_fence_changed": force_all,
    }
    for raw_path in paths:
        path = PurePosixPath(raw_path.strip()).as_posix()
        if not path or path == ".":
            continue
        if path.startswith(WORKFLOW_PREFIX):
            return {key: True for key in result}
        if _is_windows_fence_path(path):
            result["backend_changed"] = True
            result["windows_fence_changed"] = True
            # The Windows foundation has a dedicated offline gate.  Its exact
            # paths must not select the unrelated Linux production image.
            continue
        if (
            _is_under(path, "backend/")
            or _is_under(path, "shared/")
            or _is_under(path, "scripts/")
            or _is_under(path, "docs/schemas/")
            or _is_under(path, "docs/operations/")
            or path in {"requirements.txt", "backend/requirements.txt"}
            or path.startswith("scripts/tick_")
        ):
            result["backend_changed"] = True
        if _is_under(path, "frontend/") or _is_under(path, "shared/"):
            result["frontend_changed"] = True
        if (
            path
            in {
                "Dockerfile",
                ".dockerignore",
                "test_rpc_readonly.py",
                "test_rpc_trade_flow.py",
            }
            or _is_under(path, "backend/")
            or _is_under(path, "frontend/")
            or _is_under(path, "shared/")
            or _is_under(path, "scripts/")
            or _is_under(path, "docs/schemas/")
            or _is_under(path, "deployments/")
            or path
            in {
                "scripts/deploy.sh",
                "scripts/install-watchdog.sh",
                "scripts/watchdog.py",
            }
        ):
            result["image_changed"] = True
        if path in QUERY_CLOSURE_FILES or (
            path.startswith("docs/schemas/")
            and PurePosixPath(path).name in QUERY_SCHEMA_NAMES
        ):
            result["query_v5_changed"] = True
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--paths-file")
    parser.add_argument("--force-all", action="store_true")
    parser.add_argument("--github-output", action="store_true")
    args = parser.parse_args()
    paths = list(args.paths)
    if args.paths_file:
        with open(args.paths_file, encoding="utf-8") as source:
            paths.extend(line.rstrip("\n") for line in source)
    result = classify(paths, force_all=args.force_all)
    if args.github_output:
        for key, value in result.items():
            print(f"{key}={'true' if value else 'false'}")
    else:
        print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
