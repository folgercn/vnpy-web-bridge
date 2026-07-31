#!/usr/bin/env python3
"""Verify one query-v4 source bundle and OCI image without Git or a repo mount."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
from pathlib import Path
import sys
from types import ModuleType
from typing import Any

SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from c_fast_t1.validate_query_v4_runtime import (
    ENTRYPOINT,
    EXPECTED_CONTAINERFILE_INSTRUCTION_SHA256,
    EXPECTED_COPY_SOURCES,
)


ROOT = Path(__file__).resolve().parents[2]
VERIFIER_PATH = Path(__file__).resolve()
DELEGATE_PATH = Path(__file__).with_name(
    "verify_query_v3_image_attestation.py"
)
MANIFEST_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-t1-query-v4-source-manifest-v1.schema.json"
)
EVIDENCE_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-t1-query-v4-external-image-evidence-v1.schema.json"
)
ATTESTATION_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-t1-query-v4-image-attestation-v1.schema.json"
)
MANIFEST_ARCHIVE_PATH = "query-v4-source-manifest.json"
CONTAINERFILE_PATH = "scripts/c_fast_t1/Containerfile.query-v4"
SCHEMA_VERSION = "commodity_c_fast_t1_query_v4_image_attestation_v1"
MANIFEST_SCHEMA_VERSION = (
    "commodity_c_fast_t1_query_v4_source_manifest_v1"
)
EVIDENCE_SCHEMA_VERSION = (
    "commodity_c_fast_t1_query_v4_external_image_evidence_v1"
)
MANIFEST_ID_PREFIX = "query-v4-source-manifest-v1-"
STATUS = (
    "QUERY_V4_SOURCE_BUNDLE_AND_OCI_CONTENT_VERIFIED_"
    "NO_BUILD_OR_REGISTRY_PROVENANCE"
)
RUNTIME_LABEL = "io.vnpy-web-bridge.c-fast-t1.query-v4-runtime"
EXPECTED_LABELS = {
    "io.vnpy-web-bridge.c-fast-t1.authority-granted": "false",
    RUNTIME_LABEL: "true",
    "org.opencontainers.image.title": (
        "vnpy-web-bridge C_FAST T1 query-v4 runner"
    ),
}
RUNTIME_PTH_PATH = (
    "usr/local/lib/python3.12/site-packages/"
    "c-fast-t1-query-v4-runtime.pth"
)
ALLOWED_POST_BASE_PATHS = frozenset(
    {
        "opt",
        "run",
        "run/c-fast-t1-query-v4-input",
        "run/c-fast-t1-readiness-v3-pins",
        "run/secrets",
        "usr",
        "usr/local",
        "usr/local/bin",
        "usr/local/bin/jsonschema",
        "usr/local/lib",
        "usr/local/lib/python3.12",
        "usr/local/lib/python3.12/site-packages",
        "var",
        "var/lib",
        "var/lib/c-fast-readonly-deployment-custody",
        "var/lib/c-fast-t1-readiness",
    }
)
ALLOWED_SITE_PACKAGE_TOPLEVEL_EXTRA = frozenset(
    {"c-fast-t1-query-v4-runtime.pth"}
)
RUNTIME_SENSITIVE_PATH_MARKERS = (
    "commodity_c_fast_t1_query_v4_sign_release",
    "commodity_c_fast_t1_query_v3_sign_release",
    "commodity_c_fast_p0_sign_acceptance",
    "commodity_c_fast_t1_build_registry_provenance_sign",
    "private_key",
    "signer",
)


def _load_delegate() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "_c_fast_t1_query_v4_image_attestation_delegate",
        DELEGATE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("query-v4 image attestation delegate is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.VERIFIER_PATH = VERIFIER_PATH
    module.MANIFEST_SCHEMA_PATH = MANIFEST_SCHEMA_PATH
    module.EVIDENCE_SCHEMA_PATH = EVIDENCE_SCHEMA_PATH
    module.ATTESTATION_SCHEMA_PATH = ATTESTATION_SCHEMA_PATH
    module.MANIFEST_ARCHIVE_PATH = MANIFEST_ARCHIVE_PATH
    module.CONTAINERFILE_PATH = CONTAINERFILE_PATH
    module.SCHEMA_VERSION = SCHEMA_VERSION
    module.MANIFEST_SCHEMA_VERSION = MANIFEST_SCHEMA_VERSION
    module.EVIDENCE_SCHEMA_VERSION = EVIDENCE_SCHEMA_VERSION
    module.MANIFEST_ID_PREFIX = MANIFEST_ID_PREFIX
    module.STATUS = STATUS
    module.EXPECTED_CONTAINERFILE_INSTRUCTION_SHA256 = (
        EXPECTED_CONTAINERFILE_INSTRUCTION_SHA256
    )
    module.EXPECTED_LABELS = EXPECTED_LABELS
    module.RUNTIME_LABEL = RUNTIME_LABEL
    module.ENTRYPOINT = list(ENTRYPOINT)
    module.RUNTIME_PTH_PATH = RUNTIME_PTH_PATH
    module.ALLOWED_POST_BASE_PATHS = ALLOWED_POST_BASE_PATHS
    module.ALLOWED_SITE_PACKAGE_TOPLEVEL = (
        module.ALLOWED_SITE_PACKAGE_TOPLEVEL
        - {"c-fast-t1-query-v3-runtime.pth"}
        | ALLOWED_SITE_PACKAGE_TOPLEVEL_EXTRA
    )
    module.REQUIRED_COPY_SOURCES = frozenset(EXPECTED_COPY_SOURCES)
    module.RUNTIME_SENSITIVE_PATH_MARKERS = (
        RUNTIME_SENSITIVE_PATH_MARKERS
    )
    module.ADDITIONAL_REPORT_FIELDS = {
        "delegate_verifier_sha256": hashlib.sha256(
            DELEGATE_PATH.read_bytes()
        ).hexdigest(),
    }
    return module


_delegate = _load_delegate()
QueryV4ImageAttestationError = _delegate.QueryV3ImageAttestationError
canonical_json = _delegate.canonical_json
derive_source_facts = _delegate.derive_source_facts
derive_oci_facts = _delegate.derive_oci_facts


def verify_query_v4_image_evidence(
    evidence_path: Path,
    source_bundle_path: Path,
    oci_layout_archive_path: Path,
    expected_source_commit_sha: str,
) -> dict[str, Any]:
    """Recompute source and OCI facts under the query-v4 contract."""

    return _delegate.verify_query_v3_image_evidence(
        evidence_path,
        source_bundle_path,
        oci_layout_archive_path,
        expected_source_commit_sha,
    )


def write_create_only(path: Path, payload: dict[str, Any]) -> None:
    _delegate._write_create_only(path, payload)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--external-image-evidence", type=Path, required=True)
    parser.add_argument("--source-bundle-archive", type=Path, required=True)
    parser.add_argument("--oci-layout-archive", type=Path, required=True)
    parser.add_argument("--expected-source-commit-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        report = verify_query_v4_image_evidence(
            args.external_image_evidence,
            args.source_bundle_archive,
            args.oci_layout_archive,
            args.expected_source_commit_sha,
        )
        write_create_only(args.output, report)
    except (QueryV4ImageAttestationError, OSError, ValueError) as exc:
        print(
            f"query-v4 image attestation failed: {exc}",
            file=sys.stderr,
        )
        return 2
    print(f"status={report['status']}")
    print(f"image_digest={report['image_digest']}")
    print("git_binary_required=false")
    print("authority_granted=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
