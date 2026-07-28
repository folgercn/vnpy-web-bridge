#!/usr/bin/env python3
"""Offline validation for the code-only C_FAST query-v3 runtime package."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONTAINERFILE = ROOT / "scripts/c_fast_t1/Containerfile.query-v3"
DEFAULT_TEMPLATE = (
    ROOT / "docs/operations/c-fast-t1-query-v3-runtime.template.yml"
)
MAX_INPUT_BYTES = 2 * 1024 * 1024
BASE_IMAGE = (
    "python:3.12-slim@"
    "sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de"
)
FROZEN_PATH = "/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin"
ENTRYPOINT = [
    "/usr/local/bin/python3.12",
    "-I",
    "/opt/c-fast-t1/scripts/commodity_c_fast_t1_query_v3.py",
]

RUNTIME_SOURCES = (
    "scripts/commodity_c_fast_t1_query_v3.py",
    "scripts/commodity_c_fast_t1_query_child_v3.py",
    "scripts/commodity_c_fast_t1_one_shot.py",
    "scripts/commodity_c_fast_t1_readiness_v2.py",
    "scripts/commodity_c_fast_t1_release_v2_foundation.py",
    "scripts/commodity_c_fast_readonly_deployment_outcome.py",
    "scripts/commodity_c_fast_readonly_deployment_release.py",
    "scripts/commodity_c_fast_t1_build_registry_provenance.py",
    "scripts/commodity_c_fast_l1_l5_audit.py",
    "scripts/c_fast_t1/verify_image_attestation.py",
)
SCHEMA_SOURCES = (
    "docs/schemas/commodity-c-fast-l1-l5-audit-manifest-v2.schema.json",
    "docs/schemas/commodity-c-fast-l1-l5-audit-v1.schema.json",
    "docs/schemas/commodity-c-fast-l1-l5-audit-v2.schema.json",
    "docs/schemas/commodity-c-fast-questdb-readonly-proof-v1.schema.json",
    "docs/schemas/commodity-c-fast-t1-one-shot-query-release-v3.schema.json",
    "docs/schemas/commodity-c-fast-t1-query-consume-v3.schema.json",
    "docs/schemas/commodity-c-fast-t1-query-child-started-v3.schema.json",
    "docs/schemas/commodity-c-fast-t1-query-terminal-v3.schema.json",
    "docs/schemas/commodity-c-fast-t1-query-v3-trusted-keys-v1.schema.json",
    "docs/schemas/commodity-c-fast-t1-readiness-v2.schema.json",
    "docs/schemas/commodity-c-fast-t1-external-image-evidence-v1.schema.json",
    "docs/schemas/commodity-c-fast-t1-image-attestation-v1.schema.json",
    "docs/schemas/commodity-c-fast-t1-build-registry-provenance-v1.schema.json",
    (
        "docs/schemas/"
        "commodity-c-fast-t1-build-registry-provenance-receipt-v1.schema.json"
    ),
    "docs/schemas/commodity-c-fast-readonly-deployment-release-v1.schema.json",
    "docs/schemas/commodity-c-fast-readonly-deployment-consume-v1.schema.json",
    "docs/schemas/commodity-c-fast-readonly-deployment-receipt-v1.schema.json",
    "docs/schemas/commodity-c-fast-readonly-deployment-outcome-v1.schema.json",
    "docs/schemas/commodity-c-fast-readonly-deployment-execution-v1.schema.json",
    "docs/schemas/commodity-c-fast-readonly-deployment-writer-post-v1.schema.json",
    "docs/schemas/commodity-c-fast-readonly-deployment-health-post-v1.schema.json",
    "docs/schemas/commodity-c-fast-readonly-deployment-backlog-post-v1.schema.json",
    (
        "docs/schemas/"
        "commodity-c-fast-readonly-deployment-principal-secret-post-v1.schema.json"
    ),
    "docs/schemas/commodity-c-fast-readonly-deployment-network-post-v1.schema.json",
)
EXPECTED_COPY_SOURCES = RUNTIME_SOURCES + SCHEMA_SOURCES
REQUIRED_DEPENDENCIES = (
    "psycopg[binary]==3.2.3",
    "cryptography==48.0.0",
    "jsonschema==4.26.0",
    "referencing==0.37.0",
)
FORBIDDEN_COPY_MARKERS = (
    "commodity_c_fast_t1_query_v3_sign_release.py",
    "commodity_c_fast_p0_sign_acceptance",
    "private",
    ".pem",
    ".key",
)

COMMAND_FLAGS = (
    "--query-release",
    "--trusted-keyring",
    "--manifest",
    "--dsn-file",
    "--readiness-packet",
    "--external-image-evidence",
    "--oci-layout-archive",
    "--source-root",
    "--content-attestation",
    "--provenance",
    "--provenance-keyring",
    "--t1-keyring",
    "--outcome",
    "--outcome-keyring",
    "--expected-t1-runtime-source-commit-sha",
    "--expected-t1-runtime-image-digest",
    "--expected-l3-contract-source-commit-sha",
    "--expected-outcome-contract-source-commit-assertion",
    "--expected-questdb-image-digest",
    "--release",
    "--release-keyring",
    "--consume-marker",
    "--receipt",
    "--questdb-image-attestation",
    "--readonly-principal-identity-attestation",
    "--secret-file-identity-attestation",
    "--writer-continuity-pre-evidence",
    "--writer-continuity-post-evidence",
    "--health-evidence",
    "--backlog-evidence",
    "--rollback-plan",
    "--root-pin-identity-attestation",
    "--custody-path-identity-attestation",
    "--isolated-network-attestation",
    "--deployment-plan",
    "--execution",
    "--writer-post",
    "--health-post",
    "--backlog-post",
    "--principal-secret-post",
    "--network-post",
)
PATH_PREFIX_BY_FLAG = {
    "--query-release": "/var/lib/c-fast-t1-readiness/",
    "--trusted-keyring": "/run/c-fast-t1-query-v3-input/",
    "--manifest": "/run/c-fast-t1-query-v3-input/",
    "--dsn-file": "/run/secrets/",
    "--readiness-packet": "/var/lib/c-fast-t1-readiness/",
    "--outcome": "/var/lib/c-fast-readonly-deployment-custody/",
    "--consume-marker": "/var/lib/c-fast-readonly-deployment-custody/",
    "--receipt": "/var/lib/c-fast-readonly-deployment-custody/",
}
EXPECTED_VOLUME_TARGETS = (
    "/run/c-fast-t1-readiness-v2-pins/provenance-keyring.sha256",
    "/run/c-fast-t1-readiness-v2-pins/t1-authority-keyring.sha256",
    "/run/c-fast-t1-readiness-v2-pins/query-v3-authority-keyring.sha256",
    "/run/c-fast-t1-readiness-v2-pins/l3-authority-keyring.sha256",
    "/run/c-fast-t1-readiness-v2-pins/outcome-keyring.sha256",
    "/run/c-fast-t1-readiness-v2-pins/packet-custody.path",
    "/run/c-fast-t1-query-v3-input/query-keyring.json",
    "/run/c-fast-t1-query-v3-input/manifest.json",
    "/run/c-fast-t1-query-v3-input/external-image-evidence.json",
    "/run/c-fast-t1-query-v3-input/runtime.oci.tar",
    "/run/c-fast-t1-query-v3-input/content-attestation.json",
    "/run/c-fast-t1-query-v3-input/provenance.signed.json",
    "/run/c-fast-t1-query-v3-input/provenance-keyring.json",
    "/run/c-fast-t1-query-v3-input/t1-keyring.json",
    "/run/c-fast-t1-query-v3-input/outcome-keyring.json",
    "/run/c-fast-t1-query-v3-input/l3-release.signed.json",
    "/run/c-fast-t1-query-v3-input/l3-release-keyring.json",
    "/run/c-fast-t1-query-v3-input/questdb-image-attestation.json",
    "/run/c-fast-t1-query-v3-input/readonly-principal-identity.json",
    "/run/c-fast-t1-query-v3-input/secret-file-identity.json",
    "/run/c-fast-t1-query-v3-input/writer-continuity-pre.json",
    "/run/c-fast-t1-query-v3-input/writer-continuity-post-contract.json",
    "/run/c-fast-t1-query-v3-input/health-pre.json",
    "/run/c-fast-t1-query-v3-input/backlog-pre.json",
    "/run/c-fast-t1-query-v3-input/rollback-plan.json",
    "/run/c-fast-t1-query-v3-input/root-pin-identity.json",
    "/run/c-fast-t1-query-v3-input/custody-path-identity.json",
    "/run/c-fast-t1-query-v3-input/isolated-network-attestation.json",
    "/run/c-fast-t1-query-v3-input/deployment-plan.json",
    "/run/c-fast-t1-query-v3-input/deployment-execution.json",
    "/run/c-fast-t1-query-v3-input/writer-post.json",
    "/run/c-fast-t1-query-v3-input/health-post.json",
    "/run/c-fast-t1-query-v3-input/backlog-post.json",
    "/run/c-fast-t1-query-v3-input/principal-secret-post.json",
    "/run/c-fast-t1-query-v3-input/network-post.json",
    "/run/secrets/c-fast-t1-query-v3-readonly.dsn",
    "/var/lib/c-fast-readonly-deployment-custody/custody-identity.json",
    (
        "/var/lib/c-fast-readonly-deployment-custody/"
        "${C_FAST_T1_L3_CONSUME_BASENAME:?required_l3_consume_basename}"
    ),
    (
        "/var/lib/c-fast-readonly-deployment-custody/"
        "${C_FAST_T1_L3_RECEIPT_BASENAME:?required_l3_receipt_basename}"
    ),
    (
        "/var/lib/c-fast-readonly-deployment-custody/"
        "${C_FAST_T1_L3_OUTCOME_BASENAME:?required_l3_outcome_basename}"
    ),
    "/var/lib/c-fast-t1-readiness",
    (
        "/var/lib/c-fast-t1-readiness/"
        "${C_FAST_T1_READINESS_PACKET_BASENAME:"
        "?required_readiness_packet_basename}"
    ),
    (
        "/var/lib/c-fast-t1-readiness/"
        "${C_FAST_T1_QUERY_V3_RELEASE_BASENAME:"
        "?required_query_release_basename}"
    ),
)
EXPECTED_ENVIRONMENT = {
    "PATH": FROZEN_PATH,
    "PYTHONPATH": "/INVALID_POISON_MUST_BE_IGNORED_BY_PYTHON_ISOLATED_MODE",
    "C_FAST_T1_DEPLOYMENT_MUTATION_AUTHORIZED": "false",
    "C_FAST_T1_DATABASE_MUTATION_AUTHORIZED": "false",
    "C_FAST_T1_WRITE_PROBE_AUTHORIZED": "false",
    "C_FAST_T1_WEB_BRIDGE_RPC_AUTHORIZED": "false",
    "C_FAST_T1_COLLECTION_AUTHORIZED": "false",
    "C_FAST_T1_ORDER_AUTHORIZED": "false",
    "C_FAST_T1_POSITION_MUTATION_AUTHORIZED": "false",
    "C_FAST_T1_DISPATCH_AUTHORIZED": "false",
    "C_FAST_T1_TRADING_AUTHORIZED": "false",
}
EXPECTED_METADATA = {
    "template_state": "INVALID_BLOCKED_NOT_RUNNABLE_NOT_AUTHORITY",
    "schema_version": "commodity_c_fast_t1_query_v3_runtime_template_v1",
    "code_only_template": True,
    "packaging_validated_only": True,
    "image_built": False,
    "image_pushed": False,
    "deployed": False,
    "production_queried": False,
    "runtime_execution_ready": False,
    "blocking_reasons": [
        (
            "PROVENANCE_VERIFIER_REQUIRES_SIGNER_SOURCE_FOR_HASH_REVALIDATION_"
            "BUT_RUNTIME_SIGNER_COPY_IS_FORBIDDEN"
        ),
        (
            "READINESS_V2_REUSES_LEGACY_IMAGE_ATTESTATION_AND_REQUIRES_"
            "BROAD_GIT_SOURCE_ROOT"
        ),
    ],
    "requires_separate_query_v3_image_attestation": True,
    "requires_signed_query_v3_release": True,
    "requires_active_readiness_v2_pins": True,
    "authority_granted": False,
    "production_query_authorized": False,
    "collection_authorized": False,
    "dispatch_authorized": False,
    "trading_authorized": False,
}


class QueryV3PackagingError(RuntimeError):
    """Expected fail-closed packaging validation error."""


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_regular(path: Path, label: str) -> bytes:
    try:
        info = path.lstat()
    except OSError as exc:
        raise QueryV3PackagingError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise QueryV3PackagingError(f"{label} must be a regular non-symlink file")
    if info.st_size > MAX_INPUT_BYTES:
        raise QueryV3PackagingError(f"{label} is too large")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise QueryV3PackagingError(f"{label} cannot be read") from exc
    if b"\x00" in raw:
        raise QueryV3PackagingError(f"{label} contains NUL")
    return raw


def _reject_constant(value: str) -> None:
    raise QueryV3PackagingError(f"JSON constant {value!r} is forbidden")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise QueryV3PackagingError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_template(path: Path) -> tuple[bytes, dict[str, Any]]:
    raw = _read_regular(path, "query-v3 runtime template")
    try:
        payload = json.loads(
            raw,
            object_pairs_hook=_object,
            parse_constant=_reject_constant,
        )
    except QueryV3PackagingError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QueryV3PackagingError("runtime template is not strict JSON") from exc
    if not isinstance(payload, dict):
        raise QueryV3PackagingError("runtime template root must be an object")
    return raw, payload


def _copy_map(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        if not line.startswith("COPY "):
            continue
        parts = line.split()
        if len(parts) != 3:
            raise QueryV3PackagingError("COPY must use one source and one target")
        source, target = parts[1:]
        if source in result:
            raise QueryV3PackagingError("duplicate Containerfile COPY source")
        result[source] = target
    return result


def validate_containerfile(path: Path = DEFAULT_CONTAINERFILE) -> dict[str, Any]:
    raw = _read_regular(path, "query-v3 Containerfile")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise QueryV3PackagingError("Containerfile is not UTF-8") from exc
    if text.count(f"FROM {BASE_IMAGE}") != 1:
        raise QueryV3PackagingError("query-v3 base image digest drifted")
    if text.count("ENTRYPOINT") != 1 or any(
        line.upper().startswith("CMD ") for line in text.splitlines()
    ):
        raise QueryV3PackagingError(
            "query-v3 image requires one ENTRYPOINT and no CMD"
        )
    expected_entrypoint = "ENTRYPOINT " + json.dumps(
        ENTRYPOINT,
        ensure_ascii=False,
    )
    if text.count(expected_entrypoint) != 1:
        raise QueryV3PackagingError("query-v3 isolated ENTRYPOINT drifted")
    for required in (
        'io.vnpy-web-bridge.c-fast-t1.query-v3-runtime="true"',
        'io.vnpy-web-bridge.c-fast-t1.authority-granted="false"',
        (
            "> /usr/local/lib/python3.12/site-packages/"
            "c-fast-t1-query-v3-runtime.pth"
        ),
        (
            "chmod 0444 "
            "/usr/local/lib/python3.12/site-packages/"
            "c-fast-t1-query-v3-runtime.pth"
        ),
        "USER 65532:65532",
        "chmod -R a-w /opt/c-fast-t1",
    ):
        if text.count(required) != 1:
            raise QueryV3PackagingError(
                f"query-v3 Containerfile invariant drifted: {required}"
            )
    for dependency in REQUIRED_DEPENDENCIES:
        if text.count(f'"{dependency}"') != 1:
            raise QueryV3PackagingError(f"dependency pin drifted: {dependency}")
    copies = _copy_map(text)
    if tuple(copies) != EXPECTED_COPY_SOURCES:
        raise QueryV3PackagingError("query-v3 COPY allowlist/order drifted")
    for source, target in copies.items():
        if target != f"./{source}":
            raise QueryV3PackagingError("query-v3 COPY target drifted")
        if any(marker in source for marker in FORBIDDEN_COPY_MARKERS):
            raise QueryV3PackagingError("forbidden signing/secret source copied")
        source_path = ROOT / source
        info = source_path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise QueryV3PackagingError(
                f"runtime source is not regular: {source}"
            )
    for source in RUNTIME_SOURCES:
        if text.count(source) < 2:
            raise QueryV3PackagingError(
                f"runtime source is not byte-compiled: {source}"
            )
    if "docker.sock" in text or re.search(r"\b(curl|wget|ssh)\b", text):
        raise QueryV3PackagingError("runtime Containerfile adds external capability")
    if "commodity_c_fast_t1_build_registry_provenance_sign.py" in text:
        raise QueryV3PackagingError("provenance signing tool must not enter runtime")
    return {
        "containerfile_sha256": _sha256(raw),
        "copy_source_count": len(copies),
        "runtime_source_count": len(RUNTIME_SOURCES),
        "schema_source_count": len(SCHEMA_SOURCES),
        "isolated_entrypoint_verified": True,
        "fixed_system_site_path_verified": True,
        "runtime_execution_ready": False,
        "blocking_reasons": EXPECTED_METADATA["blocking_reasons"],
        "authority_granted": False,
    }


def _command_pairs(command: Any) -> list[tuple[str, str]]:
    if (
        not isinstance(command, list)
        or len(command) != 2 * len(COMMAND_FLAGS)
        or any(not isinstance(item, str) for item in command)
    ):
        raise QueryV3PackagingError("query-v3 command shape is invalid")
    pairs = list(zip(command[::2], command[1::2]))
    if tuple(flag for flag, _value in pairs) != COMMAND_FLAGS:
        raise QueryV3PackagingError("query-v3 required command flags drifted")
    return pairs


def validate_runtime_template(
    path: Path = DEFAULT_TEMPLATE,
) -> dict[str, Any]:
    raw, payload = _load_template(path)
    if set(payload) != {
        "x-c-fast-t1-query-v3-runtime",
        "services",
        "networks",
    }:
        raise QueryV3PackagingError("runtime template top-level fields drifted")
    if payload["x-c-fast-t1-query-v3-runtime"] != EXPECTED_METADATA:
        raise QueryV3PackagingError("runtime metadata/authority boundary drifted")
    services = payload["services"]
    if not isinstance(services, dict) or set(services) != {
        "c-fast-t1-query-v3"
    }:
        raise QueryV3PackagingError("runtime service identity drifted")
    service = services["c-fast-t1-query-v3"]
    required_service_fields = {
        "profiles",
        "image",
        "entrypoint",
        "command",
        "networks",
        "read_only",
        "user",
        "cap_drop",
        "security_opt",
        "restart",
        "healthcheck",
        "pids_limit",
        "mem_limit",
        "cpus",
        "tmpfs",
        "environment",
        "volumes",
    }
    if not isinstance(service, dict) or set(service) != required_service_fields:
        raise QueryV3PackagingError("runtime service fields drifted")
    if service["entrypoint"] != ENTRYPOINT:
        raise QueryV3PackagingError("runtime entrypoint does not match Containerfile")
    if service["image"] != (
        "${C_FAST_T1_QUERY_V3_IMAGE_REPOSITORY:?required_repository}"
        "@${C_FAST_T1_QUERY_V3_IMAGE_DIGEST:?required_sha256_digest}"
    ):
        raise QueryV3PackagingError("runtime image must use an exact RepoDigest")
    pairs = _command_pairs(service["command"])
    values = dict(pairs)
    for flag, prefix in PATH_PREFIX_BY_FLAG.items():
        value = values[flag]
        if not value.startswith(prefix):
            raise QueryV3PackagingError(f"{flag} escaped its fixed mount")
    if values["--source-root"] != (
        "INVALID_PENDING_QUERY_V3_RUNTIME_SOURCE_VERIFIER_REFACTOR"
    ):
        raise QueryV3PackagingError(
            "blocked template must not mount a broad git source root"
        )
    input_flags = set(COMMAND_FLAGS) - set(PATH_PREFIX_BY_FLAG) - {
        "--source-root",
        "--expected-t1-runtime-source-commit-sha",
        "--expected-t1-runtime-image-digest",
        "--expected-l3-contract-source-commit-sha",
        "--expected-outcome-contract-source-commit-assertion",
        "--expected-questdb-image-digest",
    }
    for flag in input_flags:
        if not values[flag].startswith("/run/c-fast-t1-query-v3-input/"):
            raise QueryV3PackagingError(f"{flag} escaped the readonly input bundle")
    expected_values = {
        "--expected-t1-runtime-source-commit-sha": (
            "${C_FAST_T1_QUERY_V3_SOURCE_COMMIT_SHA:"
            "?required_exact_40_char_sha}"
        ),
        "--expected-t1-runtime-image-digest": (
            "${C_FAST_T1_QUERY_V3_IMAGE_DIGEST:?required_sha256_digest}"
        ),
        "--expected-l3-contract-source-commit-sha": (
            "${C_FAST_T1_L3_CONTRACT_SOURCE_COMMIT_SHA:"
            "?required_exact_40_char_sha}"
        ),
        "--expected-outcome-contract-source-commit-assertion": (
            "${C_FAST_T1_L3_OUTCOME_SOURCE_COMMIT_SHA:"
            "?required_exact_40_char_sha}"
        ),
        "--expected-questdb-image-digest": (
            "${C_FAST_T1_QUESTDB_IMAGE_DIGEST:?required_sha256_digest}"
        ),
    }
    for flag, expected in expected_values.items():
        if values[flag] != expected:
            raise QueryV3PackagingError(f"{flag} environment binding drifted")
    fixed_service = {
        "profiles": ["manual-c-fast-t1-query-v3"],
        "networks": ["c-fast-t1-query-v3-questdb-only"],
        "read_only": True,
        "user": "65532:65532",
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "restart": "no",
        "healthcheck": {"disable": True},
        "pids_limit": 64,
        "mem_limit": "1g",
        "cpus": 1.0,
        "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=64m"],
        "environment": EXPECTED_ENVIRONMENT,
    }
    for field, expected in fixed_service.items():
        if service[field] != expected:
            raise QueryV3PackagingError(f"runtime service {field} drifted")
    volumes = service["volumes"]
    if not isinstance(volumes, list) or any(
        not isinstance(volume, dict)
        or set(volume) != {"type", "source", "target", "read_only"}
        for volume in volumes
    ):
        raise QueryV3PackagingError("runtime volume shape drifted")
    if tuple(volume["target"] for volume in volumes) != EXPECTED_VOLUME_TARGETS:
        raise QueryV3PackagingError("runtime exact-file mount targets drifted")
    source_pattern = re.compile(
        r"^\$\{C_FAST_T1_[A-Z0-9_]+:\?required_[a-z0-9_]+\}$"
    )
    sources = [volume["source"] for volume in volumes]
    if (
        len(set(sources)) != len(sources)
        or any(source_pattern.fullmatch(source) is None for source in sources)
    ):
        raise QueryV3PackagingError(
            "runtime mounts require unique fail-closed environment sources"
        )
    for volume in volumes:
        expected_read_only = volume["target"] != "/var/lib/c-fast-t1-readiness"
        if (
            volume["type"] != "bind"
            or volume["read_only"] is not expected_read_only
        ):
            raise QueryV3PackagingError(
                "only packet custody may be a writable bind mount"
            )
        if (
            volume["target"] == "/run/c-fast-t1-query-v3-input"
            or volume["source"].startswith("${C_FAST_T1_QUERY_V3_INPUT_DIR:")
        ):
            raise QueryV3PackagingError(
                "broad query-v3 input directory mounts are forbidden"
            )
    expected_networks = {
        "c-fast-t1-query-v3-questdb-only": {
            "external": True,
            "name": (
                "${C_FAST_T1_QUERY_V3_QUESTDB_NETWORK:"
                "?required_preapproved_isolated_network}"
            ),
        }
    }
    if payload["networks"] != expected_networks:
        raise QueryV3PackagingError("isolated query network drifted")
    serialized = json.dumps(payload, sort_keys=True)
    for forbidden in (
        "docker.sock",
        "network_mode",
        "privileged",
        "host_pid",
        "TradeService",
        "send_order",
    ):
        if forbidden in serialized:
            raise QueryV3PackagingError(
                f"runtime template contains forbidden capability: {forbidden}"
            )
    return {
        "runtime_template_sha256": _sha256(raw),
        "command_flag_count": len(pairs),
        "readonly_mount_count": sum(
            volume["read_only"] is True for volume in service["volumes"]
        ),
        "writable_mount_targets": [
            volume["target"]
            for volume in service["volumes"]
            if volume["read_only"] is False
        ],
        "production_query_authorized": False,
        "runtime_execution_ready": False,
        "blocking_reasons": EXPECTED_METADATA["blocking_reasons"],
        "collection_authorized": False,
        "trading_authorized": False,
    }


def validate_package(
    containerfile: Path = DEFAULT_CONTAINERFILE,
    runtime_template: Path = DEFAULT_TEMPLATE,
) -> dict[str, Any]:
    return {
        "schema_version": "commodity_c_fast_t1_query_v3_packaging_validation_v1",
        "status": "QUERY_V3_CODE_ONLY_PACKAGING_VALID_RUNTIME_BLOCKED",
        "containerfile": validate_containerfile(containerfile),
        "runtime_template": validate_runtime_template(runtime_template),
        "image_built": False,
        "image_pushed": False,
        "deployed": False,
        "production_queried": False,
        "runtime_execution_ready": False,
        "blocking_reasons": EXPECTED_METADATA["blocking_reasons"],
        "authority_granted": False,
    }


def write_report_create_only(path: Path, payload: dict[str, Any]) -> None:
    output = path.expanduser()
    parent = output.parent.resolve(strict=True)
    if output.parent != parent:
        raise QueryV3PackagingError("output parent must already be normalized")
    raw = (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(parent / output.name, flags, 0o600)
    except OSError as exc:
        raise QueryV3PackagingError("validation output create-only write failed") from exc
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--containerfile",
        type=Path,
        default=DEFAULT_CONTAINERFILE,
    )
    parser.add_argument(
        "--runtime-template",
        type=Path,
        default=DEFAULT_TEMPLATE,
    )
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        report = validate_package(args.containerfile, args.runtime_template)
        if args.output is not None:
            write_report_create_only(args.output, report)
        else:
            print(
                json.dumps(
                    report,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
    except (OSError, QueryV3PackagingError, ValueError) as exc:
        print(f"query-v3 packaging validation failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
