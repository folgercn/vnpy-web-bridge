#!/usr/bin/env python3
"""Validate the code-only C_FAST query-v5 overlay package offline."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONTAINERFILE = ROOT / "scripts/c_fast_t1/Containerfile.query-v5"
DEFAULT_TEMPLATE = ROOT / "docs/operations/c-fast-t1-query-v5-runtime.template.yml"
CONTAINERFILE_PATH = "scripts/c_fast_t1/Containerfile.query-v5"
LAUNCHER_SOURCE = "scripts/commodity_c_fast_t1_query_v5_launcher.py"
EXPECTED_COPY_SOURCES = (LAUNCHER_SOURCE,)
EXPECTED_COPY_TARGETS = {
    LAUNCHER_SOURCE: "release/scripts/commodity_c_fast_t1_query_v5_launcher.py",
}
ENTRYPOINT = [
    "/usr/local/bin/python3.12",
    "-I",
    "-S",
    "-s",
    "-E",
    "-B",
    "/opt/c-fast-query-v5/release/scripts/commodity_c_fast_t1_query_v5_launcher.py",
]
RUNTIME_LABEL = "io.vnpy-web-bridge.c-fast-t1.query-v5-runtime"
EXPECTED_CONTAINERFILE_INSTRUCTION_SHA256 = (
    "7c71961c00e41b3eb3a5dd284263aa2a637f8561050fd76161352081e3388eaa"
)
ALLOWED_INSTRUCTIONS = frozenset(
    {"ARG", "COPY", "ENTRYPOINT", "ENV", "FROM", "LABEL", "RUN", "USER", "WORKDIR"}
)
FORBIDDEN_MARKERS = (
    "dsn",
    "query_child",
    "sign_release",
    "private_key",
    "send_order",
    "tradeservice",
    "gateway",
)
EXPECTED_METADATA = {
    "schema_version": "commodity_c_fast_t1_query_v5_runtime_template_v1",
    "status": "QUERY_V5_CODE_ONLY_OVERLAY_PACKAGING_VALID_RUNTIME_BLOCKED",
    "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
    "parent_issue_number": 114,
    "issue_number": 216,
    "runtime_execution_ready": False,
    "requires_exact_query_v4_base_content_attestation": True,
    "requires_query_v5_overlay_content_attestation": True,
    "requires_query_v5_build_registry_provenance": True,
    "requires_future_query_release_v5_lifecycle": True,
    "code_only_blocked": True,
    "network_authorized": False,
    "production_query_authorized": False,
    "authority_granted": False,
}


class QueryV5PackagingError(RuntimeError):
    """The query-v5 code-only packaging contract failed closed."""


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _logical_instructions(text: str) -> tuple[str, ...]:
    instructions: list[str] = []
    current = ""
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if re.match(r"^#\s*(?:syntax|escape|check)\s*=", stripped, re.IGNORECASE):
            raise QueryV5PackagingError("Containerfile parser directives are forbidden")
        if not current and (not stripped or stripped.startswith("#")):
            continue
        current = f"{current} {stripped}".strip()
        if current.endswith("\\"):
            current = current[:-1].rstrip()
            continue
        instructions.append(re.sub(r"\s+", " ", current))
        current = ""
    if current or not instructions:
        raise QueryV5PackagingError("Containerfile instruction stream is invalid")
    return tuple(instructions)


def _normalized_source(path: str) -> str:
    parsed = PurePosixPath(path)
    if (
        not path
        or parsed.is_absolute()
        or any(part in {"", ".", ".."} for part in parsed.parts)
        or parsed.as_posix() != path
        or not path.startswith("scripts/")
        or any(marker in path.lower() for marker in FORBIDDEN_MARKERS)
    ):
        raise QueryV5PackagingError("query-v5 COPY source is invalid")
    return path


def inspect_containerfile(raw: bytes) -> tuple[str, tuple[str, ...], dict[str, str]]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise QueryV5PackagingError("query-v5 Containerfile must be UTF-8") from exc
    instructions = _logical_instructions(text)
    keywords = tuple(item.split(maxsplit=1)[0].upper() for item in instructions)
    unsupported = sorted(set(keywords) - ALLOWED_INSTRUCTIONS)
    if unsupported:
        raise QueryV5PackagingError(
            "forbidden Containerfile instruction: " + ", ".join(unsupported)
        )
    if instructions[:2] != ("ARG QUERY_V4_BASE_IMAGE", "FROM ${QUERY_V4_BASE_IMAGE}"):
        raise QueryV5PackagingError(
            "query-v5 must derive from an explicit query-v4 image reference"
        )
    if (
        keywords.count("FROM") != 1
        or keywords.count("ENTRYPOINT") != 1
        or "CMD" in keywords
    ):
        raise QueryV5PackagingError(
            "query-v5 requires one FROM, one ENTRYPOINT and no CMD"
        )
    if any(
        keyword == "RUN" and re.search(r"(^|\s)--mount(?:=|\s)", instruction)
        for keyword, instruction in zip(keywords, instructions)
    ):
        raise QueryV5PackagingError("Containerfile RUN --mount is forbidden")
    expected_entrypoint = "ENTRYPOINT " + json.dumps(ENTRYPOINT)
    if instructions.count(expected_entrypoint) != 1:
        raise QueryV5PackagingError("query-v5 isolated ENTRYPOINT drifted")
    copy_instruction = (
        "COPY scripts/commodity_c_fast_t1_query_v5_launcher.py "
        "./release/scripts/commodity_c_fast_t1_query_v5_launcher.py"
    )
    if (
        instructions.count("USER 0:0") != 1
        or instructions.count("USER 65532:65532") != 1
        or instructions.index("USER 0:0") > instructions.index(copy_instruction)
        or instructions.index("USER 65532:65532")
        > instructions.index(expected_entrypoint)
    ):
        raise QueryV5PackagingError("query-v5 build/runtime user transition drifted")
    normalized = "\n".join(instructions)
    required_fragments = (
        "ARG QUERY_V4_BASE_IMAGE",
        'io.vnpy-web-bridge.c-fast-t1.query-v4-runtime="true"',
        f'{RUNTIME_LABEL}="true"',
        'io.vnpy-web-bridge.c-fast-t1.authority-granted="false"',
        "USER 65532:65532",
        "chmod -R a-w /opt/c-fast-query-v5",
        "/run/c-fast-t1-query-v5-pins",
        "/usr/local/bin/python3.12 -I -S -s -E -B",
    )
    if any(fragment not in normalized for fragment in required_fragments):
        raise QueryV5PackagingError("query-v5 Containerfile invariant drifted")
    if any(marker in normalized.lower() for marker in FORBIDDEN_MARKERS):
        raise QueryV5PackagingError(
            "query-v5 code-only image contains authority/runtime markers"
        )
    copies: dict[str, str] = {}
    for instruction, keyword in zip(instructions, keywords):
        if keyword != "COPY":
            continue
        parts = instruction.split()
        if len(parts) != 3:
            raise QueryV5PackagingError("COPY must have one source and one target")
        source = _normalized_source(parts[1])
        target = parts[2]
        expected_target = "./" + EXPECTED_COPY_TARGETS.get(source, "")
        if target != expected_target or source in copies:
            raise QueryV5PackagingError("query-v5 COPY target or uniqueness drifted")
        copies[source] = target.removeprefix("./")
    if tuple(copies) != EXPECTED_COPY_SOURCES:
        raise QueryV5PackagingError("query-v5 COPY closure drifted")
    instruction_sha256 = _sha256(normalized.encode("utf-8"))
    if instruction_sha256 != EXPECTED_CONTAINERFILE_INSTRUCTION_SHA256:
        raise QueryV5PackagingError("query-v5 normalized instruction sequence drifted")
    return instruction_sha256, tuple(copies), copies


def _load_template(path: Path) -> dict[str, Any]:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise QueryV5PackagingError("query-v5 runtime template is invalid") from exc
    if not isinstance(payload, dict):
        raise QueryV5PackagingError("query-v5 runtime template must be an object")
    return payload


def validate_template(path: Path) -> None:
    payload = _load_template(path)
    if payload.get("x-c-fast-t1-query-v5-runtime") != EXPECTED_METADATA:
        raise QueryV5PackagingError("query-v5 runtime metadata drifted")
    services = payload.get("services")
    if not isinstance(services, dict) or set(services) != {
        "c-fast-t1-query-v5-code-only"
    }:
        raise QueryV5PackagingError("query-v5 runtime service scope drifted")
    service = services["c-fast-t1-query-v5-code-only"]
    if not isinstance(service, dict):
        raise QueryV5PackagingError("query-v5 runtime service is invalid")
    expected_image = (
        "${C_FAST_T1_QUERY_V5_IMAGE_REPOSITORY:?required_repository}"
        "@${C_FAST_T1_QUERY_V5_IMAGE_DIGEST:?required_sha256_digest}"
    )
    if (
        service.get("image") != expected_image
        or service.get("read_only") is not True
        or service.get("network_mode") != "none"
        or service.get("user") != "65532:65532"
        or service.get("entrypoint") is not None
        or service.get("environment") != {}
        or service.get("cap_drop") != ["ALL"]
        or service.get("security_opt") != ["no-new-privileges:true"]
    ):
        raise QueryV5PackagingError("query-v5 runtime isolation drifted")
    command = service.get("command")
    if command != [
        "--runtime-image-digest",
        "${C_FAST_T1_QUERY_V5_IMAGE_DIGEST:?required_sha256_digest}",
        "--verify-code-only",
    ]:
        raise QueryV5PackagingError("query-v5 code-only command drifted")
    volumes = service.get("volumes")
    if not isinstance(volumes, list) or len(volumes) != 1:
        raise QueryV5PackagingError("query-v5 runtime mount scope drifted")
    volume = volumes[0]
    if volume != {
        "type": "bind",
        "source": "${C_FAST_T1_QUERY_V5_PIN_ROOT:?required_pin_root}",
        "target": "/run/c-fast-t1-query-v5-pins",
        "read_only": True,
        "bind": {"create_host_path": False},
    }:
        raise QueryV5PackagingError("query-v5 pin-root mount drifted")
    serialized = json.dumps(payload, sort_keys=True).lower()
    if any(marker in serialized for marker in FORBIDDEN_MARKERS):
        raise QueryV5PackagingError("query-v5 template contains a forbidden capability")


def validate_package(containerfile: Path, template: Path) -> dict[str, Any]:
    try:
        container_raw = containerfile.read_bytes()
    except OSError as exc:
        raise QueryV5PackagingError("cannot read query-v5 Containerfile") from exc
    instruction_sha256, sources, _copies = inspect_containerfile(container_raw)
    validate_template(template)
    return {
        "schema_version": "commodity_c_fast_t1_query_v5_packaging_validation_v1",
        "status": "QUERY_V5_CODE_ONLY_OVERLAY_PACKAGING_VALID_RUNTIME_BLOCKED",
        "containerfile_sha256": _sha256(container_raw),
        "containerfile_instruction_sha256": instruction_sha256,
        "runtime_sources": list(sources),
        "runtime_execution_ready": False,
        "query_release_v5_implemented": False,
        "dsn_accessed": False,
        "query_executed": False,
        "code_only_blocked": True,
        "authority_granted": False,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--containerfile", type=Path, default=DEFAULT_CONTAINERFILE)
    parser.add_argument("--runtime-template", type=Path, default=DEFAULT_TEMPLATE)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        report = validate_package(args.containerfile, args.runtime_template)
    except (OSError, QueryV5PackagingError, ValueError) as exc:
        print(f"query-v5 packaging validation failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
