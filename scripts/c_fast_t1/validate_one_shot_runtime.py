#!/usr/bin/env python3
"""Offline validation for the C_FAST T1 one-shot runtime bundle."""

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


SCHEMA_VERSION = "commodity_c_fast_t1_one_shot_runtime_validation_v1"
MAX_INPUT_BYTES = 512 * 1024
ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TEMPLATE = (
    ROOT / "docs/operations/c-fast-t1-one-shot-runtime.template.yml"
)
DEFAULT_CONTAINERFILE = ROOT / "scripts/c_fast_t1/Containerfile.one-shot"

RUNTIME_METADATA = {
    "schema_version": "commodity_c_fast_t1_one_shot_runtime_template_v1",
    "code_only_template": True,
    "deployment_mutation_authorized": False,
    "production_query_authorized": False,
    "requires_l3_readonly_deployment_release": True,
    "requires_signed_one_shot_release": True,
}
ENTRYPOINT = [
    "python",
    "-I",
    "/opt/c-fast-t1/scripts/commodity_c_fast_t1_one_shot.py",
]
COMMAND = [
    "--release",
    "/run/c-fast-t1-input/release.json",
    "--trusted-keyring",
    "/run/c-fast-t1-input/trusted-keyring.json",
    "--manifest",
    "/run/c-fast-t1-input/manifest.json",
    "--dsn-file",
    "/run/secrets/c-fast-t1-readonly.dsn",
    "--custody-dir",
    "/var/lib/c-fast-t1-custody",
    "--source-commit-sha",
    "${C_FAST_T1_SOURCE_COMMIT_SHA:?required_exact_40_char_sha}",
    "--runtime-image-digest",
    "${C_FAST_T1_RUNTIME_IMAGE_DIGEST:?required_sha256_digest}",
]
ENVIRONMENT = {
    "C_FAST_T1_DEPLOYMENT_MUTATION_AUTHORIZED": "false",
    "C_FAST_T1_ORDER_AUTHORIZED": "false",
    "C_FAST_T1_POSITION_MUTATION_AUTHORIZED": "false",
    "C_FAST_T1_DISPATCH_AUTHORIZED": "false",
}
VOLUMES = [
    {
        "type": "bind",
        "source": (
            "${C_FAST_T1_PINS_DIR:"
            "?required_root_owned_readonly_directory}"
        ),
        "target": "/run/c-fast-t1-pins",
        "read_only": True,
    },
    {
        "type": "bind",
        "source": (
            "${C_FAST_T1_RELEASE_FILE:"
            "?required_signed_release_file}"
        ),
        "target": "/run/c-fast-t1-input/release.json",
        "read_only": True,
    },
    {
        "type": "bind",
        "source": (
            "${C_FAST_T1_TRUSTED_KEYRING_FILE:"
            "?required_uid_65532_mode_0600_file}"
        ),
        "target": "/run/c-fast-t1-input/trusted-keyring.json",
        "read_only": True,
    },
    {
        "type": "bind",
        "source": (
            "${C_FAST_T1_MANIFEST_FILE:"
            "?required_frozen_manifest_file}"
        ),
        "target": "/run/c-fast-t1-input/manifest.json",
        "read_only": True,
    },
    {
        "type": "bind",
        "source": (
            "${C_FAST_T1_READONLY_DSN_FILE:"
            "?required_uid_65532_mode_0600_file}"
        ),
        "target": "/run/secrets/c-fast-t1-readonly.dsn",
        "read_only": True,
    },
    {
        "type": "bind",
        "source": "/var/lib/c-fast-t1-custody",
        "target": "/var/lib/c-fast-t1-custody",
    },
]
RUNNER = {
    "profiles": ["manual-c-fast-t1-one-shot"],
    "image": (
        "${C_FAST_T1_RUNTIME_IMAGE_REPOSITORY:"
        "?required_repository}@"
        "${C_FAST_T1_RUNTIME_IMAGE_DIGEST:"
        "?required_sha256_digest}"
    ),
    "entrypoint": ENTRYPOINT,
    "command": COMMAND,
    "networks": ["c-fast-t1-questdb-only"],
    "read_only": True,
    "user": "65532:65532",
    "cap_drop": ["ALL"],
    "security_opt": ["no-new-privileges:true"],
    "restart": "no",
    "pids_limit": 64,
    "mem_limit": "1g",
    "cpus": 1.0,
    "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=64m"],
    "environment": ENVIRONMENT,
    "volumes": VOLUMES,
}
NETWORKS = {
    "c-fast-t1-questdb-only": {
        "external": True,
        "name": (
            "${C_FAST_T1_QUESTDB_NETWORK:"
            "?required_preapproved_isolated_network}"
        ),
    }
}

REQUIRED_CONTAINERFILE_LINES = {
    (
        "FROM python:3.12-slim@"
        "sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de"
    ),
    "ARG SOURCE_REVISION=UNSET",
    '      io.vnpy-web-bridge.c-fast-t1.one-shot-runtime="true" \\',
    '      io.vnpy-web-bridge.c-fast-t1.authority-granted="false"',
    '      "psycopg[binary]==3.2.3" \\',
    '      "cryptography==48.0.0" \\',
    '      "jsonschema==4.26.0" \\',
    '      "referencing==0.37.0"',
    (
        "COPY scripts/commodity_c_fast_t1_one_shot.py "
        "./scripts/commodity_c_fast_t1_one_shot.py"
    ),
    (
        "COPY scripts/commodity_c_fast_l1_l5_audit.py "
        "./scripts/commodity_c_fast_l1_l5_audit.py"
    ),
    "USER 65532:65532",
    (
        'ENTRYPOINT ["python", "-I", '
        '"/opt/c-fast-t1/scripts/commodity_c_fast_t1_one_shot.py"]'
    ),
}
REQUIRED_SCHEMA_SOURCES = {
    "docs/schemas/commodity-c-fast-l1-l5-audit-manifest-v2.schema.json",
    "docs/schemas/commodity-c-fast-l1-l5-audit-v1.schema.json",
    "docs/schemas/commodity-c-fast-l1-l5-audit-v2.schema.json",
    "docs/schemas/commodity-c-fast-questdb-readonly-proof-v1.schema.json",
    "docs/schemas/commodity-c-fast-t1-one-shot-release-v1.schema.json",
    "docs/schemas/commodity-c-fast-t1-consume-v1.schema.json",
    "docs/schemas/commodity-c-fast-t1-terminal-seal-v1.schema.json",
}
EXPECTED_INSTRUCTIONS = (
    (
        "FROM python:3.12-slim@"
        "sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de"
    ),
    "ARG SOURCE_REVISION=UNSET",
    (
        'LABEL org.opencontainers.image.title="vnpy-web-bridge C_FAST T1 '
        'one-shot runner" org.opencontainers.image.revision="${SOURCE_REVISION}" '
        'io.vnpy-web-bridge.c-fast-t1.one-shot-runtime="true" '
        'io.vnpy-web-bridge.c-fast-t1.authority-granted="false"'
    ),
    "ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1",
    "WORKDIR /opt/c-fast-t1",
    (
        "RUN python -m pip install --no-cache-dir --disable-pip-version-check "
        '"psycopg[binary]==3.2.3" "cryptography==48.0.0" '
        '"jsonschema==4.26.0" "referencing==0.37.0"'
    ),
    (
        "COPY scripts/commodity_c_fast_t1_one_shot.py "
        "./scripts/commodity_c_fast_t1_one_shot.py"
    ),
    (
        "COPY scripts/commodity_c_fast_l1_l5_audit.py "
        "./scripts/commodity_c_fast_l1_l5_audit.py"
    ),
    (
        "COPY docs/schemas/commodity-c-fast-l1-l5-audit-manifest-v2.schema.json "
        "./docs/schemas/commodity-c-fast-l1-l5-audit-manifest-v2.schema.json"
    ),
    (
        "COPY docs/schemas/commodity-c-fast-l1-l5-audit-v1.schema.json "
        "./docs/schemas/commodity-c-fast-l1-l5-audit-v1.schema.json"
    ),
    (
        "COPY docs/schemas/commodity-c-fast-l1-l5-audit-v2.schema.json "
        "./docs/schemas/commodity-c-fast-l1-l5-audit-v2.schema.json"
    ),
    (
        "COPY docs/schemas/commodity-c-fast-questdb-readonly-proof-v1.schema.json "
        "./docs/schemas/commodity-c-fast-questdb-readonly-proof-v1.schema.json"
    ),
    (
        "COPY docs/schemas/commodity-c-fast-t1-one-shot-release-v1.schema.json "
        "./docs/schemas/commodity-c-fast-t1-one-shot-release-v1.schema.json"
    ),
    (
        "COPY docs/schemas/commodity-c-fast-t1-consume-v1.schema.json "
        "./docs/schemas/commodity-c-fast-t1-consume-v1.schema.json"
    ),
    (
        "COPY docs/schemas/commodity-c-fast-t1-terminal-seal-v1.schema.json "
        "./docs/schemas/commodity-c-fast-t1-terminal-seal-v1.schema.json"
    ),
    (
        "RUN python -m py_compile "
        "scripts/commodity_c_fast_t1_one_shot.py "
        "scripts/commodity_c_fast_l1_l5_audit.py "
        "&& chmod -R a-w /opt/c-fast-t1"
    ),
    "USER 65532:65532",
    (
        'ENTRYPOINT ["python", "-I", '
        '"/opt/c-fast-t1/scripts/commodity_c_fast_t1_one_shot.py"]'
    ),
)
FORBIDDEN_CONTAINERFILE_FRAGMENTS = (
    "COPY . ",
    "COPY ./ ",
    "ADD ",
    "curl ",
    "wget ",
    "ssh ",
    "commodity_c_fast_t1_sign_release.py",
    "QUESTDB_PG_DSN",
    "QDB_PG_READONLY_PASSWORD",
)
FORBIDDEN_TEMPLATE_FRAGMENTS = (
    "env_file",
    "docker.sock",
    "QUESTDB_PG_DSN",
    "QDB_PG_READONLY_PASSWORD",
    "QDB_PG_SECURITY_READONLY",
    "QDB_READONLY",
    "TradeService",
    "send_order",
    "cancel_order",
    "WEB_TRADE_ENABLED",
)


class RuntimeValidationError(RuntimeError):
    """Expected one-shot runtime contract violation."""


def _reject_duplicate_object_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeValidationError(
                f"duplicate JSON key is forbidden: {key}"
            )
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise RuntimeValidationError(
        f"non-finite JSON value is forbidden: {value}"
    )


def _read_regular_file(path: Path, label: str) -> bytes:
    try:
        before_path = path.lstat()
        if stat.S_ISLNK(before_path.st_mode):
            raise RuntimeValidationError(f"{label} must not be a symlink")
        if not stat.S_ISREG(before_path.st_mode):
            raise RuntimeValidationError(f"{label} must be a regular file")
        if before_path.st_size > MAX_INPUT_BYTES:
            raise RuntimeValidationError(
                f"{label} exceeds {MAX_INPUT_BYTES} byte limit"
            )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            first = os.read(descriptor, MAX_INPUT_BYTES + 1)
            os.lseek(descriptor, 0, os.SEEK_SET)
            second = os.read(descriptor, MAX_INPUT_BYTES + 1)
            closed = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after_path = path.lstat()
    except RuntimeValidationError:
        raise
    except OSError as exc:
        raise RuntimeValidationError(f"cannot read {label}") from exc

    def identity(value: os.stat_result) -> tuple[int, ...]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_size,
            stat.S_IFMT(value.st_mode),
        )

    if (
        len(
            {
                identity(before_path),
                identity(opened),
                identity(closed),
                identity(after_path),
            }
        )
        != 1
        or first != second
        or len(first) != opened.st_size
    ):
        raise RuntimeValidationError(f"{label} changed while being read")
    if len(first) > MAX_INPUT_BYTES:
        raise RuntimeValidationError(
            f"{label} exceeds {MAX_INPUT_BYTES} byte limit"
        )
    return first


def _load_template(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular_file(path, "runtime template")
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_object_keys,
            parse_constant=_reject_json_constant,
        )
    except RuntimeValidationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeValidationError(
            "runtime template must be UTF-8 JSON-compatible YAML"
        ) from exc
    if not isinstance(payload, dict):
        raise RuntimeValidationError(
            "runtime template must contain one JSON object"
        )
    return payload, raw


def _require_exact(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        raise RuntimeValidationError(
            f"{label} does not match the frozen value"
        )


def _validate_template(
    payload: dict[str, Any],
    raw: bytes,
) -> dict[str, bool]:
    _require_exact(
        set(payload),
        {"x-c-fast-t1-one-shot-runtime", "services", "networks"},
        "runtime template top-level fields",
    )
    _require_exact(
        payload["x-c-fast-t1-one-shot-runtime"],
        RUNTIME_METADATA,
        "runtime metadata",
    )
    _require_exact(
        payload["services"],
        {"c-fast-t1-one-shot": RUNNER},
        "one-shot service",
    )
    _require_exact(payload["networks"], NETWORKS, "isolated network")
    text = raw.decode("utf-8")
    forbidden = [
        value for value in FORBIDDEN_TEMPLATE_FRAGMENTS if value in text
    ]
    if forbidden:
        raise RuntimeValidationError(
            f"runtime template contains forbidden fragments: {forbidden}"
        )
    return {
        "runtime_metadata_frozen": True,
        "signed_release_entrypoint_frozen": True,
        "non_root_read_only_runtime": True,
        "fixed_pin_input_dsn_custody_mounts": True,
        "external_network_reference_frozen": True,
        "trading_and_writer_capabilities_absent": True,
    }


def _validate_containerfile(text: str) -> dict[str, bool]:
    instructions: list[str] = []
    pending = ""
    for source_line in text.splitlines():
        stripped = source_line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            if re.match(
                r"^#\s*(syntax|escape|check)\s*=",
                stripped,
                flags=re.IGNORECASE,
            ):
                raise RuntimeValidationError(
                    "Containerfile parser directives are forbidden"
                )
            continue
        pending = f"{pending} {stripped}".strip()
        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue
        normalized = " ".join(pending.split())
        opcode, separator, remainder = normalized.partition(" ")
        if not separator:
            raise RuntimeValidationError(
                "Containerfile instruction is malformed"
            )
        instructions.append(f"{opcode.upper()} {remainder}")
        pending = ""
    if pending:
        raise RuntimeValidationError(
            "Containerfile has an unterminated continuation"
        )
    if tuple(instructions) != EXPECTED_INSTRUCTIONS:
        raise RuntimeValidationError(
            "Containerfile instruction sequence does not match frozen bundle"
        )

    lines = set(text.splitlines())
    missing = sorted(REQUIRED_CONTAINERFILE_LINES - lines)
    if missing:
        raise RuntimeValidationError(
            f"Containerfile missing frozen lines: {missing}"
        )
    forbidden = [
        value for value in FORBIDDEN_CONTAINERFILE_FRAGMENTS if value in text
    ]
    if forbidden:
        raise RuntimeValidationError(
            f"Containerfile contains forbidden fragments: {forbidden}"
        )
    if text.count("ENTRYPOINT") != 1:
        raise RuntimeValidationError(
            "Containerfile must contain exactly one ENTRYPOINT"
        )
    copy_sources = [
        line.split()[1]
        for line in text.splitlines()
        if line.startswith("COPY ")
    ]
    expected_sources = {
        "scripts/commodity_c_fast_t1_one_shot.py",
        "scripts/commodity_c_fast_l1_l5_audit.py",
        *REQUIRED_SCHEMA_SOURCES,
    }
    if len(copy_sources) != len(expected_sources) or set(
        copy_sources
    ) != expected_sources:
        raise RuntimeValidationError(
            "Containerfile COPY allowlist does not match one-shot bundle"
        )
    return {
        "containerfile_base_digest_pinned": True,
        "containerfile_dependencies_pinned": True,
        "containerfile_runtime_bundle_complete": True,
        "containerfile_signer_absent": True,
        "containerfile_entrypoint_frozen": True,
    }


def validate_runtime(
    template_path: Path,
    containerfile_path: Path,
) -> dict[str, Any]:
    payload, template_raw = _load_template(template_path)
    containerfile_raw = _read_regular_file(
        containerfile_path,
        "one-shot Containerfile",
    )
    try:
        containerfile_text = containerfile_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeValidationError(
            "one-shot Containerfile must be UTF-8"
        ) from exc
    checks = _validate_template(payload, template_raw)
    checks.update(_validate_containerfile(containerfile_text))
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "PASS",
        "template_sha256": hashlib.sha256(template_raw).hexdigest(),
        "containerfile_sha256": hashlib.sha256(
            containerfile_raw
        ).hexdigest(),
        "checks": checks,
        "deployment_mutation_authorized": False,
        "production_query_authorized": False,
        "database_mutations": 0,
        "orders_sent": 0,
        "positions_modified": 0,
        "dispatch_changed": False,
    }


def _write_create_only(path: Path, payload: dict[str, Any]) -> None:
    raw = (
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            os.write(descriptor, raw)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise RuntimeValidationError(
            "cannot create runtime validation output"
        ) from exc


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", type=Path, default=DEFAULT_TEMPLATE)
    parser.add_argument(
        "--containerfile",
        type=Path,
        default=DEFAULT_CONTAINERFILE,
    )
    parser.add_argument("--json-output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        report = validate_runtime(
            args.template.expanduser().resolve(),
            args.containerfile.expanduser().resolve(),
        )
        if args.json_output is not None:
            _write_create_only(
                args.json_output.expanduser().resolve(),
                report,
            )
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
        return 0
    except RuntimeValidationError as exc:
        print(f"runtime validation failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
