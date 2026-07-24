#!/usr/bin/env python3
"""Offline fail-closed validation for the C_FAST T1 packaging-only artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any


SCHEMA_VERSION = "commodity_c_fast_t1_runner_packaging_validation_v1"
MAX_INPUT_BYTES = 512 * 1024
ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TEMPLATE = (
    ROOT
    / "docs/operations/c-fast-t1-readonly-override.template.yml"
)
DEFAULT_CONTAINERFILE = ROOT / "scripts/c_fast_t1/Containerfile"

PREPARATION_METADATA = {
    "schema_version": "commodity_c_fast_t1_runner_packaging_v1",
    "activation_allowed": False,
    "authority_granted": False,
    "production_query_authorized": False,
    "requires_separate_signed_one_shot_release": True,
}
QUESTDB_ENVIRONMENT = {
    "QDB_PG_READONLY_USER_ENABLED": "true",
    "QDB_PG_READONLY_USER": (
        "${C_FAST_T1_QUESTDB_READONLY_USER:"
        "?required_non_admin_principal}"
    ),
    "QDB_PG_READONLY_PASSWORD_FILE": (
        "/run/secrets/c_fast_t1_questdb_readonly_password"
    ),
}
QUESTDB_SECRET_MOUNT = [
    {
        "source": "c_fast_t1_questdb_readonly_password",
        "target": "c_fast_t1_questdb_readonly_password",
        "mode": 0o400,
    }
]
RUNNER_ENVIRONMENT = {
    "C_FAST_T1_PACKAGING_ONLY": "true",
    "C_FAST_T1_AUTHORITY_GRANTED": "false",
    "C_FAST_T1_PRODUCTION_QUERY_AUTHORIZED": "false",
}
RUNNER_REQUIRED = {
    "profiles": ["manual-c-fast-t1-preparation-only"],
    "image": "${C_FAST_T1_AUDIT_IMAGE:?required_immutable_digest}",
    "entrypoint": ["/bin/false"],
    "network_mode": "none",
    "read_only": True,
    "user": "65532:65532",
    "cap_drop": ["ALL"],
    "security_opt": ["no-new-privileges:true"],
    "pids_limit": 64,
    "mem_limit": "1g",
    "cpus": 1.0,
    "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=64m"],
    "environment": RUNNER_ENVIRONMENT,
}
TOP_LEVEL_SECRET = {
    "c_fast_t1_questdb_readonly_password": {
        "file": (
            "${C_FAST_T1_QUESTDB_READONLY_PASSWORD_FILE:"
            "?required_0600_secret_file}"
        )
    }
}
FORBIDDEN_CONFIGURATION_KEYS = {
    "QDB_PG_READONLY_PASSWORD",
    "QDB_PG_SECURITY_READONLY",
    "QDB_READONLY",
    "QUESTDB_PG_DSN",
    "QUESTDB_ILP_CONF",
}
REQUIRED_CONTAINERFILE_LINES = {
    (
        "FROM python:3.12-slim@"
        "sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de"
    ),
    'ARG SOURCE_REVISION=UNSET',
    '      io.vnpy-web-bridge.c-fast-t1.packaging-only="true" \\',
    '      io.vnpy-web-bridge.c-fast-t1.authority-granted="false"',
    '      "psycopg[binary]==3.2.3" \\',
    '      "jsonschema==4.26.0" \\',
    '      "referencing==0.37.0"',
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
    "USER 65532:65532",
    'ENTRYPOINT ["/bin/false"]',
}
FORBIDDEN_CONTAINERFILE_FRAGMENTS = (
    "COPY . ",
    "COPY ./ ",
    "ADD ",
    "curl ",
    "wget ",
    "ssh ",
    "QUESTDB_PG_DSN",
    "QDB_PG_READONLY_PASSWORD",
)


class PackagingValidationError(RuntimeError):
    """An expected packaging contract violation."""


def _reject_duplicate_object_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PackagingValidationError(
                f"duplicate JSON key is forbidden: {key}"
            )
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise PackagingValidationError(
        f"non-finite JSON value is forbidden: {value}"
    )


def _read_regular_file(path: Path, label: str) -> bytes:
    try:
        path_stat = path.lstat()
        if stat.S_ISLNK(path_stat.st_mode):
            raise PackagingValidationError(f"{label} must not be a symlink")
        if not stat.S_ISREG(path_stat.st_mode):
            raise PackagingValidationError(f"{label} must be a regular file")
        if path_stat.st_size > MAX_INPUT_BYTES:
            raise PackagingValidationError(
                f"{label} exceeds {MAX_INPUT_BYTES} byte limit"
            )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            raw = os.read(descriptor, MAX_INPUT_BYTES + 1)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        path_after = path.lstat()
    except PackagingValidationError:
        raise
    except OSError as exc:
        raise PackagingValidationError(f"cannot read {label}") from exc

    identities = {
        (
            item.st_dev,
            item.st_ino,
            item.st_size,
            stat.S_IFMT(item.st_mode),
        )
        for item in (path_stat, before, after, path_after)
    }
    if len(identities) != 1 or len(raw) != before.st_size:
        raise PackagingValidationError(
            f"{label} changed while it was being read"
        )
    if len(raw) > MAX_INPUT_BYTES:
        raise PackagingValidationError(
            f"{label} exceeds {MAX_INPUT_BYTES} byte limit"
        )
    return raw


def _load_template(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular_file(path, "override template")
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_object_keys,
            parse_constant=_reject_json_constant,
        )
    except PackagingValidationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PackagingValidationError(
            "override template must be UTF-8 JSON-compatible YAML"
        ) from exc
    if not isinstance(payload, dict):
        raise PackagingValidationError(
            "override template must contain one JSON object"
        )
    return payload, raw


def _require_exact(
    actual: Any,
    expected: Any,
    label: str,
) -> None:
    if actual != expected:
        raise PackagingValidationError(f"{label} does not match frozen value")


def _walk_keys(value: Any) -> list[str]:
    keys: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            keys.append(str(key))
            keys.extend(_walk_keys(item))
    elif isinstance(value, list):
        for item in value:
            keys.extend(_walk_keys(item))
    return keys


def _validate_template(payload: dict[str, Any]) -> dict[str, bool]:
    _require_exact(
        set(payload),
        {"x-c-fast-t1-preparation-only", "services", "secrets"},
        "override top-level fields",
    )
    _require_exact(
        payload.get("x-c-fast-t1-preparation-only"),
        PREPARATION_METADATA,
        "preparation-only metadata",
    )

    services = payload.get("services")
    if not isinstance(services, dict):
        raise PackagingValidationError("services must be an object")
    _require_exact(
        set(services),
        {"questdb", "c-fast-t1-audit-package"},
        "service names",
    )

    questdb = services.get("questdb")
    if not isinstance(questdb, dict):
        raise PackagingValidationError("questdb service must be an object")
    _require_exact(
        set(questdb),
        {"environment", "secrets"},
        "questdb override fields",
    )
    _require_exact(
        questdb.get("environment"),
        QUESTDB_ENVIRONMENT,
        "QuestDB dedicated readonly environment",
    )
    _require_exact(
        questdb.get("secrets"),
        QUESTDB_SECRET_MOUNT,
        "QuestDB readonly password secret mount",
    )

    runner = services.get("c-fast-t1-audit-package")
    if not isinstance(runner, dict):
        raise PackagingValidationError(
            "c-fast-t1-audit-package service must be an object"
        )
    _require_exact(runner, RUNNER_REQUIRED, "packaging-only runner")
    _require_exact(
        payload.get("secrets"),
        TOP_LEVEL_SECRET,
        "top-level readonly password secret",
    )

    all_keys = set(_walk_keys(payload))
    forbidden = sorted(all_keys & FORBIDDEN_CONFIGURATION_KEYS)
    if forbidden:
        raise PackagingValidationError(
            f"forbidden configuration keys present: {forbidden}"
        )
    serialized = json.dumps(payload, sort_keys=True)
    if "postgresql://" in serialized or "admin:quest" in serialized:
        raise PackagingValidationError(
            "template must not contain a DSN or default admin credential"
        )

    return {
        "preparation_metadata_frozen": True,
        "dedicated_readonly_user_file_secret": True,
        "global_readonly_forbidden": True,
        "writer_dsn_absent": True,
        "runner_non_activatable": True,
        "runner_network_disabled": True,
        "runner_hardening_frozen": True,
        "runner_image_digest_required": True,
    }


def _validate_containerfile(text: str) -> dict[str, bool]:
    lines = set(text.splitlines())
    missing = sorted(REQUIRED_CONTAINERFILE_LINES - lines)
    if missing:
        raise PackagingValidationError(
            f"Containerfile missing frozen lines: {missing}"
        )
    for fragment in FORBIDDEN_CONTAINERFILE_FRAGMENTS:
        if fragment in text:
            raise PackagingValidationError(
                f"Containerfile contains forbidden fragment: {fragment.strip()}"
            )
    if text.count("ENTRYPOINT") != 1:
        raise PackagingValidationError(
            "Containerfile must contain exactly one ENTRYPOINT"
        )
    copy_sources = [
        line.split()[1]
        for line in text.splitlines()
        if line.startswith("COPY ")
    ]
    if len(copy_sources) != 5 or any(
        not (
            source == "scripts/commodity_c_fast_l1_l5_audit.py"
            or source.startswith("docs/schemas/commodity-c-fast-")
        )
        for source in copy_sources
    ):
        raise PackagingValidationError(
            "Containerfile COPY allowlist does not match the audit package"
        )
    return {
        "containerfile_base_digest_pinned": True,
        "containerfile_minimal_inputs": True,
        "containerfile_non_activatable": True,
    }


def validate_packaging(
    template_path: Path,
    containerfile_path: Path,
) -> dict[str, Any]:
    payload, template_raw = _load_template(template_path)
    containerfile_raw = _read_regular_file(
        containerfile_path,
        "Containerfile",
    )
    try:
        containerfile_text = containerfile_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PackagingValidationError(
            "Containerfile must be UTF-8"
        ) from exc

    checks = _validate_template(payload)
    checks.update(_validate_containerfile(containerfile_text))
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "PASS",
        "template_sha256": hashlib.sha256(template_raw).hexdigest(),
        "containerfile_sha256": hashlib.sha256(
            containerfile_raw
        ).hexdigest(),
        "checks": checks,
        "activation_allowed": False,
        "authority_granted": False,
        "production_queried": False,
        "database_mutations": 0,
        "orders_sent": 0,
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
        raise PackagingValidationError(
            "cannot create validation output"
        ) from exc


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Offline validation for C_FAST T1 packaging-only artifacts"
    )
    parser.add_argument(
        "--template",
        type=Path,
        default=DEFAULT_TEMPLATE,
    )
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
        report = validate_packaging(
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
    except PackagingValidationError as exc:
        print(f"packaging validation failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
