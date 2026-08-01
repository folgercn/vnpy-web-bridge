#!/usr/bin/env python3
"""Verify one query-v3 source bundle and OCI image without Git or a repo mount."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[2]
VERIFIER_PATH = Path(__file__).resolve()
MANIFEST_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-t1-query-v3-source-manifest-v1.schema.json"
)
EVIDENCE_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-t1-query-v3-external-image-evidence-v1.schema.json"
)
ATTESTATION_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-t1-query-v3-image-attestation-v1.schema.json"
)
MANIFEST_ARCHIVE_PATH = "query-v3-source-manifest.json"
CONTAINERFILE_PATH = "scripts/c_fast_t1/Containerfile.query-v3"
SCHEMA_VERSION = "commodity_c_fast_t1_query_v3_image_attestation_v1"
MANIFEST_SCHEMA_VERSION = "commodity_c_fast_t1_query_v3_source_manifest_v1"
MANIFEST_ID_PREFIX = "query-v3-source-manifest-v1-"
EVIDENCE_SCHEMA_VERSION = (
    "commodity_c_fast_t1_query_v3_external_image_evidence_v1"
)
STATUS = (
    "QUERY_V3_SOURCE_BUNDLE_AND_OCI_CONTENT_VERIFIED_"
    "NO_BUILD_OR_REGISTRY_PROVENANCE"
)
ADDITIONAL_REPORT_FIELDS: dict[str, Any] = {}
CANDIDATE_ID = "C_FAST_CROSS_SECTION_NEUTRAL"
BASE_IMAGE = (
    "python:3.12-slim@"
    "sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de"
)
BASE_IMAGE_DIGEST = BASE_IMAGE.split("@", 1)[1]
BASE_PLATFORM_MANIFEST_DIGEST = (
    "sha256:cab2dbf575e971934a81e4622f5aba17aa7929719bd7e31033a3a83b97fd0464"
)
BASE_ROOTFS_LAYER_DIGESTS = (
    "sha256:062e450697faa5f02a3a74eba9864ee4d79bc9cfbd65769fc6cdff2c05c6a053",
    "sha256:98db2485a0d07a8914586b02387e3813aa7e9fed79ab252898d3e96e21c717ea",
    "sha256:48347b15c85fd6dde9c5b0259f378fbaee3ce231b30a42f2f2bcc4ea0285cbc9",
    "sha256:fd079632edc0ab4e9d10c77ec348d5057a976e6fc508e93855548096dec2ae1e",
)
BASE_ROOTFS_DIFF_IDS = (
    "sha256:f2ec4de84f559f5c7be4233b589cdbdbb5507807e05621b77320edd55a1f2a0f",
    "sha256:ccbaccfc0388284959cf106031557105fad2067d6c4435937b3414ce90760167",
    "sha256:83fdf57f71f28b640f11d5072c284c81eadefc5ea538050fedcedba6149879bd",
    "sha256:b80f3ed1ee6de85c788d9ae7203207c44724eab4baac8697390ca1412954ad2f",
)
EXPECTED_CONTAINERFILE_INSTRUCTION_SHA256 = (
    "6322dbef5346afbc74deadc1bf74cd521517ad3d34da4d241eb80c3f89d21db4"
)
FROZEN_PATH = "/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin"
EXPECTED_ENVIRONMENT = {
    "PATH": FROZEN_PATH,
    "LANG": "C.UTF-8",
    "GPG_KEY": "7169605F62C751356D054A26A821E680E5FA6305",
    "PYTHON_VERSION": "3.12.13",
    "PYTHON_SHA256": (
        "c08bc65a81971c1dd5783182826503369466c7e67374d1646519adf05207b684"
    ),
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONUNBUFFERED": "1",
}
EXPECTED_LABELS = {
    "io.vnpy-web-bridge.c-fast-t1.authority-granted": "false",
    "io.vnpy-web-bridge.c-fast-t1.query-v3-runtime": "true",
    "org.opencontainers.image.title": (
        "vnpy-web-bridge C_FAST T1 query-v3 runner"
    ),
}
RUNTIME_LABEL = "io.vnpy-web-bridge.c-fast-t1.query-v3-runtime"
ENTRYPOINT = [
    "/usr/local/bin/python3.12",
    "-I",
    "/opt/c-fast-t1/scripts/commodity_c_fast_t1_query_v3.py",
]
INTERPRETER_PATH = "usr/local/bin/python3.12"
RUNTIME_PTH_PATH = (
    "usr/local/lib/python3.12/site-packages/"
    "c-fast-t1-query-v3-runtime.pth"
)
RUNTIME_PTH_CONTENT = b"/opt/c-fast-t1/scripts\n"
ALLOWED_POST_BASE_PATHS = frozenset(
    {
        "opt",
        "opt/c-fast-t1",
        "run",
        "run/c-fast-t1-query-v3-input",
        "run/c-fast-t1-readiness-v2-pins",
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
ALLOWED_POST_BASE_PREFIXES = (
    "opt/c-fast-t1/",
)
SITE_PACKAGES_PREFIX = "usr/local/lib/python3.12/site-packages/"
ALLOWED_SITE_PACKAGE_TOPLEVEL = frozenset(
    {
        "_cffi_backend.cpython-312-x86_64-linux-gnu.so",
        "attr",
        "attrs",
        "attrs-26.1.0.dist-info",
        "c-fast-t1-query-v3-runtime.pth",
        "cffi",
        "cffi-2.1.0.dist-info",
        "cryptography",
        "cryptography-48.0.0.dist-info",
        "jsonschema",
        "jsonschema-4.26.0.dist-info",
        "jsonschema_specifications",
        "jsonschema_specifications-2025.9.1.dist-info",
        "psycopg",
        "psycopg-3.2.3.dist-info",
        "psycopg_binary",
        "psycopg_binary-3.2.3.dist-info",
        "psycopg_binary.libs",
        "pycparser",
        "pycparser-3.0.dist-info",
        "referencing",
        "referencing-0.37.0.dist-info",
        "rpds",
        "rpds_py-2026.6.3.dist-info",
        "typing_extensions-4.16.0.dist-info",
        "typing_extensions.py",
    }
)
EXPECTED_DEPENDENCIES = {
    "cryptography": "48.0.0",
    "jsonschema": "4.26.0",
    "psycopg[binary]": "3.2.3",
    "referencing": "0.37.0",
}
EXPECTED_INSTALLED_DEPENDENCIES = {
    "attrs": "26.1.0",
    "cffi": "2.1.0",
    "cryptography": "48.0.0",
    "jsonschema": "4.26.0",
    "jsonschema-specifications": "2025.9.1",
    "psycopg": "3.2.3",
    "psycopg-binary": "3.2.3",
    "pycparser": "3.0",
    "referencing": "0.37.0",
    "rpds-py": "2026.6.3",
    "typing-extensions": "4.16.0",
}
REQUIRED_COPY_SOURCES = frozenset(
    {
        "scripts/commodity_c_fast_t1_query_v3.py",
        "scripts/commodity_c_fast_t1_query_child_v3.py",
        "scripts/commodity_c_fast_t1_one_shot.py",
        "scripts/commodity_c_fast_l1_l5_audit.py",
        "docs/schemas/commodity-c-fast-t1-one-shot-query-release-v3.schema.json",
        "docs/schemas/commodity-c-fast-t1-query-consume-v3.schema.json",
        "docs/schemas/commodity-c-fast-t1-query-child-started-v3.schema.json",
        "docs/schemas/commodity-c-fast-t1-query-terminal-v3.schema.json",
        "docs/schemas/commodity-c-fast-t1-query-v3-trusted-keys-v1.schema.json",
    }
)
FORBIDDEN_SOURCE_MARKERS = (
    "_sign_",
    "signer",
    "private",
    ".pem",
    ".key",
)
RUNTIME_SENSITIVE_PATH_MARKERS = (
    "commodity_c_fast_t1_query_v3_sign_release",
    "commodity_c_fast_p0_sign_acceptance",
    "commodity_c_fast_t1_build_registry_provenance_sign",
    "private_key",
    "signer",
)
PRIVATE_KEY_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
)
PRIVATE_KEY_MARKER_LITERAL_SOURCE_PATHS = frozenset(
    {
        "opt/c-fast-t1/scripts/c_fast_t1/verify_image_attestation.py",
        "opt/c-fast-t1/scripts/c_fast_t1/verify_query_v3_image_attestation.py",
    }
)
SENSITIVE_ENV_MARKERS = (
    "PASSWORD",
    "PASSWD",
    "SECRET",
    "TOKEN",
    "PRIVATE_KEY",
    "DSN",
)
ALLOWED_INSTRUCTIONS = frozenset(
    {"ARG", "COPY", "ENTRYPOINT", "ENV", "FROM", "LABEL", "RUN", "USER", "WORKDIR"}
)
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_SOURCE_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_OCI_BYTES = 256 * 1024 * 1024
MAX_LAYER_BYTES = 512 * 1024 * 1024
MAX_LAYER_FILE_BYTES = 128 * 1024 * 1024
MAX_ENTRIES = 100_000
MAX_BLOBS = 512
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
OCI_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
BLOB_RE = re.compile(r"^blobs/sha256/([0-9a-f]{64})$")
SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
OCI_INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
OCI_LAYER_MEDIA_TYPES = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
}


class QueryV3ImageAttestationError(RuntimeError):
    """Expected source-bundle, evidence, OCI or output violation."""


@dataclass(frozen=True)
class FileEntry:
    kind: str
    sha256: str | None = None
    content: bytes | None = None
    size: int = 0
    mode: int = 0
    uid: int = 0
    gid: int = 0
    link_target: str | None = None


def canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reject_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise QueryV3ImageAttestationError(
                f"duplicate JSON key is forbidden: {key}"
            )
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise QueryV3ImageAttestationError(
        f"non-finite JSON value is forbidden: {value}"
    )


def _parse_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_pairs,
            parse_constant=_reject_constant,
        )
    except QueryV3ImageAttestationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QueryV3ImageAttestationError(
            f"{label} must be one strict UTF-8 JSON object"
        ) from exc
    if not isinstance(payload, dict):
        raise QueryV3ImageAttestationError(
            f"{label} must be one strict UTF-8 JSON object"
        )
    return payload


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        stat.S_IFMT(value.st_mode),
    )


def _read_fd(descriptor: int, limit: int, label: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise QueryV3ImageAttestationError(
                f"{label} exceeds {limit} byte limit"
            )
    return b"".join(chunks)


def _read_regular(path: Path, label: str, *, limit: int) -> bytes:
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise QueryV3ImageAttestationError(
                f"{label} must be a regular non-symlink file"
            )
        if before.st_size > limit:
            raise QueryV3ImageAttestationError(
                f"{label} exceeds {limit} byte limit"
            )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            first = _read_fd(descriptor, limit, label)
            os.lseek(descriptor, 0, os.SEEK_SET)
            second = _read_fd(descriptor, limit, label)
            closed = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after = path.lstat()
    except QueryV3ImageAttestationError:
        raise
    except OSError as exc:
        raise QueryV3ImageAttestationError(f"cannot read {label}") from exc
    if (
        len({_identity(before), _identity(opened), _identity(closed), _identity(after)})
        != 1
        or first != second
        or len(first) != opened.st_size
    ):
        raise QueryV3ImageAttestationError(f"{label} changed while being read")
    return first


def _load_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular(path, label, limit=MAX_JSON_BYTES)
    return _parse_json(raw, label), raw


def _validate_schema(
    payload: dict[str, Any],
    schema_path: Path,
    label: str,
) -> None:
    schema, _raw = _load_json(schema_path, f"{label} schema")
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as exc:
        raise QueryV3ImageAttestationError(f"{label} schema is invalid") from exc
    errors = sorted(
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).iter_errors(payload),
        key=lambda item: [str(part) for part in item.absolute_path],
    )
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.absolute_path)
        raise QueryV3ImageAttestationError(
            f"{label} schema validation failed at "
            f"{location or '<root>'}: {first.message}"
        )


def _normalized_path(name: str, label: str) -> str:
    if not isinstance(name, str) or not name or "\x00" in name or "\\" in name:
        raise QueryV3ImageAttestationError(f"{label} path is invalid")
    while name.startswith("./"):
        name = name[2:]
    name = name.rstrip("/")
    if not name:
        return ""
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise QueryV3ImageAttestationError(f"{label} contains path traversal")
    normalized = "/".join(path.parts)
    if normalized != name:
        raise QueryV3ImageAttestationError(f"{label} path is not normalized")
    return normalized


def _tar_member_raw(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    label: str,
    *,
    limit: int,
) -> bytes:
    if member.size < 0 or member.size > limit:
        raise QueryV3ImageAttestationError(f"{label} is too large")
    stream = archive.extractfile(member)
    if stream is None:
        raise QueryV3ImageAttestationError(f"cannot read {label}")
    raw = stream.read(limit + 1)
    if len(raw) != member.size or len(raw) > limit:
        raise QueryV3ImageAttestationError(f"{label} size does not match tar header")
    return raw


def _canonical_source_bundle(
    members: list[tuple[str, bytes, int]],
) -> bytes:
    output = io.BytesIO()
    with tarfile.open(
        fileobj=output,
        mode="w:",
        format=tarfile.USTAR_FORMAT,
    ) as archive:
        for name, raw, mode in members:
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            member.mode = mode
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            member.mtime = 0
            member.type = tarfile.REGTYPE
            archive.addfile(member, io.BytesIO(raw))
    return output.getvalue()


def _normalize_source_path(path: str) -> str:
    if (
        not path
        or "\x00" in path
        or "\\" in path
        or SAFE_PATH_RE.fullmatch(path) is None
    ):
        raise QueryV3ImageAttestationError("Containerfile COPY source path is invalid")
    parsed = PurePosixPath(path)
    if parsed.is_absolute() or any(part in {"", ".", ".."} for part in parsed.parts):
        raise QueryV3ImageAttestationError(
            "Containerfile COPY source path is not normalized"
        )
    normalized = "/".join(parsed.parts)
    if normalized != path or not (
        path.startswith("scripts/") or path.startswith("docs/schemas/")
    ):
        raise QueryV3ImageAttestationError(
            "Containerfile COPY source is outside fixed roots"
        )
    lowered = path.lower()
    if any(marker in lowered for marker in FORBIDDEN_SOURCE_MARKERS):
        raise QueryV3ImageAttestationError(
            "Containerfile copies a signer or sensitive source"
        )
    return normalized


def _logical_instructions(text: str) -> tuple[str, ...]:
    instructions: list[str] = []
    current = ""
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if re.match(
            r"^#\s*(?:syntax|escape|check)\s*=",
            stripped,
            flags=re.IGNORECASE,
        ):
            raise QueryV3ImageAttestationError(
                "Containerfile parser directives are forbidden"
            )
        if not current and (not stripped or stripped.startswith("#")):
            continue
        current = f"{current} {stripped}".strip()
        if current.endswith("\\"):
            current = current[:-1].rstrip()
            continue
        instructions.append(re.sub(r"\s+", " ", current))
        current = ""
    if current:
        raise QueryV3ImageAttestationError(
            "Containerfile has an unterminated continuation"
        )
    return tuple(instructions)


def inspect_containerfile(raw: bytes) -> tuple[str, dict[str, str]]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise QueryV3ImageAttestationError(
            "query-v3 Containerfile must be UTF-8"
        ) from exc
    instructions = _logical_instructions(text)
    if not instructions:
        raise QueryV3ImageAttestationError("query-v3 Containerfile is empty")
    keywords = tuple(item.split(maxsplit=1)[0].upper() for item in instructions)
    unsupported = sorted(set(keywords) - ALLOWED_INSTRUCTIONS)
    if unsupported:
        raise QueryV3ImageAttestationError(
            "Containerfile instruction is forbidden: " + ", ".join(unsupported)
        )
    if keywords.count("FROM") != 1 or instructions[0] != f"FROM {BASE_IMAGE}":
        raise QueryV3ImageAttestationError("query-v3 base image contract drifted")
    if keywords.count("ENTRYPOINT") != 1 or "CMD" in keywords:
        raise QueryV3ImageAttestationError(
            "query-v3 requires one ENTRYPOINT and no CMD"
        )
    if any(
        keyword == "RUN"
        and re.search(r"(^|\s)--mount(?:=|\s)", instruction) is not None
        for keyword, instruction in zip(keywords, instructions)
    ):
        raise QueryV3ImageAttestationError("Containerfile RUN --mount is forbidden")
    expected_entrypoint = "ENTRYPOINT " + json.dumps(
        ENTRYPOINT,
        ensure_ascii=False,
    )
    if instructions.count(expected_entrypoint) != 1:
        raise QueryV3ImageAttestationError("query-v3 isolated ENTRYPOINT drifted")
    normalized = "\n".join(instructions)
    required_fragments = (
        f'{RUNTIME_LABEL}="{EXPECTED_LABELS[RUNTIME_LABEL]}"',
        'io.vnpy-web-bridge.c-fast-t1.authority-granted="false"',
        "USER 65532:65532",
        "chmod -R a-w /opt/c-fast-t1",
        "psycopg[binary]==3.2.3",
        "cryptography==48.0.0",
        "jsonschema==4.26.0",
        "referencing==0.37.0",
    )
    if any(normalized.count(fragment) != 1 for fragment in required_fragments):
        raise QueryV3ImageAttestationError(
            "query-v3 Containerfile invariant drifted"
        )
    copies: dict[str, str] = {}
    for instruction, keyword in zip(instructions, keywords):
        if keyword != "COPY":
            continue
        parts = instruction.split()
        if len(parts) != 3:
            raise QueryV3ImageAttestationError(
                "COPY must use exactly one source and one target"
            )
        source = _normalize_source_path(parts[1])
        if source in copies or parts[2] != f"./{source}":
            raise QueryV3ImageAttestationError(
                "query-v3 COPY source/target contract drifted"
            )
        copies[source] = parts[2]
    if not REQUIRED_COPY_SOURCES.issubset(copies):
        raise QueryV3ImageAttestationError(
            "query-v3 required COPY closure is incomplete"
        )
    instruction_sha256 = _sha256(normalized.encode("utf-8"))
    if instruction_sha256 != EXPECTED_CONTAINERFILE_INSTRUCTION_SHA256:
        raise QueryV3ImageAttestationError(
            "query-v3 Containerfile normalized instruction sequence drifted"
        )
    return instruction_sha256, copies


def _manifest_identity(manifest: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in manifest.items() if key != "manifest_id"}


def derive_source_facts(
    bundle_path: Path,
    expected_source_commit_sha: str,
) -> dict[str, Any]:
    if COMMIT_RE.fullmatch(expected_source_commit_sha) is None:
        raise QueryV3ImageAttestationError("expected source commit is invalid")
    bundle_raw = _read_regular(
        bundle_path,
        "query-v3 source bundle archive",
        limit=MAX_SOURCE_BUNDLE_BYTES,
    )
    members: list[tuple[str, bytes, int]] = []
    seen: set[str] = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(bundle_raw), mode="r:") as archive:
            for member in archive:
                name = _normalized_path(member.name, "source bundle")
                if not name or name in seen:
                    raise QueryV3ImageAttestationError(
                        "source bundle contains an empty or duplicate path"
                    )
                seen.add(name)
                if (
                    not member.isreg()
                    or member.pax_headers
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname != ""
                    or member.gname != ""
                    or member.mtime != 0
                    or member.mode not in {0o444, 0o644, 0o755}
                ):
                    raise QueryV3ImageAttestationError(
                        f"source bundle entry metadata is not canonical: {name}"
                    )
                members.append(
                    (
                        name,
                        _tar_member_raw(
                            archive,
                            member,
                            f"source bundle:{name}",
                            limit=MAX_JSON_BYTES,
                        ),
                        member.mode,
                    )
                )
    except QueryV3ImageAttestationError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise QueryV3ImageAttestationError(
            "source bundle must be one valid plain tar archive"
        ) from exc
    if not members or members[0][0] != MANIFEST_ARCHIVE_PATH:
        raise QueryV3ImageAttestationError(
            "source bundle manifest must be the first archive entry"
        )
    manifest_raw = members[0][1]
    if members[0][2] != 0o444:
        raise QueryV3ImageAttestationError("source manifest archive mode drifted")
    manifest = _parse_json(manifest_raw, "query-v3 source manifest")
    _validate_schema(
        manifest,
        MANIFEST_SCHEMA_PATH,
        "query-v3 source manifest",
    )
    if (
        manifest["schema_version"] != MANIFEST_SCHEMA_VERSION
        or manifest["source_commit_sha"] != expected_source_commit_sha
        or manifest["containerfile_path"] != CONTAINERFILE_PATH
    ):
        raise QueryV3ImageAttestationError(
            "source manifest namespace does not match expected query-v3 source"
        )
    if manifest_raw != canonical_json(manifest):
        raise QueryV3ImageAttestationError(
            "source manifest bytes are not canonical JSON"
        )
    expected_manifest_id = (
        MANIFEST_ID_PREFIX
        + _sha256(canonical_json(_manifest_identity(manifest)))
    )
    if manifest["manifest_id"] != expected_manifest_id:
        raise QueryV3ImageAttestationError("source manifest identity is invalid")
    entries = manifest["entries"]
    paths = [entry["path"] for entry in entries]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise QueryV3ImageAttestationError(
            "source manifest entries must be unique and sorted"
        )
    expected_archive_order = [MANIFEST_ARCHIVE_PATH, *paths]
    if [name for name, _raw, _mode in members] != expected_archive_order:
        raise QueryV3ImageAttestationError(
            "source bundle paths do not match exact manifest order"
        )
    if _canonical_source_bundle(members) != bundle_raw:
        raise QueryV3ImageAttestationError(
            "source bundle raw bytes are not the canonical USTAR encoding"
        )
    by_name = {name: (raw, mode) for name, raw, mode in members[1:]}
    for entry in entries:
        raw, mode = by_name[entry["path"]]
        if (
            len(raw) != entry["size"]
            or _sha256(raw) != entry["sha256"]
            or mode != entry["mode"]
        ):
            raise QueryV3ImageAttestationError(
                f"source bundle entry does not match manifest: {entry['path']}"
            )
    try:
        containerfile_raw = by_name[CONTAINERFILE_PATH][0]
    except KeyError as exc:
        raise QueryV3ImageAttestationError(
            "source bundle lacks query-v3 Containerfile"
        ) from exc
    instruction_sha256, copies = inspect_containerfile(containerfile_raw)
    expected_paths = sorted({CONTAINERFILE_PATH, *copies})
    if (
        paths != expected_paths
        or manifest["containerfile_instruction_sha256"] != instruction_sha256
    ):
        raise QueryV3ImageAttestationError(
            "source manifest does not match exact Containerfile COPY closure"
        )
    source_bundle = {
        f"/opt/c-fast-t1/{copies[source].removeprefix('./')}": _sha256(
            by_name[source][0]
        )
        for source in copies
    }
    return {
        "bundle_raw": bundle_raw,
        "manifest": manifest,
        "manifest_raw": manifest_raw,
        "containerfile_sha256": _sha256(containerfile_raw),
        "containerfile_instruction_sha256": instruction_sha256,
        "base_image_digest": BASE_IMAGE_DIGEST,
        "runtime_bundle": source_bundle,
    }


def _require_fields(
    payload: dict[str, Any],
    expected: set[str],
    label: str,
) -> None:
    if set(payload) != expected:
        raise QueryV3ImageAttestationError(f"{label} fields are invalid")


def _parse_oci_archive(raw: bytes) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    seen: set[str] = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            for member in archive:
                name = _normalized_path(member.name, "OCI layout archive")
                if name in seen:
                    raise QueryV3ImageAttestationError(
                        f"OCI layout archive has duplicate path: {name}"
                    )
                seen.add(name)
                if member.isdir():
                    continue
                if not member.isreg() or not name:
                    raise QueryV3ImageAttestationError(
                        "OCI layout archive contains a link or special file"
                    )
                if name not in {"oci-layout", "index.json"}:
                    match = BLOB_RE.fullmatch(name)
                    if match is None or len(files) >= MAX_BLOBS + 2:
                        raise QueryV3ImageAttestationError(
                            f"OCI layout archive path is not allowed: {name}"
                        )
                files[name] = _tar_member_raw(
                    archive,
                    member,
                    name,
                    limit=(
                        MAX_JSON_BYTES
                        if name in {"oci-layout", "index.json"}
                        else MAX_OCI_BYTES
                    ),
                )
    except QueryV3ImageAttestationError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise QueryV3ImageAttestationError(
            "OCI layout archive must be one valid plain tar"
        ) from exc
    if set(files) < {"oci-layout", "index.json"}:
        raise QueryV3ImageAttestationError("OCI layout metadata is incomplete")
    if _parse_json(files["oci-layout"], "oci-layout") != {
        "imageLayoutVersion": "1.0.0"
    }:
        raise QueryV3ImageAttestationError("OCI image layout version is invalid")
    for name, content in files.items():
        match = BLOB_RE.fullmatch(name)
        if match is not None and _sha256(content) != match[1]:
            raise QueryV3ImageAttestationError(
                f"OCI blob path digest mismatch: {name}"
            )
    return files


def _descriptor(
    payload: Any,
    label: str,
    media_types: set[str],
    *,
    platform: bool = False,
) -> tuple[str, int, str]:
    if not isinstance(payload, dict):
        raise QueryV3ImageAttestationError(f"{label} must be an object")
    fields = {"mediaType", "digest", "size"}
    if platform:
        fields.add("platform")
    _require_fields(payload, fields, label)
    digest, size, media_type = (
        payload["digest"],
        payload["size"],
        payload["mediaType"],
    )
    if (
        media_type not in media_types
        or not isinstance(digest, str)
        or OCI_DIGEST_RE.fullmatch(digest) is None
        or type(size) is not int
        or size < 0
        or size > MAX_OCI_BYTES
    ):
        raise QueryV3ImageAttestationError(f"{label} descriptor is invalid")
    if platform and payload["platform"] != {
        "architecture": "amd64",
        "os": "linux",
    }:
        raise QueryV3ImageAttestationError(f"{label} platform is invalid")
    return digest, size, media_type


def _blob(
    files: dict[str, bytes],
    digest: str,
    size: int,
    label: str,
) -> bytes:
    path = "blobs/sha256/" + digest.removeprefix("sha256:")
    raw = files.get(path)
    if (
        raw is None
        or len(raw) != size
        or "sha256:" + _sha256(raw) != digest
    ):
        raise QueryV3ImageAttestationError(f"{label} descriptor does not match blob")
    return raw


def _layer_raw(raw: bytes, media_type: str, label: str) -> bytes:
    if media_type == "application/vnd.oci.image.layer.v1.tar":
        if len(raw) > MAX_LAYER_BYTES:
            raise QueryV3ImageAttestationError(f"{label} is too large")
        return raw
    try:
        stream = gzip.GzipFile(fileobj=io.BytesIO(raw), mode="rb")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_LAYER_BYTES:
                raise QueryV3ImageAttestationError(
                    f"{label} exceeds decompression limit"
                )
            chunks.append(chunk)
        stream.close()
        return b"".join(chunks)
    except QueryV3ImageAttestationError:
        raise
    except (EOFError, OSError) as exc:
        raise QueryV3ImageAttestationError(f"{label} gzip stream is invalid") from exc


def _remove_path(
    filesystem: dict[str, FileEntry],
    directories: dict[str, FileEntry],
    target: str,
) -> None:
    prefix = target + "/"
    for mapping in (filesystem, directories):
        for path in list(mapping):
            if path == target or path.startswith(prefix):
                mapping.pop(path, None)


def _resolve_link(path: str, target: str, *, symlink: bool) -> str:
    if not target or "\x00" in target or "\\" in target:
        raise QueryV3ImageAttestationError("OCI layer link target is invalid")
    resolved = (
        list(PurePosixPath(path).parent.parts)
        if symlink and not target.startswith("/")
        else []
    )
    if resolved == ["."]:
        resolved = []
    for part in target.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if not resolved:
                raise QueryV3ImageAttestationError(
                    "OCI layer link target contains traversal"
                )
            resolved.pop()
        else:
            resolved.append(part)
    return "/".join(resolved)


def _is_python_execution_path(path: str) -> bool:
    return (
        path == INTERPRETER_PATH
        or path.startswith("usr/local/lib/python3.12/")
    )


def _apply_layer(
    filesystem: dict[str, FileEntry],
    directories: dict[str, FileEntry],
    raw: bytes,
    label: str,
    *,
    allow_pinned_base_root_marker: bool = False,
) -> set[str]:
    seen: set[str] = set()
    touched: set[str] = set()
    count = 0
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            for member in archive:
                count += 1
                if count > MAX_ENTRIES:
                    raise QueryV3ImageAttestationError(
                        f"{label} exceeds entry limit"
                    )
                if member.name == ".":
                    if not allow_pinned_base_root_marker:
                        raise QueryV3ImageAttestationError(
                            f"{label} path is not normalized"
                        )
                    if (
                        not member.isdir()
                        or member.size != 0
                        or member.linkname
                        or member.pax_headers
                    ):
                        raise QueryV3ImageAttestationError(
                            f"{label} pinned base root marker is invalid"
                        )
                    continue
                name = _normalized_path(member.name, label)
                if not name or name in seen:
                    raise QueryV3ImageAttestationError(
                        f"{label} contains an empty or duplicate path"
                    )
                seen.add(name)
                touched.add(name)
                total += max(member.size, 0)
                if total > MAX_LAYER_BYTES:
                    raise QueryV3ImageAttestationError(
                        f"{label} exceeds unpacked size limit"
                    )
                path = PurePosixPath(name)
                base = path.name
                parent = "" if str(path.parent) == "." else str(path.parent)
                if base.startswith(".wh."):
                    if not member.isreg() or member.size != 0:
                        raise QueryV3ImageAttestationError(
                            f"{label} whiteout is invalid"
                        )
                    target = (
                        parent
                        if base == ".wh..wh..opq"
                        else f"{parent}/{base.removeprefix('.wh.')}".strip("/")
                    )
                    _remove_path(filesystem, directories, target)
                    continue
                for depth in range(1, len(path.parts)):
                    ancestor = "/".join(path.parts[:depth])
                    if ancestor in filesystem:
                        raise QueryV3ImageAttestationError(
                            f"{label} path has a non-directory ancestor"
                        )
                    directories.setdefault(
                        ancestor,
                        FileEntry(kind="directory", mode=0o755),
                    )
                if member.isdir():
                    filesystem.pop(name, None)
                    directories[name] = FileEntry(
                        kind="directory",
                        mode=member.mode & 0o7777,
                        uid=member.uid,
                        gid=member.gid,
                    )
                    continue
                _remove_path(filesystem, directories, name)
                if member.isreg():
                    content = _tar_member_raw(
                        archive,
                        member,
                        f"{label}:{name}",
                        limit=MAX_LAYER_FILE_BYTES,
                    )
                    filesystem[name] = FileEntry(
                        kind="regular",
                        sha256=_sha256(content),
                        content=content,
                        size=len(content),
                        mode=member.mode & 0o7777,
                        uid=member.uid,
                        gid=member.gid,
                    )
                elif member.issym():
                    filesystem[name] = FileEntry(
                        kind="symlink",
                        mode=member.mode & 0o7777,
                        uid=member.uid,
                        gid=member.gid,
                        link_target=_resolve_link(
                            name,
                            member.linkname,
                            symlink=True,
                        ),
                    )
                elif member.islnk():
                    target = _resolve_link(
                        name,
                        member.linkname,
                        symlink=False,
                    )
                    if (
                        _is_python_execution_path(name)
                        or _is_python_execution_path(target)
                    ):
                        raise QueryV3ImageAttestationError(
                            "OCI Python execution closure cannot contain "
                            f"hardlinks: /{name} -> /{target}"
                        )
                    target_entry = filesystem.get(target)
                    if target_entry is None or target_entry.kind != "regular":
                        raise QueryV3ImageAttestationError(
                            f"{label} hardlink target is not an existing regular file"
                        )
                    filesystem[name] = FileEntry(
                        kind="regular",
                        sha256=target_entry.sha256,
                        content=target_entry.content,
                        size=target_entry.size,
                        mode=member.mode & 0o7777,
                        uid=member.uid,
                        gid=member.gid,
                    )
                else:
                    raise QueryV3ImageAttestationError(
                        f"{label} contains a special file"
                    )
                if len(filesystem) + len(directories) > MAX_ENTRIES:
                    raise QueryV3ImageAttestationError(
                        "OCI filesystem exceeds entry limit"
                    )
    except QueryV3ImageAttestationError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise QueryV3ImageAttestationError(f"{label} is not a valid tar") from exc
    return touched


def _post_base_path_allowed(path: str) -> bool:
    if path in ALLOWED_POST_BASE_PATHS or path.startswith(
        ALLOWED_POST_BASE_PREFIXES
    ):
        return True
    if not path.startswith(SITE_PACKAGES_PREFIX):
        return False
    relative = path.removeprefix(SITE_PACKAGES_PREFIX)
    return relative.split("/", 1)[0] in ALLOWED_SITE_PACKAGE_TOPLEVEL


def _validate_python_startup_closure(
    filesystem: dict[str, FileEntry],
) -> None:
    forbidden: list[str] = []
    for path in filesystem:
        basename = PurePosixPath(path).name.lower()
        stem = basename.split(".", 1)[0]
        if basename.endswith(".pth") and path != RUNTIME_PTH_PATH:
            forbidden.append("/" + path)
        elif stem in {"sitecustomize", "usercustomize"}:
            forbidden.append("/" + path)
        elif basename.endswith(".egg-link"):
            forbidden.append("/" + path)
    if forbidden:
        raise QueryV3ImageAttestationError(
            "OCI Python startup closure contains an unpinned executable hook: "
            + ", ".join(sorted(forbidden))
        )


def _python_execution_closure(
    filesystem: dict[str, FileEntry],
) -> tuple[str, int]:
    entries: dict[str, dict[str, Any]] = {}
    for path, entry in sorted(filesystem.items()):
        if not _is_python_execution_path(path):
            continue
        entries["/" + path] = {
            "kind": entry.kind,
            "sha256": entry.sha256,
            "size": entry.size,
            "mode": entry.mode,
            "uid": entry.uid,
            "gid": entry.gid,
            "link_target": entry.link_target,
        }
    if not entries:
        raise QueryV3ImageAttestationError(
            "OCI Python execution closure is empty"
        )
    return _sha256(canonical_json({"entries": entries})), len(entries)


def _environment(config: dict[str, Any]) -> dict[str, str]:
    values = config.get("Env")
    if not isinstance(values, list):
        raise QueryV3ImageAttestationError("OCI config Env must be an array")
    parsed: dict[str, str] = {}
    for item in values:
        if not isinstance(item, str) or "=" not in item or "\x00" in item:
            raise QueryV3ImageAttestationError("OCI config Env entry is invalid")
        name, value = item.split("=", 1)
        if not name or name in parsed:
            raise QueryV3ImageAttestationError(
                "OCI config Env contains a duplicate name"
            )
        if any(marker in name.upper() for marker in SENSITIVE_ENV_MARKERS):
            raise QueryV3ImageAttestationError(
                "OCI config contains a sensitive environment name"
            )
        parsed[name] = value
    if parsed != EXPECTED_ENVIRONMENT:
        raise QueryV3ImageAttestationError(
            "OCI config environment does not match frozen query-v3 values"
        )
    return parsed


def _mode_allows(
    entry: FileEntry,
    *,
    uid: int,
    gid: int,
    owner_bit: int,
    group_bit: int,
    other_bit: int,
) -> bool:
    required = (
        owner_bit if entry.uid == uid else group_bit if entry.gid == gid else other_bit
    )
    return entry.mode & required != 0


def _runtime_identity_can_write(entry: FileEntry) -> bool:
    return _mode_allows(
        entry,
        uid=65532,
        gid=65532,
        owner_bit=0o200,
        group_bit=0o020,
        other_bit=0o002,
    )


def _validate_python_execution_permissions(
    filesystem: dict[str, FileEntry],
    directories: dict[str, FileEntry],
) -> None:
    file_paths = {
        path
        for path in filesystem
        if _is_python_execution_path(path)
    }
    directory_paths = {
        path
        for path in directories
        if (
            path
            in {
                "usr",
                "usr/local",
                "usr/local/bin",
                "usr/local/lib",
                "usr/local/lib/python3.12",
            }
            or path.startswith("usr/local/lib/python3.12/")
        )
    }
    for path in sorted(file_paths):
        entry = filesystem[path]
        if entry.kind != "regular":
            raise QueryV3ImageAttestationError(
                "OCI Python execution closure cannot contain "
                f"links: /{path}"
            )
        if (
            entry.mode & 0o022 != 0
            or _runtime_identity_can_write(entry)
        ):
            raise QueryV3ImageAttestationError(
                "OCI Python execution closure is writable by the runtime "
                f"identity or group/world: /{path}"
            )
    for path in sorted(directory_paths):
        entry = directories[path]
        if (
            entry.kind != "directory"
            or entry.mode & 0o022 != 0
            or _runtime_identity_can_write(entry)
            or not _mode_allows(
                entry,
                uid=65532,
                gid=65532,
                owner_bit=0o100,
                group_bit=0o010,
                other_bit=0o001,
            )
        ):
            raise QueryV3ImageAttestationError(
                "OCI Python execution closure directory is writable or not "
                f"traversable by the runtime identity: /{path}"
            )


def _installed_versions(filesystem: dict[str, FileEntry]) -> dict[str, str]:
    installed: dict[str, str] = {}
    for path, entry in filesystem.items():
        if not path.endswith(".dist-info/METADATA") or entry.content is None:
            continue
        try:
            metadata = BytesParser(policy=policy.default).parsebytes(entry.content)
        except (TypeError, ValueError) as exc:
            raise QueryV3ImageAttestationError(
                "installed package METADATA is invalid"
            ) from exc
        name, version = metadata.get("Name"), metadata.get("Version")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        normalized = name.strip().lower().replace("_", "-")
        if normalized not in EXPECTED_INSTALLED_DEPENDENCIES:
            continue
        if normalized in installed:
            raise QueryV3ImageAttestationError(
                f"installed dependency is duplicated: {normalized}"
            )
        expected_path = (
            "usr/local/lib/python3.12/site-packages/"
            f"{normalized.replace('-', '_')}-{version.strip()}"
            ".dist-info/METADATA"
        )
        if path != expected_path:
            raise QueryV3ImageAttestationError(
                f"installed dependency METADATA path is invalid: {path}"
            )
        installed[normalized] = version.strip()
    if installed != EXPECTED_INSTALLED_DEPENDENCIES:
        raise QueryV3ImageAttestationError(
            "installed dependency versions do not match query-v3 pins"
        )
    return installed


def derive_oci_facts(
    archive_path: Path,
    expected_source_commit_sha: str,
    expected_runtime_bundle: dict[str, str],
) -> dict[str, Any]:
    archive_raw = _read_regular(
        archive_path,
        "query-v3 OCI layout archive",
        limit=MAX_OCI_BYTES,
    )
    files = _parse_oci_archive(archive_raw)
    index = _parse_json(files["index.json"], "OCI index")
    _require_fields(index, {"schemaVersion", "mediaType", "manifests"}, "OCI index")
    if (
        index["schemaVersion"] != 2
        or index["mediaType"] != OCI_INDEX_MEDIA_TYPE
        or not isinstance(index["manifests"], list)
        or len(index["manifests"]) != 1
    ):
        raise QueryV3ImageAttestationError(
            "OCI index must contain one linux/amd64 manifest"
        )
    manifest_digest, manifest_size, _ = _descriptor(
        index["manifests"][0],
        "OCI manifest",
        {OCI_MANIFEST_MEDIA_TYPE},
        platform=True,
    )
    manifest_raw = _blob(
        files,
        manifest_digest,
        manifest_size,
        "OCI manifest",
    )
    manifest = _parse_json(manifest_raw, "OCI manifest")
    _require_fields(
        manifest,
        {"schemaVersion", "mediaType", "config", "layers"},
        "OCI manifest",
    )
    if (
        manifest["schemaVersion"] != 2
        or manifest["mediaType"] != OCI_MANIFEST_MEDIA_TYPE
        or not isinstance(manifest["layers"], list)
        or not manifest["layers"]
        or len(manifest["layers"]) > 256
    ):
        raise QueryV3ImageAttestationError("OCI manifest is invalid")
    config_digest, config_size, _ = _descriptor(
        manifest["config"],
        "OCI config",
        {OCI_CONFIG_MEDIA_TYPE},
    )
    config_raw = _blob(files, config_digest, config_size, "OCI config")
    config_document = _parse_json(config_raw, "OCI config")
    if (
        config_document.get("architecture") != "amd64"
        or config_document.get("os") != "linux"
        or not isinstance(config_document.get("config"), dict)
    ):
        raise QueryV3ImageAttestationError("OCI config platform is invalid")
    config = config_document["config"]
    filesystem: dict[str, FileEntry] = {}
    directories: dict[str, FileEntry] = {}
    layer_digests: list[str] = []
    diff_ids: list[str] = []
    referenced = {
        "blobs/sha256/" + manifest_digest.removeprefix("sha256:"),
        "blobs/sha256/" + config_digest.removeprefix("sha256:"),
    }
    unpacked_total = 0
    post_base_touched: set[str] = set()
    for index_number, layer in enumerate(manifest["layers"]):
        digest, size, media_type = _descriptor(
            layer,
            f"OCI layer {index_number}",
            OCI_LAYER_MEDIA_TYPES,
        )
        compressed = _blob(
            files,
            digest,
            size,
            f"OCI layer {index_number}",
        )
        uncompressed = _layer_raw(
            compressed,
            media_type,
            f"OCI layer {index_number}",
        )
        unpacked_total += len(uncompressed)
        if unpacked_total > MAX_LAYER_BYTES:
            raise QueryV3ImageAttestationError(
                "OCI layers exceed total unpacked size limit"
            )
        layer_digests.append(digest)
        diff_ids.append("sha256:" + _sha256(uncompressed))
        touched = _apply_layer(
            filesystem,
            directories,
            uncompressed,
            f"OCI layer {index_number}",
            allow_pinned_base_root_marker=(
                index_number < len(BASE_ROOTFS_LAYER_DIGESTS)
                and digest == BASE_ROOTFS_LAYER_DIGESTS[index_number]
            ),
        )
        if index_number >= len(BASE_ROOTFS_LAYER_DIGESTS):
            post_base_touched.update(touched)
        referenced.add("blobs/sha256/" + digest.removeprefix("sha256:"))
    if {name for name in files if BLOB_RE.fullmatch(name)} != referenced:
        raise QueryV3ImageAttestationError(
            "OCI layout contains missing or unreferenced blobs"
        )
    if config_document.get("rootfs") != {"type": "layers", "diff_ids": diff_ids}:
        raise QueryV3ImageAttestationError("OCI rootfs diff_ids do not match layers")
    if (
        tuple(layer_digests[: len(BASE_ROOTFS_LAYER_DIGESTS)])
        != BASE_ROOTFS_LAYER_DIGESTS
        or tuple(diff_ids[: len(BASE_ROOTFS_DIFF_IDS)]) != BASE_ROOTFS_DIFF_IDS
        or len(layer_digests) <= len(BASE_ROOTFS_LAYER_DIGESTS)
    ):
        raise QueryV3ImageAttestationError(
            "OCI rootfs does not inherit the pinned linux/amd64 base image prefix"
        )
    _validate_python_startup_closure(filesystem)
    _validate_python_execution_permissions(filesystem, directories)
    disallowed_delta = sorted(
        path for path in post_base_touched if not _post_base_path_allowed(path)
    )
    if disallowed_delta:
        raise QueryV3ImageAttestationError(
            "OCI post-base layer changes a path outside the frozen build delta: "
            + ", ".join("/" + path for path in disallowed_delta)
        )
    expected_labels = {
        **EXPECTED_LABELS,
        "org.opencontainers.image.revision": expected_source_commit_sha,
    }
    labels = config.get("Labels")
    if labels != expected_labels:
        raise QueryV3ImageAttestationError("OCI labels do not match exact query source")
    if (
        config.get("User") != "65532:65532"
        or config.get("WorkingDir") != "/opt/c-fast-t1"
        or config.get("Entrypoint") != ENTRYPOINT
        or config.get("Cmd") not in (None, [])
        or config.get("Healthcheck") is not None
        or config.get("Volumes") not in (None, {})
        or config.get("OnBuild") not in (None, [])
    ):
        raise QueryV3ImageAttestationError("OCI runtime config drifted")
    environment = _environment(config)
    interpreter = filesystem.get(INTERPRETER_PATH)
    if (
        interpreter is None
        or interpreter.kind != "regular"
        or interpreter.size <= 0
        or not _mode_allows(
            interpreter,
            uid=65532,
            gid=65532,
            owner_bit=0o100,
            group_bit=0o010,
            other_bit=0o001,
        )
    ):
        raise QueryV3ImageAttestationError(
            "OCI interpreter must be a non-empty executable regular file"
        )
    runtime_pth = filesystem.get(RUNTIME_PTH_PATH)
    if (
        runtime_pth is None
        or runtime_pth.kind != "regular"
        or runtime_pth.content != RUNTIME_PTH_CONTENT
        or runtime_pth.uid != 0
        or runtime_pth.gid != 0
        or runtime_pth.mode != 0o444
    ):
        raise QueryV3ImageAttestationError(
            "query-v3 isolated runtime .pth binding drifted"
        )
    runtime_prefix = "opt/c-fast-t1/"
    actual_runtime_paths = {
        path for path in filesystem if path.startswith(runtime_prefix)
    }
    expected_relative = {
        path.removeprefix("/") for path in expected_runtime_bundle
    }
    if actual_runtime_paths != expected_relative:
        raise QueryV3ImageAttestationError(
            "OCI runtime bundle has missing or unexpected paths"
        )
    runtime_bundle: dict[str, str] = {}
    for expected_path, expected_hash in sorted(expected_runtime_bundle.items()):
        entry = filesystem.get(expected_path.removeprefix("/"))
        if (
            entry is None
            or entry.kind != "regular"
            or entry.sha256 != expected_hash
            or entry.uid != 0
            or entry.gid != 0
            or entry.mode not in {0o444, 0o555}
            or not _mode_allows(
                entry,
                uid=65532,
                gid=65532,
                owner_bit=0o400,
                group_bit=0o040,
                other_bit=0o004,
            )
        ):
            raise QueryV3ImageAttestationError(
                f"OCI runtime file does not match source bundle: {expected_path}"
            )
        runtime_bundle[expected_path] = entry.sha256
    for path, entry in sorted(directories.items()):
        if not (
            path == "opt/c-fast-t1"
            or path.startswith("opt/c-fast-t1/")
        ):
            continue
        if (
            entry.kind != "directory"
            or entry.uid != 0
            or entry.gid != 0
            or entry.mode != 0o555
        ):
            raise QueryV3ImageAttestationError(
                "OCI runtime directory is not root-owned and immutable: "
                f"/{path}"
            )
    required_directories = {"opt", "opt/c-fast-t1"}
    for relative in expected_relative:
        parent = PurePosixPath(relative).parent
        while str(parent).startswith("opt/c-fast-t1"):
            required_directories.add(str(parent))
            parent = parent.parent
    for path in sorted(required_directories):
        entry = directories.get(path)
        if (
            entry is None
            or entry.kind != "directory"
            or entry.uid != 0
            or entry.gid != 0
            or (
                path == "opt"
                and (
                    entry.mode & 0o022 != 0
                    or _runtime_identity_can_write(entry)
                )
            )
            or not _mode_allows(
                entry,
                uid=65532,
                gid=65532,
                owner_bit=0o100,
                group_bit=0o010,
                other_bit=0o001,
            )
        ):
            raise QueryV3ImageAttestationError(
                f"OCI runtime directory is not traversable by uid 65532: /{path}"
            )
    forbidden: list[str] = []
    sensitive: list[str] = []
    for path, entry in {**filesystem, **directories}.items():
        lowered = path.lower()
        basename = PurePosixPath(lowered).name
        if path.startswith(runtime_prefix) and (
            "__pycache__" in PurePosixPath(path).parts
            or basename.endswith((".pyc", ".pyo"))
        ):
            forbidden.append("/" + path)
        if (
            any(marker in lowered for marker in RUNTIME_SENSITIVE_PATH_MARKERS)
            or basename in {"id_rsa", "id_ed25519"}
            or path not in PRIVATE_KEY_MARKER_LITERAL_SOURCE_PATHS
            and entry.content is not None
            and any(marker in entry.content for marker in PRIVATE_KEY_MARKERS)
        ):
            sensitive.append("/" + path)
    if forbidden or sensitive:
        raise QueryV3ImageAttestationError(
            "OCI contains forbidden bytecode, signer or private-key material: "
            f"forbidden={forbidden}, sensitive={sensitive}"
        )
    execution_closure_sha256, execution_closure_entries = (
        _python_execution_closure(filesystem)
    )
    return {
        "archive_raw": archive_raw,
        "manifest_digest": manifest_digest,
        "config_digest": config_digest,
        "layer_digests": layer_digests,
        "diff_ids": diff_ids,
        "python_execution_closure_sha256": execution_closure_sha256,
        "python_execution_closure_entries": execution_closure_entries,
        "config": {
            "user": config["User"],
            "working_dir": config["WorkingDir"],
            "entrypoint": config["Entrypoint"],
            "relevant_environment": environment,
            "labels": labels,
        },
        "runtime_bundle": runtime_bundle,
        "installed_versions": _installed_versions(filesystem),
        "forbidden": forbidden,
        "unexpected": [],
        "sensitive": sensitive,
    }


def _exact(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        raise QueryV3ImageAttestationError(
            f"{label} does not match recomputed content"
        )


def verify_query_v3_image_evidence(
    evidence_path: Path,
    source_bundle_path: Path,
    oci_layout_archive_path: Path,
    expected_source_commit_sha: str,
) -> dict[str, Any]:
    evidence, evidence_raw = _load_json(
        evidence_path,
        "query-v3 external image evidence",
    )
    _validate_schema(
        evidence,
        EVIDENCE_SCHEMA_PATH,
        "query-v3 external image evidence",
    )
    if evidence["schema_version"] != EVIDENCE_SCHEMA_VERSION:
        raise QueryV3ImageAttestationError(
            "query-v3 external evidence version is invalid"
        )
    source = derive_source_facts(
        source_bundle_path,
        expected_source_commit_sha,
    )
    manifest_raw = source["manifest_raw"]
    direct = {
        "source_commit_sha": expected_source_commit_sha,
        "source_bundle_archive_sha256": _sha256(source["bundle_raw"]),
        "source_manifest_raw_sha256": _sha256(manifest_raw),
        "source_manifest_canonical_sha256": _sha256(
            canonical_json(source["manifest"])
        ),
    }
    for field, expected in direct.items():
        _exact(evidence[field], expected, field)
    build = evidence["build"]
    _exact(
        build["containerfile_sha256"],
        source["containerfile_sha256"],
        "Containerfile digest",
    )
    _exact(build["base_image_digest"], BASE_IMAGE_DIGEST, "base image digest")
    _exact(
        build["direct_dependencies"],
        EXPECTED_DEPENDENCIES,
        "direct dependency pins",
    )
    oci = derive_oci_facts(
        oci_layout_archive_path,
        expected_source_commit_sha,
        source["runtime_bundle"],
    )
    image = evidence["image"]
    _exact(
        image["export_sha256"],
        _sha256(oci["archive_raw"]),
        "OCI archive digest",
    )
    _exact(image["digest"], oci["manifest_digest"], "OCI manifest digest")
    _exact(image["id"], oci["config_digest"], "OCI config digest")
    _exact(
        image["rootfs_layer_digests"],
        oci["layer_digests"],
        "OCI layer digests",
    )
    _exact(image["config"], oci["config"], "OCI config facts")
    _exact(
        image["bundle_files"],
        oci["runtime_bundle"],
        "OCI runtime bundle",
    )
    _exact(
        oci["runtime_bundle"],
        source["runtime_bundle"],
        "source bundle to OCI runtime closure",
    )
    for field, actual in (
        ("forbidden_path_matches", oci["forbidden"]),
        ("unexpected_bundle_paths", oci["unexpected"]),
        ("signer_or_private_key_paths", oci["sensitive"]),
    ):
        _exact(image[field], actual, field)
        _exact(actual, [], field)
    _exact(
        image["reference"].rsplit("@", 1)[-1],
        oci["manifest_digest"],
        "immutable image reference",
    )
    runtime_index = _sha256(canonical_json(oci["runtime_bundle"]))
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "source_commit_sha": expected_source_commit_sha,
        "source_bundle_archive_sha256": direct[
            "source_bundle_archive_sha256"
        ],
        "source_manifest_raw_sha256": direct["source_manifest_raw_sha256"],
        "source_manifest_canonical_sha256": direct[
            "source_manifest_canonical_sha256"
        ],
        "external_evidence_sha256": _sha256(evidence_raw),
        "evidence_captured_at": evidence["captured_at"],
        "containerfile_sha256": source["containerfile_sha256"],
        "verifier_sha256": _sha256(
            _read_regular(VERIFIER_PATH, "query-v3 verifier", limit=MAX_JSON_BYTES)
        ),
        "source_manifest_schema_sha256": _sha256(
            _read_regular(
                MANIFEST_SCHEMA_PATH,
                "query-v3 source manifest schema",
                limit=MAX_JSON_BYTES,
            )
        ),
        "evidence_schema_sha256": _sha256(
            _read_regular(
                EVIDENCE_SCHEMA_PATH,
                "query-v3 evidence schema",
                limit=MAX_JSON_BYTES,
            )
        ),
        "attestation_schema_sha256": _sha256(
            _read_regular(
                ATTESTATION_SCHEMA_PATH,
                "query-v3 attestation schema",
                limit=MAX_JSON_BYTES,
            )
        ),
        "base_image_digest": BASE_IMAGE_DIGEST,
        "base_platform_manifest_digest": BASE_PLATFORM_MANIFEST_DIGEST,
        "base_rootfs_layer_digests": list(BASE_ROOTFS_LAYER_DIGESTS),
        "base_rootfs_diff_ids": list(BASE_ROOTFS_DIFF_IDS),
        "python_execution_closure_sha256": oci[
            "python_execution_closure_sha256"
        ],
        "python_execution_closure_entries": oci[
            "python_execution_closure_entries"
        ],
        "installed_dependency_metadata_versions": oci["installed_versions"],
        "oci_layout_archive_sha256": _sha256(oci["archive_raw"]),
        "image_reference": image["reference"],
        "image_digest": oci["manifest_digest"],
        "image_id": oci["config_digest"],
        "rootfs_layer_digests": oci["layer_digests"],
        "runtime_bundle_sha256": oci["runtime_bundle"],
        "runtime_bundle_index_sha256": runtime_index,
        "checks": {
            "source_bundle_archive_recomputed": True,
            "source_manifest_schema_valid": True,
            "source_manifest_identity_recomputed": True,
            "source_bundle_exact_allowlist_verified": True,
            "source_bundle_metadata_canonical": True,
            "source_commit_assertion_bound": True,
            "git_binary_required": False,
            "git_commit_independently_resolved": False,
            "containerfile_instruction_contract_matched": True,
            "oci_archive_sha256_recomputed": True,
            "oci_manifest_config_and_layers_recomputed": True,
            "pinned_base_rootfs_prefix_verified": True,
            "post_base_delta_allowlist_verified": True,
            "python_startup_closure_verified": True,
            "python_execution_closure_frozen": True,
            "immutable_image_reference_matched": True,
            "runtime_files_recomputed_from_layers": True,
            "runtime_bundle_matches_source_bundle": True,
            "forbidden_and_signer_paths_absent": True,
            "build_provenance_verified": False,
            "registry_provenance_verified": False,
        },
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
    if set(report) & set(ADDITIONAL_REPORT_FIELDS):
        raise QueryV3ImageAttestationError(
            "additional attestation fields collide with the base report"
        )
    report.update(ADDITIONAL_REPORT_FIELDS)
    _validate_schema(
        report,
        ATTESTATION_SCHEMA_PATH,
        "query-v3 image attestation",
    )
    return report


def _write_create_only(path: Path, payload: dict[str, Any]) -> None:
    if not path.is_absolute():
        raise QueryV3ImageAttestationError("output path must be absolute")
    raw = (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    try:
        parent = path.parent.resolve(strict=True)
        info = parent.lstat()
    except OSError as exc:
        raise QueryV3ImageAttestationError("output parent is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise QueryV3ImageAttestationError(
            "output parent must be a non-symlink directory"
        )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(parent / path.name, flags, 0o600)
        try:
            offset = 0
            while offset < len(raw):
                written = os.write(descriptor, raw[offset:])
                if written <= 0:
                    raise OSError("short write")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise QueryV3ImageAttestationError(
            "cannot create query-v3 attestation output"
        ) from exc


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
        report = verify_query_v3_image_evidence(
            args.external_image_evidence,
            args.source_bundle_archive,
            args.oci_layout_archive,
            args.expected_source_commit_sha,
        )
        _write_create_only(args.output, report)
    except (QueryV3ImageAttestationError, OSError, ValueError) as exc:
        print(f"query-v3 image attestation failed: {exc}", file=sys.stderr)
        return 2
    print(f"status={report['status']}")
    print(f"image_digest={report['image_digest']}")
    print("git_binary_required=false")
    print("authority_granted=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
