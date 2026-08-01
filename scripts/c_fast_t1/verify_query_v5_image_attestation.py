"""Verify query-v5 source and final OCI composition against exact query-v4."""

from __future__ import annotations

import sys


if __name__ == "__main__":
    raise SystemExit(
        "query-v5 image attestation requires the independently pinned isolated launcher"
    )


import argparse
from dataclasses import dataclass
import hashlib
import io
from pathlib import Path, PurePosixPath
import tarfile
from typing import Any, Callable

SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from c_fast_t1 import verify_query_v4_image_attestation as query_v4  # noqa: E402
from c_fast_t1.validate_query_v5_runtime import (  # noqa: E402
    CONTAINERFILE_PATH,
    ENTRYPOINT,
    EXPECTED_CONTAINERFILE_INSTRUCTION_SHA256,
    EXPECTED_COPY_SOURCES,
    EXPECTED_COPY_TARGETS,
    QueryV5PackagingError,
    inspect_containerfile,
)


ROOT = Path(__file__).resolve().parents[2]
VERIFIER_PATH = Path(__file__).resolve()
MANIFEST_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-query-v5-source-manifest-v1.schema.json"
)
EVIDENCE_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/commodity-c-fast-t1-query-v5-external-image-evidence-v1.schema.json"
)
ATTESTATION_SCHEMA_PATH = (
    ROOT / "docs/schemas/commodity-c-fast-t1-query-v5-image-attestation-v1.schema.json"
)
MANIFEST_ARCHIVE_PATH = "query-v5-source-manifest.json"
MANIFEST_SCHEMA_VERSION = "commodity_c_fast_t1_query_v5_source_manifest_v1"
EVIDENCE_SCHEMA_VERSION = "commodity_c_fast_t1_query_v5_external_image_evidence_v1"
SCHEMA_VERSION = "commodity_c_fast_t1_query_v5_image_attestation_v1"
MANIFEST_ID_PREFIX = "query-v5-source-manifest-v1-"
STATUS = (
    "QUERY_V5_BASE_AND_OVERLAY_OCI_COMPOSITION_VERIFIED_NO_BUILD_OR_REGISTRY_PROVENANCE"
)
RUNTIME_IDENTITY_VERSION = (
    "commodity_c_fast_t1_query_v5_image_attestation_runtime_identity_v1"
)
RUNTIME_PREFIX = "opt/c-fast-query-v5/"
PIN_DIRECTORY = "run/c-fast-t1-query-v5-pins"
ALLOWED_OVERLAY_DIRECTORIES = frozenset(
    {
        "opt/c-fast-query-v5",
        "opt/c-fast-query-v5/release",
        "opt/c-fast-query-v5/release/scripts",
        PIN_DIRECTORY,
    }
)
EXPECTED_LABEL_TITLE = "vnpy-web-bridge C_FAST T1 query-v5 code-only overlay"
PRIVATE_KEY_MARKERS = query_v4._delegate.PRIVATE_KEY_MARKERS
SENSITIVE_PATH_MARKERS = (
    "private_key",
    "signer",
    "sign_release",
    "query_child",
    "dsn",
)
CONFIG_SENSITIVE_TEXT_MARKERS = (
    "private_key",
    "signer",
    "sign_release",
)

_delegate = query_v4._delegate
QueryV5ImageAttestationError = query_v4.QueryV4ImageAttestationError
canonical_json = query_v4.canonical_json


@dataclass(frozen=True)
class QueryV5AttestationRuntimeIdentity:
    runtime_image_digest: str
    pin_manifest_sha256: str
    launcher_sha256: str
    verifier_sha256: str
    query_v4_verifier_sha256: str
    query_v4_delegate_sha256: str
    query_v5_validator_sha256: str
    query_v4_validator_sha256: str
    python_executable_path_sha256: str
    python_executable_sha256: str
    loaded_executable_sha256: str
    source_root_path_sha256: str
    source_root_identity_sha256: str
    source_closure_manifest_sha256: str
    dependency_root_path_sha256: str
    dependency_root_identity_sha256: str
    dependency_closure_manifest_sha256: str
    isolated_flags_verified: bool
    source_closure_retained: bool
    immutable_runtime_verified: bool


_ACTIVE_RUNTIME_IDENTITY: QueryV5AttestationRuntimeIdentity | None = None
_ACTIVE_RUNTIME_REVALIDATOR: Callable[[], None] | None = None


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _fail(message: str) -> None:
    raise QueryV5ImageAttestationError(message)


def _validate_runtime_identity(
    identity: QueryV5AttestationRuntimeIdentity,
) -> None:
    if (
        not identity.runtime_image_digest.startswith("sha256:")
        or len(identity.runtime_image_digest) != 71
        or any(
            character not in "0123456789abcdef"
            for character in identity.runtime_image_digest[7:]
        )
    ):
        _fail("query-v5 attestation runtime image digest is invalid")
    hashes = {
        field: getattr(identity, field)
        for field in identity.__dataclass_fields__
        if field.endswith("_sha256")
    }
    if any(
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
        for value in hashes.values()
    ):
        _fail("query-v5 attestation runtime identity hash is invalid")
    if not (
        identity.isolated_flags_verified
        and identity.source_closure_retained
        and identity.immutable_runtime_verified
    ):
        _fail("query-v5 attestation runtime identity is not independently enforced")


def _runtime_identity_payload(
    identity: QueryV5AttestationRuntimeIdentity,
) -> dict[str, Any]:
    _validate_runtime_identity(identity)
    payload = {
        "schema_version": RUNTIME_IDENTITY_VERSION,
        **{field: getattr(identity, field) for field in identity.__dataclass_fields__},
    }
    payload["runtime_identity_sha256"] = _sha256(canonical_json(payload))
    return payload


def install_verified_runtime_identity(
    identity: QueryV5AttestationRuntimeIdentity,
    revalidator: Callable[[], None],
) -> None:
    """Install the launcher's retained execution identity exactly once."""

    global _ACTIVE_RUNTIME_IDENTITY, _ACTIVE_RUNTIME_REVALIDATOR
    if _ACTIVE_RUNTIME_IDENTITY is not None:
        _fail("query-v5 attestation runtime identity is already installed")
    _validate_runtime_identity(identity)
    if not callable(revalidator):
        _fail("query-v5 attestation runtime revalidator is required")
    _ACTIVE_RUNTIME_IDENTITY = identity
    _ACTIVE_RUNTIME_REVALIDATOR = revalidator


def _require_runtime_identity() -> QueryV5AttestationRuntimeIdentity:
    identity = _ACTIVE_RUNTIME_IDENTITY
    revalidator = _ACTIVE_RUNTIME_REVALIDATOR
    if identity is None or not callable(revalidator):
        _fail("query-v5 attestation requires the independently pinned launcher")
    _validate_runtime_identity(identity)
    revalidator()
    return identity


def _exact(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        _fail(f"{label} does not match recomputed content")


def _reject_sensitive_config(
    raw: bytes,
    document: dict[str, Any],
    label: str,
) -> None:
    if any(marker in raw for marker in PRIVATE_KEY_MARKERS):
        _fail(f"{label} OCI config contains private-key material")
    pending: list[Any] = [document]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            pending.extend(value.keys())
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, str):
            encoded = value.encode("utf-8")
            if any(marker in encoded for marker in PRIVATE_KEY_MARKERS) or any(
                marker in value.lower() for marker in CONFIG_SENSITIVE_TEXT_MARKERS
            ):
                _fail(f"{label} OCI config contains sensitive material")


def _source_facts(
    bundle_path: Path,
    expected_source_commit_sha: str,
) -> dict[str, Any]:
    if _delegate.COMMIT_RE.fullmatch(expected_source_commit_sha) is None:
        _fail("expected query-v5 source commit is invalid")
    bundle_raw = _delegate._read_regular(
        bundle_path,
        "query-v5 source bundle archive",
        limit=_delegate.MAX_SOURCE_BUNDLE_BYTES,
    )
    members: list[tuple[str, bytes, int]] = []
    seen: set[str] = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(bundle_raw), mode="r:") as archive:
            for member in archive:
                name = _delegate._normalized_path(member.name, "source bundle")
                if not name or name in seen:
                    _fail("source bundle contains an empty or duplicate path")
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
                    _fail(f"source bundle entry metadata is not canonical: {name}")
                members.append(
                    (
                        name,
                        _delegate._tar_member_raw(
                            archive,
                            member,
                            f"source bundle:{name}",
                            limit=_delegate.MAX_JSON_BYTES,
                        ),
                        member.mode,
                    )
                )
    except QueryV5ImageAttestationError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise QueryV5ImageAttestationError(
            "source bundle must be one valid plain tar archive"
        ) from exc
    if not members or members[0][0] != MANIFEST_ARCHIVE_PATH:
        _fail("query-v5 source manifest must be the first archive entry")
    manifest_raw = members[0][1]
    if members[0][2] != 0o444:
        _fail("query-v5 source manifest archive mode drifted")
    manifest = _delegate._parse_json(manifest_raw, "query-v5 source manifest")
    _delegate._validate_schema(
        manifest,
        MANIFEST_SCHEMA_PATH,
        "query-v5 source manifest",
    )
    if (
        manifest["schema_version"] != MANIFEST_SCHEMA_VERSION
        or manifest["source_commit_sha"] != expected_source_commit_sha
        or manifest["containerfile_path"] != CONTAINERFILE_PATH
    ):
        _fail("source manifest namespace does not match expected query-v5 source")
    if manifest_raw != canonical_json(manifest):
        _fail("query-v5 source manifest bytes are not canonical JSON")
    identity = {key: value for key, value in manifest.items() if key != "manifest_id"}
    expected_manifest_id = MANIFEST_ID_PREFIX + _sha256(canonical_json(identity))
    if manifest["manifest_id"] != expected_manifest_id:
        _fail("query-v5 source manifest identity is invalid")
    entries = manifest["entries"]
    paths = [entry["path"] for entry in entries]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        _fail("query-v5 source manifest entries must be unique and sorted")
    if [name for name, _raw, _mode in members] != [
        MANIFEST_ARCHIVE_PATH,
        *paths,
    ]:
        _fail("query-v5 source bundle paths do not match exact manifest order")
    if _delegate._canonical_source_bundle(members) != bundle_raw:
        _fail("query-v5 source bundle is not canonical USTAR")
    by_name = {name: (raw, mode) for name, raw, mode in members[1:]}
    for entry in entries:
        raw, mode = by_name[entry["path"]]
        if (
            len(raw) != entry["size"]
            or _sha256(raw) != entry["sha256"]
            or mode != entry["mode"]
        ):
            _fail(
                "query-v5 source bundle entry does not match manifest: " + entry["path"]
            )
    try:
        containerfile_raw = by_name[CONTAINERFILE_PATH][0]
        instruction_sha256, copy_sources, copies = inspect_containerfile(
            containerfile_raw
        )
    except (KeyError, QueryV5PackagingError) as exc:
        raise QueryV5ImageAttestationError(
            "query-v5 Containerfile contract is invalid"
        ) from exc
    expected_paths = sorted({CONTAINERFILE_PATH, *EXPECTED_COPY_SOURCES})
    if (
        paths != expected_paths
        or copy_sources != EXPECTED_COPY_SOURCES
        or copies != EXPECTED_COPY_TARGETS
        or instruction_sha256 != EXPECTED_CONTAINERFILE_INSTRUCTION_SHA256
        or manifest["containerfile_instruction_sha256"] != instruction_sha256
    ):
        _fail("query-v5 source does not match exact Containerfile COPY closure")
    runtime_bundle = {
        f"/opt/c-fast-query-v5/{copies[source]}": _sha256(by_name[source][0])
        for source in copy_sources
    }
    runtime_modes = {
        f"/opt/c-fast-query-v5/{copies[source]}": by_name[source][1]
        for source in copy_sources
    }
    return {
        "bundle_raw": bundle_raw,
        "manifest": manifest,
        "manifest_raw": manifest_raw,
        "containerfile_sha256": _sha256(containerfile_raw),
        "runtime_bundle": runtime_bundle,
        "runtime_modes": runtime_modes,
    }


def _load_oci_state(path: Path, label: str) -> dict[str, Any]:
    archive_raw = _delegate._read_regular(
        path,
        f"{label} OCI layout archive",
        limit=_delegate.MAX_OCI_BYTES,
    )
    files = _delegate._parse_oci_archive(archive_raw)
    index = _delegate._parse_json(files["index.json"], f"{label} OCI index")
    _delegate._require_fields(
        index,
        {"schemaVersion", "mediaType", "manifests"},
        f"{label} OCI index",
    )
    if (
        index["schemaVersion"] != 2
        or index["mediaType"] != _delegate.OCI_INDEX_MEDIA_TYPE
        or not isinstance(index["manifests"], list)
        or len(index["manifests"]) != 1
    ):
        _fail(f"{label} OCI index must contain one linux/amd64 manifest")
    manifest_digest, manifest_size, _media_type = _delegate._descriptor(
        index["manifests"][0],
        f"{label} OCI manifest",
        {_delegate.OCI_MANIFEST_MEDIA_TYPE},
        platform=True,
    )
    manifest_raw = _delegate._blob(
        files,
        manifest_digest,
        manifest_size,
        f"{label} OCI manifest",
    )
    manifest = _delegate._parse_json(
        manifest_raw,
        f"{label} OCI manifest",
    )
    _delegate._require_fields(
        manifest,
        {"schemaVersion", "mediaType", "config", "layers"},
        f"{label} OCI manifest",
    )
    if (
        manifest["schemaVersion"] != 2
        or manifest["mediaType"] != _delegate.OCI_MANIFEST_MEDIA_TYPE
        or not isinstance(manifest["layers"], list)
        or not manifest["layers"]
        or len(manifest["layers"]) > 256
    ):
        _fail(f"{label} OCI manifest is invalid")
    config_digest, config_size, _config_media_type = _delegate._descriptor(
        manifest["config"],
        f"{label} OCI config",
        {_delegate.OCI_CONFIG_MEDIA_TYPE},
    )
    config_raw = _delegate._blob(
        files,
        config_digest,
        config_size,
        f"{label} OCI config",
    )
    config_document = _delegate._parse_json(config_raw, f"{label} OCI config")
    _reject_sensitive_config(config_raw, config_document, label)
    if (
        config_document.get("architecture") != "amd64"
        or config_document.get("os") != "linux"
        or not isinstance(config_document.get("config"), dict)
    ):
        _fail(f"{label} OCI config platform is invalid")
    filesystem: dict[str, Any] = {}
    directories: dict[str, Any] = {}
    layer_descriptors: list[dict[str, Any]] = []
    layer_digests: list[str] = []
    diff_ids: list[str] = []
    layer_raw: list[bytes] = []
    referenced = {
        "blobs/sha256/" + manifest_digest.removeprefix("sha256:"),
        "blobs/sha256/" + config_digest.removeprefix("sha256:"),
    }
    unpacked_total = 0
    for number, descriptor in enumerate(manifest["layers"]):
        digest, size, media_type = _delegate._descriptor(
            descriptor,
            f"{label} OCI layer {number}",
            _delegate.OCI_LAYER_MEDIA_TYPES,
        )
        stored = _delegate._blob(
            files,
            digest,
            size,
            f"{label} OCI layer {number}",
        )
        raw = _delegate._layer_raw(
            stored,
            media_type,
            f"{label} OCI layer {number}",
        )
        unpacked_total += len(raw)
        if unpacked_total > _delegate.MAX_LAYER_BYTES:
            _fail(f"{label} OCI layers exceed total unpacked size limit")
        _delegate._apply_layer(
            filesystem,
            directories,
            raw,
            f"{label} OCI layer {number}",
        )
        layer_descriptors.append(dict(descriptor))
        layer_digests.append(digest)
        diff_ids.append("sha256:" + _sha256(raw))
        layer_raw.append(raw)
        referenced.add("blobs/sha256/" + digest.removeprefix("sha256:"))
    if {name for name in files if _delegate.BLOB_RE.fullmatch(name)} != referenced:
        _fail(f"{label} OCI layout contains missing or unreferenced blobs")
    if config_document.get("rootfs") != {"type": "layers", "diff_ids": diff_ids}:
        _fail(f"{label} OCI rootfs diff_ids do not match layers")
    return {
        "archive_raw": archive_raw,
        "manifest_digest": manifest_digest,
        "config_digest": config_digest,
        "config": config_document["config"],
        "layer_descriptors": layer_descriptors,
        "layer_digests": layer_digests,
        "diff_ids": diff_ids,
        "layer_raw": layer_raw,
        "filesystem": filesystem,
        "directories": directories,
    }


def _scan_overlay_layer(
    raw: bytes,
    label: str,
    base_paths: set[str],
    expected_runtime_bundle: dict[str, str],
    expected_runtime_modes: dict[str, int],
) -> set[str]:
    if any(marker in raw for marker in PRIVATE_KEY_MARKERS):
        _fail(f"{label} raw tar contains private-key material")
    expected_runtime_paths = {
        path.removeprefix("/") for path in expected_runtime_bundle
    }
    touched: set[str] = set()
    canonical_members: list[tuple[str, bytes, int, bytes]] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            if archive.pax_headers:
                _fail(f"{label} contains forbidden global PAX headers")
            for member in archive:
                path = _delegate._normalized_path(member.name, label)
                if not path or path in touched:
                    _fail(f"{label} contains an empty or duplicate path")
                touched.add(path)
                if member.pax_headers:
                    _fail(f"{label} contains forbidden local PAX headers")
                if PurePosixPath(path).name.startswith(".wh."):
                    _fail(f"{label} contains a forbidden whiteout")
                if path in base_paths:
                    _fail(f"{label} overwrites query-v4 base path: /{path}")
                if not (
                    path in ALLOWED_OVERLAY_DIRECTORIES
                    or path.startswith(RUNTIME_PREFIX)
                ):
                    _fail(f"{label} touches path outside overlay allowlist: /{path}")
                mode = member.mode & 0o7777
                if member.uid != 0 or member.gid != 0:
                    _fail(f"{label} contains a non-root-owned entry: /{path}")
                if any(marker in path.lower() for marker in SENSITIVE_PATH_MARKERS):
                    _fail(f"{label} contains signer or private-key material: /{path}")
                if not member.isdir() and not member.isreg():
                    _fail(f"{label} contains a link or special file: /{path}")
                if path in ALLOWED_OVERLAY_DIRECTORIES:
                    allowed_modes = {0o555} if path == PIN_DIRECTORY else {0o555, 0o755}
                    if not member.isdir() or mode not in allowed_modes:
                        _fail(
                            f"{label} allowlisted directory entry is not exact: /{path}"
                        )
                    canonical_members.append((path, b"", mode, tarfile.DIRTYPE))
                elif path in expected_runtime_paths:
                    if not member.isreg():
                        _fail(f"{label} runtime entry is not a regular file: /{path}")
                    content = _delegate._tar_member_raw(
                        archive,
                        member,
                        f"{label}:{path}",
                        limit=_delegate.MAX_LAYER_FILE_BYTES,
                    )
                    if any(marker in content for marker in PRIVATE_KEY_MARKERS):
                        _fail(
                            f"{label} contains signer or private-key material: /{path}"
                        )
                    image_path = "/" + path
                    source_mode = expected_runtime_modes[image_path]
                    if _sha256(content) != expected_runtime_bundle[
                        image_path
                    ] or mode not in {source_mode, source_mode & ~0o222}:
                        _fail(
                            f"{label} runtime entry does not match exact source: /{path}"
                        )
                    canonical_members.append((path, content, mode, tarfile.REGTYPE))
                else:
                    _fail(f"{label} contains an unexpected overlay path: /{path}")
    except QueryV5ImageAttestationError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise QueryV5ImageAttestationError(f"{label} is not a valid tar") from exc
    canonical = io.BytesIO()
    try:
        with tarfile.open(
            fileobj=canonical,
            mode="w:",
            format=tarfile.USTAR_FORMAT,
        ) as archive:
            for path, content, mode, kind in canonical_members:
                member = tarfile.TarInfo(path)
                member.type = kind
                member.mode = mode
                member.uid = 0
                member.gid = 0
                member.uname = ""
                member.gname = ""
                member.mtime = 0
                if kind == tarfile.REGTYPE:
                    member.size = len(content)
                    archive.addfile(member, io.BytesIO(content))
                else:
                    archive.addfile(member)
    except (OSError, tarfile.TarError, ValueError) as exc:
        raise QueryV5ImageAttestationError(
            f"{label} cannot be represented as canonical USTAR"
        ) from exc
    if raw != canonical.getvalue():
        _fail(
            f"{label} is not the unique canonical USTAR encoding of its exact members"
        )
    return touched


def _environment(config: dict[str, Any], label: str) -> dict[str, str]:
    values = config.get("Env")
    if not isinstance(values, list):
        _fail(f"{label} OCI config Env must be an array")
    parsed: dict[str, str] = {}
    for item in values:
        if not isinstance(item, str) or "=" not in item or "\x00" in item:
            _fail(f"{label} OCI config Env entry is invalid")
        name, value = item.split("=", 1)
        if not name or name in parsed:
            _fail(f"{label} OCI config Env contains a duplicate name")
        if any(marker in name.upper() for marker in _delegate.SENSITIVE_ENV_MARKERS):
            _fail(f"{label} OCI config contains a sensitive environment name")
        parsed[name] = value
    return parsed


def _validate_final_oci(
    base: dict[str, Any],
    final: dict[str, Any],
    query_v4_report: dict[str, Any],
    source: dict[str, Any],
    expected_source_commit_sha: str,
) -> dict[str, Any]:
    base_count = len(base["layer_descriptors"])
    if len(final["layer_descriptors"]) <= base_count:
        _fail("query-v5 OCI has no overlay layer")
    _exact(
        final["layer_descriptors"][:base_count],
        base["layer_descriptors"],
        "query-v4 OCI layer descriptor prefix",
    )
    _exact(
        final["diff_ids"][:base_count],
        base["diff_ids"],
        "query-v4 OCI diff-id prefix",
    )
    base_paths = set(base["filesystem"]) | set(base["directories"])
    overlay_touched: set[str] = set()
    for number, raw in enumerate(final["layer_raw"][base_count:], base_count):
        overlay_touched.update(
            _scan_overlay_layer(
                raw,
                f"query-v5 OCI layer {number}",
                base_paths,
                source["runtime_bundle"],
                source["runtime_modes"],
            )
        )
    config = final["config"]
    expected_labels = {
        "io.vnpy-web-bridge.c-fast-t1.authority-granted": "false",
        "io.vnpy-web-bridge.c-fast-t1.query-v4-runtime": "true",
        "io.vnpy-web-bridge.c-fast-t1.query-v5-base-image": query_v4_report[
            "image_reference"
        ],
        "io.vnpy-web-bridge.c-fast-t1.query-v5-runtime": "true",
        "org.opencontainers.image.revision": expected_source_commit_sha,
        "org.opencontainers.image.title": EXPECTED_LABEL_TITLE,
    }
    if config.get("Labels") != expected_labels:
        _fail("query-v5 OCI labels do not match exact source and base image")
    mutable_config_fields = {
        "Cmd",
        "Entrypoint",
        "Env",
        "Healthcheck",
        "Labels",
        "OnBuild",
        "User",
        "Volumes",
        "WorkingDir",
    }
    inherited_base_config = {
        key: value
        for key, value in base["config"].items()
        if key not in mutable_config_fields
    }
    inherited_final_config = {
        key: value for key, value in config.items() if key not in mutable_config_fields
    }
    _exact(
        inherited_final_config,
        inherited_base_config,
        "query-v5 inherited OCI config fields",
    )
    if (
        config.get("User") != "65532:65532"
        or config.get("WorkingDir") != "/opt/c-fast-query-v5"
        or config.get("Entrypoint") != ENTRYPOINT
        or config.get("Cmd") not in (None, [])
        or config.get("Healthcheck") is not None
        or config.get("Volumes") not in (None, {})
        or config.get("OnBuild") not in (None, [])
    ):
        _fail("query-v5 OCI runtime config drifted")
    base_environment = _environment(base["config"], "query-v4")
    final_environment = _environment(config, "query-v5")
    _exact(final_environment, base_environment, "query-v5 inherited environment")
    _delegate._validate_python_startup_closure(final["filesystem"])
    _delegate._validate_python_execution_permissions(
        final["filesystem"],
        final["directories"],
    )
    closure_sha256, closure_entries = _delegate._python_execution_closure(
        final["filesystem"]
    )
    _exact(
        closure_sha256,
        query_v4_report["python_execution_closure_sha256"],
        "merged Python execution closure",
    )
    _exact(
        closure_entries,
        query_v4_report["python_execution_closure_entries"],
        "merged Python execution closure entry count",
    )
    expected_runtime_paths = {
        path.removeprefix("/") for path in source["runtime_bundle"]
    }
    actual_runtime_paths = {
        path for path in final["filesystem"] if path.startswith(RUNTIME_PREFIX)
    }
    _exact(
        actual_runtime_paths,
        expected_runtime_paths,
        "query-v5 OCI runtime path closure",
    )
    runtime_bundle: dict[str, str] = {}
    for image_path, expected_hash in sorted(source["runtime_bundle"].items()):
        entry = final["filesystem"].get(image_path.removeprefix("/"))
        if (
            entry is None
            or entry.kind != "regular"
            or entry.sha256 != expected_hash
            or entry.uid != 0
            or entry.gid != 0
            or entry.mode not in {0o444, 0o555}
            or entry.mode & 0o022
        ):
            _fail(f"query-v5 runtime file is not exact and immutable: {image_path}")
        runtime_bundle[image_path] = entry.sha256
    required_directories = set(ALLOWED_OVERLAY_DIRECTORIES)
    for path in sorted(required_directories):
        entry = final["directories"].get(path)
        if (
            entry is None
            or entry.kind != "directory"
            or entry.uid != 0
            or entry.gid != 0
            or entry.mode != 0o555
        ):
            _fail(f"query-v5 overlay directory is not immutable: /{path}")
    sensitive: list[str] = []
    for path in sorted(overlay_touched):
        entry = final["filesystem"].get(path) or final["directories"].get(path)
        lowered = path.lower()
        if (
            any(marker in lowered for marker in SENSITIVE_PATH_MARKERS)
            or entry is not None
            and entry.content is not None
            and any(marker in entry.content for marker in PRIVATE_KEY_MARKERS)
        ):
            sensitive.append("/" + path)
    if sensitive:
        _fail("query-v5 overlay contains signer or private-key material")
    return {
        "overlay_touched_paths": ["/" + path for path in sorted(overlay_touched)],
        "runtime_bundle": runtime_bundle,
        "python_execution_closure_sha256": closure_sha256,
        "python_execution_closure_entries": closure_entries,
        "environment": final_environment,
        "labels": expected_labels,
    }


def verify_query_v5_image_evidence(
    query_v4_external_image_evidence_path: Path,
    query_v4_source_bundle_path: Path,
    query_v4_oci_layout_archive_path: Path,
    query_v4_content_attestation_path: Path,
    expected_query_v4_source_commit_sha: str,
    external_image_evidence_path: Path,
    source_bundle_path: Path,
    oci_layout_archive_path: Path,
    expected_source_commit_sha: str,
) -> dict[str, Any]:
    runtime_identity = _require_runtime_identity()
    query_v4_report = query_v4.verify_query_v4_image_evidence(
        query_v4_external_image_evidence_path,
        query_v4_source_bundle_path,
        query_v4_oci_layout_archive_path,
        expected_query_v4_source_commit_sha,
    )
    supplied_v4_report, supplied_v4_raw = _delegate._load_json(
        query_v4_content_attestation_path,
        "query-v4 content attestation",
    )
    _delegate._validate_schema(
        supplied_v4_report,
        query_v4.ATTESTATION_SCHEMA_PATH,
        "query-v4 content attestation",
    )
    _exact(
        supplied_v4_report,
        query_v4_report,
        "query-v4 content attestation replay",
    )
    source = _source_facts(source_bundle_path, expected_source_commit_sha)
    base = _load_oci_state(query_v4_oci_layout_archive_path, "query-v4")
    _exact(base["manifest_digest"], query_v4_report["image_digest"], "query-v4 image")
    _exact(base["config_digest"], query_v4_report["image_id"], "query-v4 config")
    _exact(
        base["layer_digests"],
        query_v4_report["rootfs_layer_digests"],
        "query-v4 rootfs layers",
    )
    final = _load_oci_state(oci_layout_archive_path, "query-v5")
    composition = _validate_final_oci(
        base,
        final,
        query_v4_report,
        source,
        expected_source_commit_sha,
    )
    evidence, evidence_raw = _delegate._load_json(
        external_image_evidence_path,
        "query-v5 external image evidence",
    )
    _delegate._validate_schema(
        evidence,
        EVIDENCE_SCHEMA_PATH,
        "query-v5 external image evidence",
    )
    if evidence["schema_version"] != EVIDENCE_SCHEMA_VERSION:
        _fail("query-v5 external evidence version is invalid")
    direct = {
        "source_commit_sha": expected_source_commit_sha,
        "source_bundle_archive_sha256": _sha256(source["bundle_raw"]),
        "source_manifest_raw_sha256": _sha256(source["manifest_raw"]),
        "source_manifest_canonical_sha256": _sha256(canonical_json(source["manifest"])),
    }
    for field, expected in direct.items():
        _exact(evidence[field], expected, field)
    v4_binding = evidence["query_v4"]
    for field, expected in {
        "content_attestation_raw_sha256": _sha256(supplied_v4_raw),
        "content_attestation_canonical_sha256": _sha256(
            canonical_json(supplied_v4_report)
        ),
        "oci_layout_archive_sha256": _sha256(base["archive_raw"]),
        "image_reference": query_v4_report["image_reference"],
        "image_digest": base["manifest_digest"],
        "image_id": base["config_digest"],
    }.items():
        _exact(v4_binding[field], expected, f"query-v4 {field}")
    build = evidence["build"]
    for field, expected in {
        "containerfile_sha256": source["containerfile_sha256"],
        "query_v4_base_image_reference": query_v4_report["image_reference"],
        "query_v4_base_image_digest": base["manifest_digest"],
    }.items():
        _exact(build[field], expected, f"build {field}")
    image = evidence["image"]
    expected_config = {
        "user": "65532:65532",
        "working_dir": "/opt/c-fast-query-v5",
        "entrypoint": ENTRYPOINT,
        "relevant_environment": composition["environment"],
        "labels": composition["labels"],
    }
    for field, expected in {
        "digest": final["manifest_digest"],
        "id": final["config_digest"],
        "export_sha256": _sha256(final["archive_raw"]),
        "rootfs_layer_digests": final["layer_digests"],
        "rootfs_diff_ids": final["diff_ids"],
        "config": expected_config,
        "bundle_files": composition["runtime_bundle"],
        "overlay_touched_paths": composition["overlay_touched_paths"],
        "forbidden_path_matches": [],
        "unexpected_bundle_paths": [],
        "signer_or_private_key_paths": [],
    }.items():
        _exact(image[field], expected, f"image {field}")
    _exact(
        image["reference"].rsplit("@", 1)[-1],
        final["manifest_digest"],
        "query-v5 immutable image reference",
    )
    base_count = len(base["layer_digests"])
    runtime_index = _sha256(canonical_json(composition["runtime_bundle"]))
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "query_v4_source_commit_sha": expected_query_v4_source_commit_sha,
        "source_commit_sha": expected_source_commit_sha,
        "query_v4_content_attestation_raw_sha256": _sha256(supplied_v4_raw),
        "query_v4_content_attestation_canonical_sha256": _sha256(
            canonical_json(supplied_v4_report)
        ),
        "query_v4_oci_layout_archive_sha256": _sha256(base["archive_raw"]),
        "source_bundle_archive_sha256": direct["source_bundle_archive_sha256"],
        "source_manifest_raw_sha256": direct["source_manifest_raw_sha256"],
        "source_manifest_canonical_sha256": direct["source_manifest_canonical_sha256"],
        "external_evidence_sha256": _sha256(evidence_raw),
        "evidence_captured_at": evidence["captured_at"],
        "containerfile_sha256": source["containerfile_sha256"],
        "verifier_sha256": runtime_identity.verifier_sha256,
        "attestation_runtime": _runtime_identity_payload(runtime_identity),
        "source_manifest_schema_sha256": _sha256(
            _delegate._read_regular(
                MANIFEST_SCHEMA_PATH,
                "query-v5 source manifest schema",
                limit=_delegate.MAX_JSON_BYTES,
            )
        ),
        "evidence_schema_sha256": _sha256(
            _delegate._read_regular(
                EVIDENCE_SCHEMA_PATH,
                "query-v5 evidence schema",
                limit=_delegate.MAX_JSON_BYTES,
            )
        ),
        "attestation_schema_sha256": _sha256(
            _delegate._read_regular(
                ATTESTATION_SCHEMA_PATH,
                "query-v5 attestation schema",
                limit=_delegate.MAX_JSON_BYTES,
            )
        ),
        "query_v4_image_reference": query_v4_report["image_reference"],
        "query_v4_image_digest": base["manifest_digest"],
        "query_v4_image_id": base["config_digest"],
        "image_reference": image["reference"],
        "image_digest": final["manifest_digest"],
        "image_id": final["config_digest"],
        "query_v4_rootfs_layer_digests": base["layer_digests"],
        "query_v4_rootfs_diff_ids": base["diff_ids"],
        "overlay_layer_digests": final["layer_digests"][base_count:],
        "overlay_diff_ids": final["diff_ids"][base_count:],
        "rootfs_layer_digests": final["layer_digests"],
        "rootfs_diff_ids": final["diff_ids"],
        "overlay_touched_paths": composition["overlay_touched_paths"],
        "python_execution_closure_sha256": composition[
            "python_execution_closure_sha256"
        ],
        "python_execution_closure_entries": composition[
            "python_execution_closure_entries"
        ],
        "runtime_bundle_sha256": composition["runtime_bundle"],
        "runtime_bundle_index_sha256": runtime_index,
        "checks": {
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
            "overlay_layers_canonical_ustar_verified": True,
            "all_overlay_layer_contents_sensitive_free": True,
            "merged_python_execution_closure_frozen": True,
            "runtime_bundle_matches_source_bundle": True,
            "immutable_image_reference_matched": True,
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
    _delegate._validate_schema(
        report,
        ATTESTATION_SCHEMA_PATH,
        "query-v5 image attestation",
    )
    _require_runtime_identity()
    return report


def write_create_only(path: Path, payload: dict[str, Any]) -> None:
    _delegate._write_create_only(path, payload)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--query-v4-external-image-evidence", type=Path, required=True)
    parser.add_argument("--query-v4-source-bundle-archive", type=Path, required=True)
    parser.add_argument("--query-v4-oci-layout-archive", type=Path, required=True)
    parser.add_argument("--query-v4-content-attestation", type=Path, required=True)
    parser.add_argument("--expected-query-v4-source-commit-sha", required=True)
    parser.add_argument("--external-image-evidence", type=Path, required=True)
    parser.add_argument("--source-bundle-archive", type=Path, required=True)
    parser.add_argument("--oci-layout-archive", type=Path, required=True)
    parser.add_argument("--expected-source-commit-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        _require_runtime_identity()
        report = verify_query_v5_image_evidence(
            args.query_v4_external_image_evidence,
            args.query_v4_source_bundle_archive,
            args.query_v4_oci_layout_archive,
            args.query_v4_content_attestation,
            args.expected_query_v4_source_commit_sha,
            args.external_image_evidence,
            args.source_bundle_archive,
            args.oci_layout_archive,
            args.expected_source_commit_sha,
        )
        _require_runtime_identity()
        write_create_only(args.output, report)
        _require_runtime_identity()
    except (QueryV5ImageAttestationError, OSError, ValueError) as exc:
        print(f"query-v5 image attestation failed: {exc}", file=sys.stderr)
        return 2
    print(f"status={report['status']}")
    print(f"image_digest={report['image_digest']}")
    print("build_provenance_verified=false")
    print("registry_provenance_verified=false")
    print("authority_granted=false")
    return 0
