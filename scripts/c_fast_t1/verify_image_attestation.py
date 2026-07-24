#!/usr/bin/env python3
"""Verify externally captured OCI evidence for the C_FAST T1 image."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


SCHEMA_VERSION = "commodity_c_fast_t1_image_attestation_v1"
EVIDENCE_SCHEMA_VERSION = (
    "commodity_c_fast_t1_external_image_evidence_v1"
)
STATUS = "EXTERNAL_BUILD_EVIDENCE_VERIFIED_NOT_IMAGE_BUILT_HERE"
MAX_INPUT_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-t1-external-image-evidence-v1.schema.json"
)
ATTESTATION_SCHEMA_PATH = (
    ROOT
    / "docs/schemas/"
    "commodity-c-fast-t1-image-attestation-v1.schema.json"
)
CONTAINERFILE_PATH = "scripts/c_fast_t1/Containerfile.one-shot"
ENTRYPOINT = [
    "python",
    "-I",
    "/opt/c-fast-t1/scripts/commodity_c_fast_t1_one_shot.py",
]
EXPECTED_DEPENDENCIES = {
    "cryptography": "48.0.0",
    "jsonschema": "4.26.0",
    "psycopg[binary]": "3.2.3",
    "referencing": "0.37.0",
}
EXPECTED_LABELS = {
    "io.vnpy-web-bridge.c-fast-t1.authority-granted": "false",
    "io.vnpy-web-bridge.c-fast-t1.one-shot-runtime": "true",
    "org.opencontainers.image.title": (
        "vnpy-web-bridge C_FAST T1 one-shot runner"
    ),
}
EXPECTED_COPY_SOURCES = (
    "scripts/commodity_c_fast_t1_one_shot.py",
    "scripts/commodity_c_fast_l1_l5_audit.py",
    "docs/schemas/commodity-c-fast-l1-l5-audit-manifest-v2.schema.json",
    "docs/schemas/commodity-c-fast-l1-l5-audit-v1.schema.json",
    "docs/schemas/commodity-c-fast-l1-l5-audit-v2.schema.json",
    "docs/schemas/commodity-c-fast-questdb-readonly-proof-v1.schema.json",
    "docs/schemas/commodity-c-fast-t1-one-shot-release-v1.schema.json",
    "docs/schemas/commodity-c-fast-t1-consume-v1.schema.json",
    "docs/schemas/commodity-c-fast-t1-terminal-seal-v1.schema.json",
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
OCI_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class ImageAttestationError(RuntimeError):
    """An expected image evidence or source-binding violation."""


def _reject_duplicate_object_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ImageAttestationError(
                f"duplicate JSON key is forbidden: {key}"
            )
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise ImageAttestationError(
        f"non-finite JSON value is forbidden: {value}"
    )


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        stat.S_IFMT(value.st_mode),
    )


def _read_regular_file(path: Path, label: str) -> bytes:
    try:
        before_path = path.lstat()
        if stat.S_ISLNK(before_path.st_mode):
            raise ImageAttestationError(f"{label} must not be a symlink")
        if not stat.S_ISREG(before_path.st_mode):
            raise ImageAttestationError(f"{label} must be a regular file")
        if before_path.st_size > MAX_INPUT_BYTES:
            raise ImageAttestationError(
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
    except ImageAttestationError:
        raise
    except OSError as exc:
        raise ImageAttestationError(f"cannot read {label}") from exc

    if (
        len(
            {
                _identity(before_path),
                _identity(opened),
                _identity(closed),
                _identity(after_path),
            }
        )
        != 1
        or first != second
        or len(first) != opened.st_size
    ):
        raise ImageAttestationError(f"{label} changed while being read")
    if len(first) > MAX_INPUT_BYTES:
        raise ImageAttestationError(
            f"{label} exceeds {MAX_INPUT_BYTES} byte limit"
        )
    return first


def _load_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular_file(path, label)
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_object_keys,
            parse_constant=_reject_json_constant,
        )
    except ImageAttestationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ImageAttestationError(
            f"{label} must be one UTF-8 JSON object"
        ) from exc
    if not isinstance(payload, dict):
        raise ImageAttestationError(
            f"{label} must be one UTF-8 JSON object"
        )
    return payload, raw


def _validate_schema(
    payload: dict[str, Any],
    schema_path: Path,
    label: str,
) -> None:
    schema, _ = _load_json(schema_path, f"{label} schema")
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as exc:
        raise ImageAttestationError(f"{label} schema is invalid") from exc
    errors = sorted(
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).iter_errors(payload),
        key=lambda item: list(item.absolute_path),
    )
    if errors:
        first = errors[0]
        location = ".".join(str(item) for item in first.absolute_path)
        raise ImageAttestationError(
            f"{label} schema validation failed at "
            f"{location or '<root>'}: {first.message}"
        )


def _git_output(
    source_root: Path,
    arguments: list[str],
    label: str,
    *,
    limit: int = MAX_INPUT_BYTES,
) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", str(source_root), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise ImageAttestationError(f"cannot execute git for {label}") from exc
    if completed.returncode != 0:
        raise ImageAttestationError(f"git cannot resolve {label}")
    if len(completed.stdout) > limit:
        raise ImageAttestationError(f"{label} exceeds {limit} byte limit")
    return completed.stdout


def _git_archive_sha256(source_root: Path, commit_sha: str) -> str:
    try:
        process = subprocess.Popen(
            [
                "git",
                "-C",
                str(source_root),
                "archive",
                "--format=tar",
                commit_sha,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise ImageAttestationError("cannot execute git archive") from exc
    assert process.stdout is not None
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = process.stdout.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_ARCHIVE_BYTES:
            process.kill()
            process.wait()
            raise ImageAttestationError(
                f"source archive exceeds {MAX_ARCHIVE_BYTES} byte limit"
            )
        digest.update(chunk)
    stderr = process.stderr.read() if process.stderr is not None else b""
    returncode = process.wait()
    if returncode != 0:
        raise ImageAttestationError(
            "git archive failed: "
            + stderr.decode("utf-8", errors="replace").strip()
        )
    return digest.hexdigest()


def _git_blob(
    source_root: Path,
    commit_sha: str,
    relative_path: str,
) -> bytes:
    tree_entry = _git_output(
        source_root,
        ["ls-tree", commit_sha, "--", relative_path],
        f"tree entry {commit_sha}:{relative_path}",
    )
    try:
        metadata, separator, path_bytes = tree_entry.rstrip(
            b"\n"
        ).partition(b"\t")
        mode, object_type, _object_id = metadata.decode("ascii").split()
        stored_path = path_bytes.decode("utf-8")
    except (UnicodeDecodeError, ValueError) as exc:
        raise ImageAttestationError(
            f"source tree entry is malformed: {relative_path}"
        ) from exc
    if (
        separator != b"\t"
        or mode not in {"100644", "100755"}
        or object_type != "blob"
        or stored_path != relative_path
    ):
        raise ImageAttestationError(
            f"source path must be an exact regular blob: {relative_path}"
        )
    return _git_output(
        source_root,
        ["show", f"{commit_sha}:{relative_path}"],
        f"{commit_sha}:{relative_path}",
    )


def _parse_containerfile(
    raw: bytes,
) -> tuple[str, dict[str, str]]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ImageAttestationError(
            "one-shot Containerfile must be UTF-8"
        ) from exc
    first_line = text.splitlines()[0] if text.splitlines() else ""
    prefix = "FROM python:3.12-slim@"
    if not first_line.startswith(prefix):
        raise ImageAttestationError(
            "one-shot Containerfile base image is not frozen"
        )
    base_digest = first_line.removeprefix(prefix)
    if OCI_DIGEST_RE.fullmatch(base_digest) is None:
        raise ImageAttestationError(
            "one-shot Containerfile base image digest is invalid"
        )

    copy_map: dict[str, str] = {}
    for line in text.splitlines():
        if not line.startswith("COPY "):
            continue
        parts = line.split()
        if len(parts) != 3:
            raise ImageAttestationError(
                "one-shot Containerfile COPY instruction is malformed"
            )
        source, target = parts[1:]
        if source in copy_map:
            raise ImageAttestationError(
                "one-shot Containerfile has duplicate COPY source"
            )
        copy_map[source] = target
    if tuple(copy_map) != EXPECTED_COPY_SOURCES:
        raise ImageAttestationError(
            "one-shot Containerfile COPY allowlist drifted"
        )
    for dependency, version in EXPECTED_DEPENDENCIES.items():
        if text.count(f'"{dependency}=={version}"') != 1:
            raise ImageAttestationError(
                f"dependency pin drifted: {dependency}"
            )
    return base_digest, copy_map


def _image_path(target: str) -> str:
    normalized = target.removeprefix("./")
    return f"/opt/c-fast-t1/{normalized}"


def derive_source_facts(
    source_root: Path,
    commit_sha: str,
) -> dict[str, Any]:
    if COMMIT_RE.fullmatch(commit_sha) is None:
        raise ImageAttestationError(
            "expected source commit must be 40 lowercase hex characters"
        )
    resolved = _git_output(
        source_root,
        ["rev-parse", f"{commit_sha}^{{commit}}"],
        "expected source commit",
    ).decode("ascii", errors="strict").strip()
    if resolved != commit_sha:
        raise ImageAttestationError(
            "expected source commit did not resolve exactly"
        )
    containerfile_raw = _git_blob(
        source_root,
        commit_sha,
        CONTAINERFILE_PATH,
    )
    base_digest, copy_map = _parse_containerfile(containerfile_raw)
    bundle_files: dict[str, str] = {}
    for source, target in copy_map.items():
        bundle_files[_image_path(target)] = hashlib.sha256(
            _git_blob(source_root, commit_sha, source)
        ).hexdigest()
    return {
        "source_archive_sha256": _git_archive_sha256(
            source_root,
            commit_sha,
        ),
        "containerfile_sha256": hashlib.sha256(
            containerfile_raw
        ).hexdigest(),
        "base_image_digest": base_digest,
        "bundle_files": bundle_files,
    }


def _require_exact(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        raise ImageAttestationError(f"{label} does not match exact source")


def verify_image_evidence(
    evidence_path: Path,
    source_root: Path,
    expected_source_commit_sha: str,
) -> dict[str, Any]:
    evidence, evidence_raw = _load_json(
        evidence_path,
        "external image evidence",
    )
    _validate_schema(
        evidence,
        EVIDENCE_SCHEMA_PATH,
        "external image evidence",
    )
    source_facts = derive_source_facts(
        source_root,
        expected_source_commit_sha,
    )

    _require_exact(
        evidence["source_commit_sha"],
        expected_source_commit_sha,
        "source commit",
    )
    _require_exact(
        evidence["source_archive_sha256"],
        source_facts["source_archive_sha256"],
        "source archive digest",
    )
    build = evidence["build"]
    image = evidence["image"]
    config = image["config"]
    _require_exact(
        build["containerfile_sha256"],
        source_facts["containerfile_sha256"],
        "Containerfile digest",
    )
    _require_exact(
        build["base_image_digest"],
        source_facts["base_image_digest"],
        "base image digest",
    )
    _require_exact(
        build["direct_dependencies"],
        EXPECTED_DEPENDENCIES,
        "direct dependencies",
    )
    _require_exact(
        image["bundle_files"],
        source_facts["bundle_files"],
        "runtime bundle hashes",
    )
    _require_exact(
        config["labels"],
        {
            **EXPECTED_LABELS,
            "org.opencontainers.image.revision": (
                expected_source_commit_sha
            ),
        },
        "OCI labels",
    )
    _require_exact(config["user"], "65532:65532", "OCI user")
    _require_exact(
        config["working_dir"],
        "/opt/c-fast-t1",
        "OCI working directory",
    )
    _require_exact(config["entrypoint"], ENTRYPOINT, "OCI entrypoint")
    _require_exact(
        config["relevant_environment"],
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1",
        },
        "OCI relevant environment",
    )
    _require_exact(
        image["forbidden_path_matches"],
        [],
        "forbidden path scan",
    )
    _require_exact(
        image["unexpected_bundle_paths"],
        [],
        "unexpected bundle path scan",
    )
    _require_exact(
        image["signer_or_private_key_paths"],
        [],
        "signer/private-key path scan",
    )
    reference_digest = image["reference"].rsplit("@", maxsplit=1)[-1]
    _require_exact(
        reference_digest,
        image["digest"],
        "immutable image reference digest",
    )
    if len(set(image["rootfs_layer_digests"])) != len(
        image["rootfs_layer_digests"]
    ):
        raise ImageAttestationError(
            "rootfs layer digests must be unique and ordered"
        )

    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "source_commit_sha": expected_source_commit_sha,
        "source_archive_sha256": source_facts[
            "source_archive_sha256"
        ],
        "external_evidence_sha256": hashlib.sha256(
            evidence_raw
        ).hexdigest(),
        "evidence_captured_at": evidence["captured_at"],
        "containerfile_sha256": source_facts[
            "containerfile_sha256"
        ],
        "base_image_digest": source_facts["base_image_digest"],
        "image_reference": image["reference"],
        "image_digest": image["digest"],
        "image_id": image["id"],
        "image_export_sha256": image["export_sha256"],
        "rootfs_layer_digests": image["rootfs_layer_digests"],
        "runtime_bundle_sha256": source_facts["bundle_files"],
        "checks": {
            "exact_git_commit_resolved": True,
            "git_archive_digest_matched": True,
            "containerfile_digest_matched": True,
            "base_image_digest_matched": True,
            "direct_dependencies_matched": True,
            "immutable_image_reference_matched": True,
            "oci_revision_matched": True,
            "non_root_entrypoint_matched": True,
            "runtime_bundle_hashes_matched": True,
            "forbidden_and_signer_paths_absent": True,
        },
        "image_built_here": False,
        "authority_granted": False,
        "deployment_mutation_authorized": False,
        "production_query_authorized": False,
        "execution_quality_collection_authorized": False,
        "order_submission_authorized": False,
        "position_mutation_authorized": False,
        "dispatch_authorized": False,
        "database_mutation_authorized": False,
        "dynamic_selection_allowed": False,
        "database_mutations": 0,
        "orders_sent": 0,
        "positions_modified": 0,
        "dispatch_changed": False,
    }
    _validate_schema(
        report,
        ATTESTATION_SCHEMA_PATH,
        "image attestation",
    )
    return report


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
        raise ImageAttestationError(
            "cannot create image attestation output"
        ) from exc


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument(
        "--source-root",
        type=Path,
        default=ROOT,
    )
    parser.add_argument(
        "--expected-source-commit-sha",
        required=True,
    )
    parser.add_argument("--json-output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        report = verify_image_evidence(
            args.evidence.expanduser().resolve(),
            args.source_root.expanduser().resolve(),
            args.expected_source_commit_sha,
        )
        if args.json_output is not None:
            _write_create_only(
                args.json_output.expanduser().resolve(),
                report,
            )
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
        return 0
    except (ImageAttestationError, OSError, UnicodeError) as exc:
        print(f"image attestation failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
