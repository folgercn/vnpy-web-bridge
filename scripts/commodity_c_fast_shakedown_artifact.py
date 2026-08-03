#!/usr/bin/env python3
"""Produce, sign, verify, and create-only install one C_FAST SimNow artifact.

The producer consumes only a human-confirmed Research bundle.  It has no
account, RPC, order, position, or gateway dependency.  Control authority is
added later with a distinct Ed25519 key.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import errno
import hashlib
import json
import os
import stat
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))

from app.schemas.commodity_c_fast_shadow import (  # noqa: E402
    CommodityCFastShakedownSnapshotDTO,
)
from app.core.config import Settings  # noqa: E402
from app.services.commodity_c_fast_shadow import (  # noqa: E402
    CommodityCFastShadowService,
)
from app.services.commodity_c_fast_shadow_common import (  # noqa: E402
    canonical_json,
    formula_target_binding_sha256,
    shakedown_research_payload,
    unsigned_snapshot_payload,
)
from commodity_c_fast_shadow_sign import (  # noqa: E402
    PLACEHOLDER_SIGNATURE,
    load_private_key,
)

INPUT_KEYS = {
    "schema_version",
    "human_confirmed",
    "reviewer_assertion",
    "evidence",
    "snapshot",
}
EVIDENCE_KEYS = {"name", "kind", "sha256"}
REQUIRED_EVIDENCE_KINDS = {
    "research_manifest",
    "allocation",
    "daily_roll",
    "reference_price",
}
PROTECTED_SNAPSHOT_KEYS = {
    "schema_version",
    "mode",
    "execution_lane",
    "frequency",
    "source_is_month_last_official_day",
    "execution_is_next_cross_month_official_day",
    "input_cutoff_after_source_close",
    "calendar_alignment",
    "allocator_output_validation",
    "daily_roll_alignment",
    "formula_target_binding_sha256",
    "research_signature",
    "control_acceptance_id",
    "execution_permit_id",
    "accepted_at_utc",
    "expires_at_utc",
    "account_sha256",
    "max_selected_products",
    "max_child_order_lots",
    "countable_forward",
    "control_signer_key_id",
    "signature",
}
INSTALL_SNAPSHOT_NAME = "snapshot.json"
INSTALL_CHECKSUM_NAME = "snapshot.json.sha256"
INSTALL_FILE_NAMES = {INSTALL_SNAPSHOT_NAME, INSTALL_CHECKSUM_NAME}
MAX_INSTALLED_SNAPSHOT_BYTES = 2 * 1024 * 1024


class SnapshotInstallInvalidError(ValueError):
    """The published install unit is incomplete or fails integrity checks."""


def read_object(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("input must contain one JSON object")
    return raw


def write_private_create(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    fd = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
    except Exception:
        raise
    finally:
        temporary.unlink(missing_ok=True)


def _directory_open_flags() -> int:
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise OSError(
            errno.ENOTSUP,
            "directory descriptor custody is unsupported",
        )
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def _stat_identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _require_private_owned_directory(
    value: os.stat_result,
    *,
    label: str,
) -> None:
    if (
        not stat.S_ISDIR(value.st_mode)
        or value.st_uid != os.geteuid()
        or value.st_mode & 0o077
    ):
        raise SnapshotInstallInvalidError(
            f"{label} must be an owner-controlled private directory"
        )


def _entry_lstat(directory_fd: int, name: str) -> os.stat_result:
    return os.stat(
        name,
        dir_fd=directory_fd,
        follow_symlinks=False,
    )


def _assert_path_identity(
    path: Path,
    expected: tuple[int, int],
    *,
    label: str,
) -> None:
    try:
        current = os.lstat(path)
    except OSError as exc:
        raise SnapshotInstallInvalidError(
            f"{label} path changed during installation"
        ) from exc
    _require_private_owned_directory(current, label=label)
    if _stat_identity(current) != expected:
        raise SnapshotInstallInvalidError(
            f"{label} path changed during installation"
        )


def _open_private_parent(path: Path) -> tuple[int, tuple[int, int]]:
    try:
        fd = os.open(path, _directory_open_flags())
    except OSError as exc:
        raise SnapshotInstallInvalidError(
            "snapshot installation parent must pre-exist as a private "
            "non-symlink directory"
        ) from exc
    try:
        opened = os.fstat(fd)
        _require_private_owned_directory(
            opened,
            label="snapshot installation parent",
        )
        identity = _stat_identity(opened)
        _assert_path_identity(
            path,
            identity,
            label="snapshot installation parent",
        )
        return fd, identity
    except Exception:
        os.close(fd)
        raise


def atomic_rename_no_replace(
    parent_fd: int,
    source_name: str,
    destination_name: str,
) -> None:
    """Publish one directory within a pinned parent without replacement."""
    libc = ctypes.CDLL(None, use_errno=True)
    source_raw = os.fsencode(source_name)
    destination_raw = os.fsencode(destination_name)
    if sys.platform.startswith("linux"):
        rename = getattr(libc, "renameat2", None)
        if rename is None:
            raise OSError(
                errno.ENOTSUP,
                "renameat2(RENAME_NOREPLACE) is unavailable",
                destination_name,
            )
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        result = rename(
            parent_fd,
            source_raw,
            parent_fd,
            destination_raw,
            1,  # RENAME_NOREPLACE
        )
    elif sys.platform == "darwin":
        rename = getattr(libc, "renameatx_np", None)
        if rename is None:
            raise OSError(
                errno.ENOTSUP,
                "renameatx_np(RENAME_EXCL) is unavailable",
                destination_name,
            )
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        result = rename(
            parent_fd,
            source_raw,
            parent_fd,
            destination_raw,
            0x00000004,  # RENAME_EXCL
        )
    else:
        raise OSError(
            errno.ENOTSUP,
            "atomic no-replace directory rename is unsupported",
            destination_name,
        )
    if result:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise FileExistsError(
                error,
                "snapshot installation destination already exists",
                destination_name,
            )
        raise OSError(
            error,
            os.strerror(error),
            destination_name,
        )


def _write_private_file(
    directory_fd: int,
    name: str,
    payload: bytes,
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= os.O_NOFOLLOW
    fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            os.unlink(name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        raise


def _cleanup_staging_if_unpublished(
    parent_fd: int,
    staging_name: str,
    staging_identity: tuple[int, int] | None,
) -> None:
    """Remove only the still-named staging directory that we created."""
    if staging_identity is None:
        return
    try:
        staging_fd = os.open(
            staging_name,
            _directory_open_flags(),
            dir_fd=parent_fd,
        )
    except OSError:
        # The no-replace rename may have committed before its caller observed
        # an exception.  Never follow the old directory fd into destination.
        os.fsync(parent_fd)
        return
    remove_named_staging = False
    try:
        opened = os.fstat(staging_fd)
        try:
            named = _entry_lstat(parent_fd, staging_name)
        except OSError:
            return
        if (
            _stat_identity(opened) != staging_identity
            or _stat_identity(named) != staging_identity
        ):
            return
        remove_named_staging = True
        for child in INSTALL_FILE_NAMES:
            try:
                os.unlink(child, dir_fd=staging_fd)
            except FileNotFoundError:
                pass
    finally:
        os.close(staging_fd)
    if remove_named_staging:
        try:
            os.rmdir(staging_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.fsync(parent_fd)


def _read_private_regular_file(
    directory_fd: int,
    name: str,
    *,
    max_bytes: int,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(name, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise SnapshotInstallInvalidError(
            f"installed {name} is missing or unsafe"
        ) from exc
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_mode & 0o077
            or before.st_size > max_bytes
        ):
            raise SnapshotInstallInvalidError(
                f"installed {name} is not a private regular file"
            )
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(fd)

        def identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
            return (
                value.st_dev,
                value.st_ino,
                value.st_size,
                value.st_mtime_ns,
                value.st_ctime_ns,
            )

        if len(raw) > max_bytes or identity(before) != identity(after):
            raise SnapshotInstallInvalidError(
                f"installed {name} changed during validation"
            )
        return raw
    finally:
        os.close(fd)


def _validate_snapshot_installation_at(
    parent_fd: int,
    destination_name: str,
) -> str:
    try:
        directory_fd = os.open(
            destination_name,
            _directory_open_flags(),
            dir_fd=parent_fd,
        )
    except OSError as exc:
        raise SnapshotInstallInvalidError(
            "snapshot installation must be a directory"
        ) from exc
    try:
        before = os.fstat(directory_fd)
        _require_private_owned_directory(
            before,
            label="snapshot installation directory",
        )
        try:
            path_before = _entry_lstat(parent_fd, destination_name)
        except OSError as exc:
            raise SnapshotInstallInvalidError(
                "snapshot installation path changed during validation"
            ) from exc
        if (
            not stat.S_ISDIR(path_before.st_mode)
            or (path_before.st_dev, path_before.st_ino)
            != (before.st_dev, before.st_ino)
        ):
            raise SnapshotInstallInvalidError(
                "snapshot installation path changed during validation"
            )
        if set(os.listdir(directory_fd)) != INSTALL_FILE_NAMES:
            raise SnapshotInstallInvalidError(
                "snapshot installation files are not exact"
            )
        snapshot_raw = _read_private_regular_file(
            directory_fd,
            INSTALL_SNAPSHOT_NAME,
            max_bytes=MAX_INSTALLED_SNAPSHOT_BYTES,
        )
        checksum_raw = _read_private_regular_file(
            directory_fd,
            INSTALL_CHECKSUM_NAME,
            max_bytes=65,
        )
        after = os.fstat(directory_fd)
        try:
            path_after = _entry_lstat(parent_fd, destination_name)
        except OSError as exc:
            raise SnapshotInstallInvalidError(
                "snapshot installation path changed during validation"
            ) from exc
        if (
            before.st_dev,
            before.st_ino,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or (
            not stat.S_ISDIR(path_after.st_mode)
            or (path_after.st_dev, path_after.st_ino)
            != (after.st_dev, after.st_ino)
        ):
            raise SnapshotInstallInvalidError(
                "snapshot installation changed during validation"
            )
    finally:
        os.close(directory_fd)

    if not snapshot_raw.endswith(b"\n") or snapshot_raw.endswith(b"\n\n"):
        raise SnapshotInstallInvalidError(
            "installed snapshot is not canonical JSON"
        )
    canonical = snapshot_raw[:-1]
    try:
        parsed = json.loads(canonical)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SnapshotInstallInvalidError(
            "installed snapshot is not valid JSON"
        ) from exc
    if not isinstance(parsed, dict) or canonical_json(parsed) != canonical:
        raise SnapshotInstallInvalidError(
            "installed snapshot is not canonical JSON"
        )
    digest = hashlib.sha256(canonical).hexdigest()
    if checksum_raw != digest.encode("ascii") + b"\n":
        raise SnapshotInstallInvalidError(
            "installed snapshot checksum mismatch"
        )
    return digest


def validate_snapshot_installation(destination: Path) -> str:
    """Validate one snapshot/checksum directory under pinned custody."""
    if destination.name in {"", ".", ".."}:
        raise SnapshotInstallInvalidError(
            "snapshot installation destination is invalid"
        )
    parent_fd, parent_identity = _open_private_parent(destination.parent)
    try:
        digest = _validate_snapshot_installation_at(
            parent_fd,
            destination.name,
        )
        _assert_path_identity(
            destination.parent,
            parent_identity,
            label="snapshot installation parent",
        )
        return digest
    finally:
        os.close(parent_fd)


def install_snapshot_bundle(destination: Path, canonical: bytes) -> str:
    """Create-only publish snapshot and checksum as one directory rename."""
    if destination.name in {"", ".", ".."}:
        raise ValueError("snapshot installation destination is invalid")
    try:
        parsed = json.loads(canonical)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("snapshot installation input is not JSON") from exc
    if not isinstance(parsed, dict) or canonical_json(parsed) != canonical:
        raise ValueError("snapshot installation input is not canonical JSON")
    if len(canonical) + 1 > MAX_INSTALLED_SNAPSHOT_BYTES:
        raise ValueError("snapshot installation input exceeds 2 MiB")

    expected_digest = hashlib.sha256(canonical).hexdigest()
    staging_name = (
        f".{destination.name}.staging-{uuid.uuid4().hex}"
    )
    parent_fd, parent_identity = _open_private_parent(destination.parent)
    staging_fd: int | None = None
    staging_created = False
    staging_identity: tuple[int, int] | None = None
    published = False
    try:
        try:
            _entry_lstat(parent_fd, destination.name)
        except FileNotFoundError:
            pass
        else:
            _validate_snapshot_installation_at(
                parent_fd,
                destination.name,
            )
            raise FileExistsError(
                f"snapshot installation already exists: {destination}"
            )

        os.mkdir(staging_name, mode=0o700, dir_fd=parent_fd)
        staging_created = True
        staging_fd = os.open(
            staging_name,
            _directory_open_flags(),
            dir_fd=parent_fd,
        )
        staging_stat = os.fstat(staging_fd)
        staging_identity = _stat_identity(staging_stat)
        _require_private_owned_directory(
            staging_stat,
            label="snapshot installation staging directory",
        )
        if _stat_identity(
            _entry_lstat(parent_fd, staging_name)
        ) != staging_identity:
            raise SnapshotInstallInvalidError(
                "snapshot installation staging path changed"
            )

        _write_private_file(
            staging_fd,
            INSTALL_SNAPSHOT_NAME,
            canonical + b"\n",
        )
        _write_private_file(
            staging_fd,
            INSTALL_CHECKSUM_NAME,
            expected_digest.encode("ascii") + b"\n",
        )
        os.fsync(staging_fd)
        if _stat_identity(
            _entry_lstat(parent_fd, staging_name)
        ) != staging_identity:
            raise SnapshotInstallInvalidError(
                "snapshot installation staging path changed"
            )
        closing_staging_fd = staging_fd
        staging_fd = None
        os.close(closing_staging_fd)
        _assert_path_identity(
            destination.parent,
            parent_identity,
            label="snapshot installation parent",
        )
        atomic_rename_no_replace(
            parent_fd,
            staging_name,
            destination.name,
        )
        published = True
        os.fsync(parent_fd)
        _assert_path_identity(
            destination.parent,
            parent_identity,
            label="snapshot installation parent",
        )
        installed_digest = _validate_snapshot_installation_at(
            parent_fd,
            destination.name,
        )
        if installed_digest != expected_digest:
            raise SnapshotInstallInvalidError(
                "published snapshot installation changed unexpectedly"
            )
        _assert_path_identity(
            destination.parent,
            parent_identity,
            label="snapshot installation parent",
        )
        return installed_digest
    finally:
        if staging_fd is not None:
            os.close(staging_fd)
        if not published and staging_created:
            _cleanup_staging_if_unpublished(
                parent_fd,
                staging_name,
                staging_identity,
            )
        os.close(parent_fd)


def dummy_control(core: dict[str, Any]) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    return {
        **core,
        "research_signature": PLACEHOLDER_SIGNATURE,
        "control_acceptance_id": "cfast-accept-placeholder1",
        "execution_permit_id": "cfast-permit-placeholder1",
        "accepted_at_utc": now.isoformat(),
        "expires_at_utc": (now + timedelta(hours=1)).isoformat(),
        "account_sha256": "0" * 64,
        "max_selected_products": 1,
        "max_child_order_lots": 0,
        "countable_forward": False,
        "control_signer_key_id": "placeholder-control",
        "signature": PLACEHOLDER_SIGNATURE,
    }


def produce(bundle: dict[str, Any]) -> dict[str, Any]:
    if set(bundle) != INPUT_KEYS:
        raise ValueError("research input bundle fields are not exact")
    if (
        bundle["schema_version"]
        != "commodity_c_fast_simnow_research_input_v1"
        or bundle["human_confirmed"] is not True
        or bundle["reviewer_assertion"]
        != "REAL_RESEARCH_INPUT_NOT_FIXTURE_NOT_EXECUTION_DERIVED"
    ):
        raise ValueError("research input authority assertion is invalid")
    evidence = bundle["evidence"]
    if (
        not isinstance(evidence, list)
        or not evidence
        or any(
            not isinstance(row, dict)
            or set(row) != EVIDENCE_KEYS
            or not isinstance(row["name"], str)
            or not row["name"]
            or row["kind"] not in REQUIRED_EVIDENCE_KINDS
            or not isinstance(row["sha256"], str)
            or len(row["sha256"]) != 64
            or any(ch not in "0123456789abcdef" for ch in row["sha256"])
            for row in evidence
        )
    ):
        raise ValueError("research evidence list is invalid")
    if len({row["name"] for row in evidence}) != len(evidence):
        raise ValueError("research evidence names must be unique")
    evidence_by_kind = {row["kind"]: row for row in evidence}
    if (
        len(evidence_by_kind) != len(evidence)
        or set(evidence_by_kind) != REQUIRED_EVIDENCE_KINDS
    ):
        raise ValueError("research evidence kinds must be exact and unique")
    snapshot = bundle["snapshot"]
    if not isinstance(snapshot, dict) or set(snapshot) & PROTECTED_SNAPSHOT_KEYS:
        raise ValueError("snapshot contains producer/control-owned fields")
    bindings = snapshot.get("research_bindings")
    if not isinstance(bindings, dict):
        raise ValueError("research_bindings is required")
    bindings = dict(bindings)
    for key in (
        "snapshot_producer_status",
        "producer_sha256",
        "input_bundle_sha256",
    ):
        if key in bindings:
            raise ValueError(f"research input may not set {key}")
    expected_evidence_hashes = {
        "research_manifest": bindings.get("research_manifest_sha256"),
        "allocation": bindings.get("allocation_evidence_sha256"),
        "daily_roll": bindings.get("daily_roll_evidence_sha256"),
    }
    if any(
        evidence_by_kind[kind]["sha256"] != expected
        for kind, expected in expected_evidence_hashes.items()
    ):
        raise ValueError("research evidence hash does not match bindings")
    targets = snapshot.get("targets")
    reference_hashes = {
        row.get("reference_price_source_sha256")
        for row in targets
        if isinstance(row, dict)
    } if isinstance(targets, list) else set()
    if (
        len(reference_hashes) != 1
        or evidence_by_kind["reference_price"]["sha256"]
        not in reference_hashes
    ):
        raise ValueError(
            "reference-price evidence does not bind every target"
        )
    input_hash = hashlib.sha256(canonical_json(bundle)).hexdigest()
    core = {
        **snapshot,
        "schema_version": "commodity_c_fast_simnow_shakedown_snapshot_v1",
        "mode": "simnow_shakedown",
        "execution_lane": "simnow_shakedown",
        "frequency": "ONE_SHOT",
        "source_is_month_last_official_day": False,
        "execution_is_next_cross_month_official_day": False,
        "input_cutoff_after_source_close": False,
        "calendar_alignment": "HUMAN_CONFIRMED_RESEARCH_BUNDLE",
        "allocator_output_validation":
        "PRODUCER_RECOMPUTED_AND_SIGNER_CONFIRMED",
        "daily_roll_alignment": "HUMAN_CONFIRMED_PIT_EXACT_CONTRACT",
        "research_bindings": {
            **bindings,
            "snapshot_producer_status":
            "IMPLEMENTED_HUMAN_CONFIRMED_BUNDLE_V1",
            "producer_sha256": hashlib.sha256(
                Path(__file__).read_bytes()
            ).hexdigest(),
            "input_bundle_sha256": input_hash,
        },
        "formula_target_binding_sha256": "0" * 64,
    }
    draft = CommodityCFastShakedownSnapshotDTO.model_validate(
        dummy_control(core)
    )
    CommodityCFastShadowService(
        settings=Settings()
    )._verify_targets(draft)
    core["formula_target_binding_sha256"] = (
        formula_target_binding_sha256(draft)
    )
    CommodityCFastShakedownSnapshotDTO.model_validate(dummy_control(core))
    return core


def load_public_key(path: Path) -> Ed25519PublicKey:
    raw = path.read_bytes().strip()
    if raw.startswith(b"-----BEGIN"):
        key = serialization.load_pem_public_key(raw)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("public key is not Ed25519")
        return key
    decoded = base64.b64decode(raw, validate=True)
    if len(decoded) != 32:
        raise ValueError("public key must contain exactly 32 bytes")
    return Ed25519PublicKey.from_public_bytes(decoded)


def public_key_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def sign_research(
    core: dict[str, Any], private_key: Ed25519PrivateKey
) -> dict[str, Any]:
    draft = CommodityCFastShakedownSnapshotDTO.model_validate(
        dummy_control(core)
    )
    CommodityCFastShadowService(
        settings=Settings()
    )._verify_targets(draft)
    if formula_target_binding_sha256(draft) != draft.formula_target_binding_sha256:
        raise ValueError("formula/target binding mismatch")
    signature = private_key.sign(canonical_json(shakedown_research_payload(draft)))
    return {**core, "research_signature": base64.b64encode(signature).decode()}


def issue_permit(
    research: dict[str, Any],
    *,
    research_public_key: Ed25519PublicKey,
    control_private_key: Ed25519PrivateKey,
    acceptance_id: str,
    permit_id: str,
    account_sha256: str,
    accepted_at: str,
    expires_at: str,
    max_selected_products: int,
    control_signer_key_id: str,
) -> dict[str, Any]:
    control_public_key = control_private_key.public_key()
    if public_key_bytes(research_public_key) == public_key_bytes(
        control_public_key
    ):
        raise ValueError("Research and Control keys must be distinct")
    payload = {
        **research,
        "control_acceptance_id": acceptance_id,
        "execution_permit_id": permit_id,
        "accepted_at_utc": accepted_at,
        "expires_at_utc": expires_at,
        "account_sha256": account_sha256,
        "max_selected_products": max_selected_products,
        "max_child_order_lots": 0,
        "countable_forward": False,
        "control_signer_key_id": control_signer_key_id,
        "signature": PLACEHOLDER_SIGNATURE,
    }
    snapshot = CommodityCFastShakedownSnapshotDTO.model_validate(payload)
    research_public_key.verify(
        base64.b64decode(snapshot.research_signature, validate=True),
        canonical_json(shakedown_research_payload(snapshot)),
    )
    payload["signature"] = base64.b64encode(
        control_private_key.sign(
            canonical_json(unsigned_snapshot_payload(snapshot))
        )
    ).decode()
    return CommodityCFastShakedownSnapshotDTO.model_validate(payload).model_dump(
        mode="json"
    )


def verify(
    payload: dict[str, Any],
    research_key: Ed25519PublicKey,
    control_key: Ed25519PublicKey,
) -> CommodityCFastShakedownSnapshotDTO:
    if public_key_bytes(research_key) == public_key_bytes(control_key):
        raise ValueError("Research and Control keys must be distinct")
    snapshot = CommodityCFastShakedownSnapshotDTO.model_validate(payload)
    if formula_target_binding_sha256(snapshot) != snapshot.formula_target_binding_sha256:
        raise ValueError("formula/target binding mismatch")
    research_key.verify(
        base64.b64decode(snapshot.research_signature, validate=True),
        canonical_json(shakedown_research_payload(snapshot)),
    )
    control_key.verify(
        base64.b64decode(snapshot.signature, validate=True),
        canonical_json(unsigned_snapshot_payload(snapshot)),
    )
    now = datetime.now(timezone.utc)
    checker = CommodityCFastShadowService(
        settings=Settings(
            commodity_c_fast_simnow_account_hashes=snapshot.account_sha256
        ),
        clock=lambda: now,
    )
    checker._verify_shakedown_timing(snapshot)
    checker._verify_targets(snapshot)
    return snapshot


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("produce", "sign-research", "issue-permit", "verify", "install"):
        command = commands.add_parser(name)
        command.add_argument("--input", required=True, type=Path)
        if name in {"produce", "sign-research", "issue-permit"}:
            command.add_argument("--output", required=True, type=Path)
        if name == "sign-research":
            command.add_argument("--research-private-key-file", required=True, type=Path)
        if name == "issue-permit":
            command.add_argument("--research-public-key-file", required=True, type=Path)
            command.add_argument("--control-private-key-file", required=True, type=Path)
            command.add_argument("--acceptance-id", required=True)
            command.add_argument("--permit-id", required=True)
            command.add_argument("--account-sha256", required=True)
            command.add_argument("--accepted-at-utc", required=True)
            command.add_argument("--expires-at-utc", required=True)
            command.add_argument("--max-selected-products", type=int, default=1)
            command.add_argument("--control-signer-key-id", required=True)
        if name in {"verify", "install"}:
            command.add_argument("--research-public-key-file", required=True, type=Path)
            command.add_argument("--control-public-key-file", required=True, type=Path)
        if name == "install":
            command.add_argument("--destination", required=True, type=Path)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        payload = read_object(args.input)
        if args.command == "produce":
            output = produce(payload)
        elif args.command == "sign-research":
            output = sign_research(
                payload, load_private_key(args.research_private_key_file)
            )
        elif args.command == "issue-permit":
            output = issue_permit(
                payload,
                research_public_key=load_public_key(args.research_public_key_file),
                control_private_key=load_private_key(args.control_private_key_file),
                acceptance_id=args.acceptance_id,
                permit_id=args.permit_id,
                account_sha256=args.account_sha256,
                accepted_at=args.accepted_at_utc,
                expires_at=args.expires_at_utc,
                max_selected_products=args.max_selected_products,
                control_signer_key_id=args.control_signer_key_id,
            )
        else:
            snapshot = verify(
                payload,
                load_public_key(args.research_public_key_file),
                load_public_key(args.control_public_key_file),
            )
            canonical = canonical_json(snapshot.model_dump(mode="json"))
            if args.command == "install":
                install_snapshot_bundle(args.destination, canonical)
            print(hashlib.sha256(canonical).hexdigest())
            return 0
        write_private_create(
            args.output,
            json.dumps(output, ensure_ascii=False, indent=2).encode() + b"\n",
        )
        return 0
    except Exception as exc:
        print(f"{args.command} failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
