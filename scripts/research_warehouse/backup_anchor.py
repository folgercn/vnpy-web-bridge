"""Signed append-only backup anchors with externally pinned chain heads."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .backup_contracts import (
    AUTHORITY_FIELDS,
    BACKUP_ANCHOR_SCHEMA,
    BACKUP_PURPOSE,
    RebuildFingerprint,
    WarehouseSnapshot,
    false_authority,
    require_identifier,
    require_sha256,
)
from .backup_custody import (
    ANCHOR_FILENAME_PATTERN,
    BackupPaths,
)
from .canonical import canonical_json, canonical_json_line, parse_json_strict, sha256
from .errors import RegistryError
from .held_custody import (
    HeldCustodyRoot,
    held_custody_lock,
    hold_custody_root,
    scan_held_snapshot,
)
from .signing import (
    load_private_key,
    load_public_key,
    public_key_sha256,
    sign_payload,
    verify_payload,
)
from .timeutil import format_utc, parse_utc, require_utc

ANCHOR_KEYS = {
    "schema_version",
    "anchor_id",
    "purpose",
    "sequence",
    "created_at",
    "parent_anchor_raw_sha256",
    "source_custody_identity",
    "backup_custody_identity",
    "snapshot",
    "rebuild",
    "authority",
    "signer_key_id",
    "signer_public_key_sha256",
    "signature",
}


@dataclass(frozen=True)
class VerifiedBackupAnchor:
    path: Path
    raw_sha256: str
    anchor_id: str
    sequence: int
    created_at: datetime
    parent_anchor_raw_sha256: str | None
    source_custody_identity: str
    backup_custody_identity: str
    snapshot: WarehouseSnapshot
    rebuild: RebuildFingerprint
    payload: dict[str, Any]


def _anchor_id(payload: dict[str, Any]) -> str:
    value = dict(payload)
    value["anchor_id"] = ""
    return "backup-" + sha256(canonical_json(value))


def _validate_payload(
    payload: object,
    *,
    public_key_path: Path,
    expected_public_key_sha256: str,
) -> tuple[dict[str, Any], WarehouseSnapshot, RebuildFingerprint]:
    if (
        not isinstance(payload, dict)
        or set(payload) != ANCHOR_KEYS
        or payload["schema_version"] != BACKUP_ANCHOR_SCHEMA
        or payload["purpose"] != BACKUP_PURPOSE
    ):
        raise RegistryError("backup anchor contract mismatch")
    if payload["authority"] != false_authority() or set(
        payload["authority"]
    ) != set(AUTHORITY_FIELDS):
        raise RegistryError("backup anchor grants authority")
    if (
        not isinstance(payload["sequence"], int)
        or isinstance(payload["sequence"], bool)
        or payload["sequence"] < 1
    ):
        raise RegistryError("backup anchor sequence is invalid")
    parse_utc(payload["created_at"], "backup anchor created_at")
    parent = payload["parent_anchor_raw_sha256"]
    if parent is not None:
        require_sha256(parent, "backup parent anchor")
    require_sha256(payload["source_custody_identity"], "source custody identity")
    require_sha256(payload["backup_custody_identity"], "backup custody identity")
    signer_id = require_identifier(payload["signer_key_id"], "backup signer key ID")
    del signer_id
    public_key = load_public_key(public_key_path)
    expected_public_key_sha256 = require_sha256(
        expected_public_key_sha256,
        "trusted backup signer public key",
    )
    if (
        public_key_sha256(public_key) != expected_public_key_sha256
        or payload["signer_public_key_sha256"] != expected_public_key_sha256
    ):
        raise RegistryError("backup signer public key pin mismatch")
    unsigned = verify_payload(payload, public_key)
    if payload["anchor_id"] != _anchor_id(unsigned):
        raise RegistryError("backup anchor ID binding mismatch")
    snapshot = WarehouseSnapshot.from_dict(payload["snapshot"])
    rebuild = RebuildFingerprint.from_dict(payload["rebuild"])
    if rebuild.registry_raw_sha256 == snapshot.root_sha256:
        raise RegistryError("backup rebuild and snapshot domains collided")
    return payload, snapshot, rebuild


def _load_chain(
    *,
    paths: BackupPaths,
    held: HeldCustodyRoot,
    public_key_path: Path,
    expected_public_key_sha256: str,
) -> list[VerifiedBackupAnchor]:
    anchors: list[VerifiedBackupAnchor] = []
    with held.open_directory("anchors") as anchors_fd:
        names = sorted(os.listdir(anchors_fd))
    if any(ANCHOR_FILENAME_PATTERN.fullmatch(name) is None for name in names):
        raise RegistryError("backup anchor custody has an unexpected member")
    for name in names:
        path = paths.anchors / name
        raw = held.read_file(
            f"anchors/{name}",
            label="backup anchor",
            limit=32 * 1024 * 1024,
        )
        payload = parse_json_strict(raw, "backup anchor")
        validated, snapshot, rebuild = _validate_payload(
            payload,
            public_key_path=public_key_path,
            expected_public_key_sha256=expected_public_key_sha256,
        )
        if raw != canonical_json_line(validated):
            raise RegistryError("backup anchor is not canonical JSON line")
        expected_name = (
            f"backup-{validated['sequence']:08d}-"
            f"{validated['anchor_id']}.json"
        )
        if path.name != expected_name:
            raise RegistryError("backup anchor custody filename mismatch")
        anchors.append(
            VerifiedBackupAnchor(
                path=path,
                raw_sha256=sha256(raw),
                anchor_id=validated["anchor_id"],
                sequence=validated["sequence"],
                created_at=parse_utc(
                    validated["created_at"],
                    "backup anchor created_at",
                ),
                parent_anchor_raw_sha256=validated[
                    "parent_anchor_raw_sha256"
                ],
                source_custody_identity=validated["source_custody_identity"],
                backup_custody_identity=validated["backup_custody_identity"],
                snapshot=snapshot,
                rebuild=rebuild,
                payload=validated,
            )
        )
    for sequence, anchor in enumerate(anchors, start=1):
        expected_parent = anchors[sequence - 2].raw_sha256 if sequence > 1 else None
        if (
            anchor.sequence != sequence
            or anchor.parent_anchor_raw_sha256 != expected_parent
        ):
            raise RegistryError("backup anchor chain is non-contiguous")
        if sequence > 1 and anchor.created_at <= anchors[sequence - 2].created_at:
            raise RegistryError("backup anchor time must strictly increase")
        if sequence > 1:
            previous = {
                entry.relative_path: entry
                for entry in anchors[sequence - 2].snapshot.entries
            }
            current = {
                entry.relative_path: entry for entry in anchor.snapshot.entries
            }
            if any(current.get(path) != entry for path, entry in previous.items()):
                raise RegistryError("backup anchor snapshot is not append-only")
    return anchors


def _create_backup_anchor(
    *,
    paths: BackupPaths,
    source_held: HeldCustodyRoot,
    backup_held: HeldCustodyRoot,
    snapshot: WarehouseSnapshot,
    rebuild: RebuildFingerprint,
    expected_parent_anchor_raw_sha256: str | None,
    signer_key_id: str,
    private_key_path: Path,
    public_key_path: Path,
    expected_public_key_sha256: str,
    now: datetime,
) -> VerifiedBackupAnchor:
    created = require_utc(now, "backup anchor created_at")
    source_custody_identity = source_held.identity_sha256(
        domain="vnpy-research-source-custody-v1",
    )
    backup_custody_identity = backup_held.identity_sha256(
        domain="vnpy-research-backup-custody-v1",
    )
    with held_custody_lock(backup_held, key="anchor-chain"):
        chain = _load_chain(
            paths=paths,
            held=backup_held,
            public_key_path=public_key_path,
            expected_public_key_sha256=expected_public_key_sha256,
        )
        actual_snapshot = scan_held_snapshot(
            backup_held,
            raw_prefix="objects/raw",
            manifests_prefix="objects/manifests",
            strip_prefix="objects",
        )
        if actual_snapshot != snapshot:
            raise RegistryError("backup object store does not match source snapshot")
        head = chain[-1] if chain else None
        idempotent = (
            head is not None
            and head.parent_anchor_raw_sha256
            == expected_parent_anchor_raw_sha256
            and head.source_custody_identity == source_custody_identity
            and head.backup_custody_identity == backup_custody_identity
            and head.snapshot == snapshot
            and head.rebuild == rebuild
        )
        if idempotent:
            return head
        actual_parent = head.raw_sha256 if head is not None else None
        if actual_parent != expected_parent_anchor_raw_sha256:
            raise RegistryError("backup anchor expected parent is stale")
        if head is not None and created <= head.created_at:
            raise RegistryError("backup anchor time does not follow current head")
        private_key = load_private_key(private_key_path)
        if public_key_sha256(private_key.public_key()) != require_sha256(
            expected_public_key_sha256,
            "trusted backup signer public key",
        ):
            raise RegistryError("backup private key is not trusted")
        public_key = load_public_key(public_key_path)
        if public_key_sha256(public_key) != expected_public_key_sha256:
            raise RegistryError("backup public key file is not trusted")
        unsigned: dict[str, Any] = {
            "schema_version": BACKUP_ANCHOR_SCHEMA,
            "anchor_id": "",
            "purpose": BACKUP_PURPOSE,
            "sequence": len(chain) + 1,
            "created_at": format_utc(created, "backup anchor created_at"),
            "parent_anchor_raw_sha256": actual_parent,
            "source_custody_identity": require_sha256(
                source_custody_identity,
                "source custody identity",
            ),
            "backup_custody_identity": require_sha256(
                backup_custody_identity,
                "backup custody identity",
            ),
            "snapshot": snapshot.as_dict(),
            "rebuild": rebuild.as_dict(),
            "authority": false_authority(),
            "signer_key_id": require_identifier(
                signer_key_id,
                "backup signer key ID",
            ),
            "signer_public_key_sha256": expected_public_key_sha256,
        }
        unsigned["anchor_id"] = _anchor_id(unsigned)
        signed = sign_payload(unsigned, private_key)
        _validate_payload(
            signed,
            public_key_path=public_key_path,
            expected_public_key_sha256=expected_public_key_sha256,
        )
        raw = canonical_json_line(signed)
        path = paths.anchors / (
            f"backup-{unsigned['sequence']:08d}-{unsigned['anchor_id']}.json"
        )
        source_held.revalidate()
        backup_held.revalidate()
        backup_held.publish_bytes(
            f"anchors/{path.name}",
            raw,
            label="signed backup anchor",
        )
        loaded = _load_chain(
            paths=paths,
            held=backup_held,
            public_key_path=public_key_path,
            expected_public_key_sha256=expected_public_key_sha256,
        )
        if not loaded or loaded[-1].raw_sha256 != sha256(raw):
            raise RegistryError("published backup anchor is not chain head")
        return loaded[-1]


def verify_backup_anchor(
    *,
    paths: BackupPaths,
    public_key_path: Path,
    expected_public_key_sha256: str,
    expected_head_anchor_raw_sha256: str,
) -> VerifiedBackupAnchor:
    with hold_custody_root(paths.root) as held:
        return _verify_backup_anchor_held(
            paths=paths,
            held=held,
            public_key_path=public_key_path,
            expected_public_key_sha256=expected_public_key_sha256,
            expected_head_anchor_raw_sha256=(
                expected_head_anchor_raw_sha256
            ),
        )


def _verify_backup_anchor_held(
    *,
    paths: BackupPaths,
    held: HeldCustodyRoot,
    public_key_path: Path,
    expected_public_key_sha256: str,
    expected_head_anchor_raw_sha256: str,
) -> VerifiedBackupAnchor:
    expected = require_sha256(
        expected_head_anchor_raw_sha256,
        "trusted backup head anchor",
    )
    with held_custody_lock(held, key="anchor-chain"):
        chain = _load_chain(
            paths=paths,
            held=held,
            public_key_path=public_key_path,
            expected_public_key_sha256=expected_public_key_sha256,
        )
        if not chain or chain[-1].raw_sha256 != expected:
            raise RegistryError("backup anchor head does not match trusted pin")
        if chain[-1].backup_custody_identity != held.identity_sha256(
            domain="vnpy-research-backup-custody-v1",
        ):
            raise RegistryError("backup anchor was replayed to different custody")
        actual = scan_held_snapshot(
            held,
            raw_prefix="objects/raw",
            manifests_prefix="objects/manifests",
            strip_prefix="objects",
        )
        if actual != chain[-1].snapshot:
            raise RegistryError("backup object store does not match trusted head")
        held.revalidate()
        return chain[-1]
