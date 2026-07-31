"""Create daily seals and expose anchored chain verification."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonical_json, canonical_json_line, parse_json_strict, sha256
from .errors import RegistryError
from .filesystem import (
    WarehousePaths,
    create_only_bytes,
    custody_lock,
    read_regular_strict,
    recover_atomic_publishes,
)
from .manifest_chain import load_manifest_chain, require_chain_anchors
from .manifest_commits import (
    commit_receipt_path,
    create_commit_receipt,
    load_commit_receipt,
)
from .manifest_contracts import (
    ID_PATTERN,
    MANIFEST_AUTHORITY,
    MANIFEST_SCHEMA,
    input_fingerprint,
    seal_base,
)
from .manifest_envelope import validate_manifest_envelope
from .manifest_validation import validate_manifest
from .models import SourceRegistry
from .observations import load_observations
from .revisions import revision_state
from .signing import (
    load_private_key,
    load_public_key,
    public_key_sha256,
    sign_payload,
)
from .timeutil import format_utc, parse_utc, require_utc

__all__ = [
    "find_committed_manifest_for_day",
    "find_committed_manifest_for_day_incremental",
    "load_manifest_chain",
    "seal_daily_batch",
    "seal_daily_batch_incremental_with_private_key",
    "seal_daily_batch_with_private_key",
    "validate_manifest",
    "verify_manifest_chain",
]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _recover_manifest_publications(paths: WarehousePaths) -> None:
    for temporary_prefix, final_glob in (
        (".publish-batch-", "batch-*.json"),
        (".publish-commit-batch-", "commit-batch-*.json"),
    ):
        recover_atomic_publishes(
            temporary_dir=paths.temporary,
            final_root=paths.manifests,
            temporary_name_prefix=temporary_prefix,
            final_name_glob=final_glob,
        )


def _path_for_manifest(
    paths: WarehousePaths,
    manifest: dict[str, Any],
) -> Path:
    return paths.manifests / manifest["trade_day"] / f"{manifest['batch_id']}.json"


def _load_day_manifests(
    *,
    paths: WarehousePaths,
    registry: SourceRegistry,
    public_key: Ed25519PublicKey,
    trade_day: str,
    verify_evidence: bool,
) -> list[dict[str, Any]]:
    """Load one day's manifests without walking the historical chain."""
    validator = validate_manifest if verify_evidence else validate_manifest_envelope
    manifests = []
    day_root = paths.manifests / trade_day
    for path in sorted(day_root.glob("batch-*.json")):
        raw = read_regular_strict(
            path,
            "daily batch manifest",
            limit=16 * 1024 * 1024,
        )
        payload = validator(
            paths,
            parse_json_strict(raw, "daily batch manifest"),
            public_key,
            registry,
        )
        if raw != canonical_json_line(payload):
            raise RegistryError("daily batch manifest is not canonical JSON")
        if path != _path_for_manifest(paths, payload):
            raise RegistryError("daily batch manifest custody path binding mismatch")
        receipt_path = commit_receipt_path(path, payload["batch_id"])
        loaded = (
            load_commit_receipt(receipt_path, payload, public_key)
            if receipt_path.exists()
            else None
        )
        manifests.append(
            {
                **payload,
                "commit_receipt": loaded[0] if loaded is not None else None,
                "commit_seal_sha256": loaded[1] if loaded is not None else None,
            }
        )
    return manifests


def _require_incremental_head(
    *,
    paths: WarehousePaths,
    registry: SourceRegistry,
    public_key: Ed25519PublicKey,
    trade_day: str | None,
    expected_batch_seal_sha256: str | None,
    expected_commit_seal_sha256: str | None,
) -> dict[str, Any] | None:
    if expected_batch_seal_sha256 is None:
        if trade_day is not None or expected_commit_seal_sha256 is not None:
            raise RegistryError("incremental manifest genesis pin is inconsistent")
        return None
    if trade_day is None or expected_commit_seal_sha256 is None:
        raise RegistryError("incremental manifest head pin is incomplete")
    matches = [
        item
        for item in _load_day_manifests(
            paths=paths,
            registry=registry,
            public_key=public_key,
            trade_day=trade_day,
            verify_evidence=False,
        )
        if item["batch_seal_sha256"] == expected_batch_seal_sha256
        and item["commit_seal_sha256"] == expected_commit_seal_sha256
        and item["commit_receipt"] is not None
    ]
    if len(matches) != 1:
        raise RegistryError("incremental manifest head does not match root pin")
    return matches[0]


def _matches_lost_response(
    manifest: dict[str, Any],
    *,
    expected_parent: str | None,
    expected_parent_commit: str | None,
    trade_day: str,
    registry: SourceRegistry,
    signer_key_id: str,
    signer_public_key_sha256: str,
) -> bool:
    return (
        manifest["parent_batch_seal_sha256"] == expected_parent
        and manifest["parent_commit_seal_sha256"] == expected_parent_commit
        and manifest["trade_day"] == trade_day
        and manifest["registry_raw_sha256"] == registry.raw_sha256
        and manifest["signer_key_id"] == signer_key_id
        and manifest["signer_public_key_sha256"] == signer_public_key_sha256
    )


def _manifest_payload(
    *,
    trade_day: str,
    sealed: datetime,
    registry: SourceRegistry,
    parent_seal: str | None,
    parent_commit_seal: str | None,
    observations: list[dict[str, Any]],
    signer_key_id: str,
    signer_public_key_sha256: str,
) -> dict[str, Any]:
    observation_ids = sorted(item["observation_id"] for item in observations)
    revisions = revision_state(observations)
    unique_objects = {item["object_id"]: item["raw_bytes"] for item in revisions}
    return {
        "schema_version": MANIFEST_SCHEMA,
        "batch_id": "",
        "trade_day": trade_day,
        "sealed_at": format_utc(sealed, "sealed_at"),
        "registry_raw_sha256": registry.raw_sha256,
        "input_fingerprint_sha256": input_fingerprint(
            registry.raw_sha256,
            observation_ids,
        ),
        "parent_batch_seal_sha256": parent_seal,
        "parent_commit_seal_sha256": parent_commit_seal,
        "batch_seal_sha256": "",
        "revisions": revisions,
        "observation_ids": observation_ids,
        "revision_count": len(revisions),
        "unique_raw_object_count": len(unique_objects),
        "observation_count": len(observations),
        "total_unique_raw_bytes": sum(unique_objects.values()),
        "signer_key_id": signer_key_id,
        "signer_public_key_sha256": signer_public_key_sha256,
        "authority": MANIFEST_AUTHORITY,
        "ready": False,
    }


def seal_daily_batch(
    *,
    paths: WarehousePaths,
    registry: SourceRegistry,
    trade_day: str,
    private_key_path: Path,
    signer_key_id: str,
    expected_parent_batch_seal_sha256: str | None,
    expected_parent_commit_seal_sha256: str | None,
    trusted_clock: Callable[[], datetime] = _utc_now,
) -> Path:
    return seal_daily_batch_with_private_key(
        paths=paths,
        registry=registry,
        trade_day=trade_day,
        private_key=load_private_key(private_key_path),
        signer_key_id=signer_key_id,
        expected_parent_batch_seal_sha256=expected_parent_batch_seal_sha256,
        expected_parent_commit_seal_sha256=expected_parent_commit_seal_sha256,
        trusted_clock=trusted_clock,
    )


def find_committed_manifest_for_day(
    *,
    paths: WarehousePaths,
    registry: SourceRegistry,
    public_key: Ed25519PublicKey,
    trade_day: str,
) -> dict[str, Any] | None:
    """Return the unique committed batch for today's exact observation set."""
    observations = load_observations(paths, registry, trade_day=trade_day)
    if not observations:
        raise RegistryError("cannot inspect a day with no raw observations")
    fingerprint = input_fingerprint(
        registry.raw_sha256,
        sorted(item["observation_id"] for item in observations),
    )
    chain = load_manifest_chain(
        paths,
        public_key,
        registry,
        allow_uncommitted_head=True,
    )
    matches = [
        item
        for item in chain
        if item["trade_day"] == trade_day
        and item["input_fingerprint_sha256"] == fingerprint
        and item["commit_receipt"] is not None
    ]
    if len(matches) > 1:
        raise RegistryError("manifest chain repeats an identical daily fingerprint")
    return matches[0] if matches else None


def find_committed_manifest_for_day_incremental(
    *,
    paths: WarehousePaths,
    registry: SourceRegistry,
    public_key: Ed25519PublicKey,
    trade_day: str,
) -> dict[str, Any] | None:
    """Find an exact committed day without rereading every prior manifest."""
    observations = load_observations(paths, registry, trade_day=trade_day)
    if not observations:
        raise RegistryError("cannot inspect a day with no raw observations")
    fingerprint = input_fingerprint(
        registry.raw_sha256,
        sorted(item["observation_id"] for item in observations),
    )
    matches = [
        item
        for item in _load_day_manifests(
            paths=paths,
            registry=registry,
            public_key=public_key,
            trade_day=trade_day,
            verify_evidence=True,
        )
        if item["input_fingerprint_sha256"] == fingerprint
        and item["commit_receipt"] is not None
    ]
    if len(matches) > 1:
        raise RegistryError("manifest day repeats an identical committed fingerprint")
    return matches[0] if matches else None


def seal_daily_batch_with_private_key(
    *,
    paths: WarehousePaths,
    registry: SourceRegistry,
    trade_day: str,
    private_key: Ed25519PrivateKey,
    signer_key_id: str,
    expected_parent_batch_seal_sha256: str | None,
    expected_parent_commit_seal_sha256: str | None,
    trusted_clock: Callable[[], datetime] = _utc_now,
) -> Path:
    """Seal one day using key material preloaded by a privileged signer parent."""
    if ID_PATTERN.fullmatch(signer_key_id) is None:
        raise RegistryError("manifest signer key ID is invalid")
    if not isinstance(private_key, Ed25519PrivateKey):
        raise RegistryError("manifest signer private key object is invalid")
    public_key = private_key.public_key()
    signer_public_hash = public_key_sha256(public_key)
    with custody_lock(paths, "manifest-chain"):
        _recover_manifest_publications(paths)
        chain = load_manifest_chain(
            paths,
            public_key,
            registry,
            allow_uncommitted_head=True,
        )
        observations = load_observations(paths, registry, trade_day=trade_day)
        if not observations:
            raise RegistryError("cannot seal a day with no raw observations")
        latest_observation = max(
            parse_utc(item["observed_at"], "observed_at") for item in observations
        )
        fingerprint = input_fingerprint(
            registry.raw_sha256,
            sorted(item["observation_id"] for item in observations),
        )
        head = chain[-1] if chain else None
        actual_parent = head["batch_seal_sha256"] if head else None
        actual_parent_commit = head["commit_seal_sha256"] if head else None
        if (
            actual_parent != expected_parent_batch_seal_sha256
            or actual_parent_commit != expected_parent_commit_seal_sha256
        ):
            if head is None or not _matches_lost_response(
                head,
                expected_parent=expected_parent_batch_seal_sha256,
                expected_parent_commit=expected_parent_commit_seal_sha256,
                trade_day=trade_day,
                registry=registry,
                signer_key_id=signer_key_id,
                signer_public_key_sha256=signer_public_hash,
            ):
                raise RegistryError(
                    "manifest head does not match expected parent anchor"
                )
            if head["commit_receipt"] is None:
                committed = require_utc(trusted_clock(), "committed_at")
                create_commit_receipt(
                    paths=paths,
                    manifest_path=_path_for_manifest(paths, head),
                    manifest=head,
                    private_key=private_key,
                    committed_at=committed,
                )
            return _path_for_manifest(paths, head)
        if head is not None and head["commit_receipt"] is None:
            raise RegistryError(
                "trusted current head is missing its externally anchored commit"
            )
        if (
            head
            and head["trade_day"] == trade_day
            and head["input_fingerprint_sha256"] == fingerprint
        ):
            return _path_for_manifest(paths, head)
        sealed = require_utc(trusted_clock(), "sealed_at")
        if sealed < latest_observation:
            raise RegistryError("sealed_at cannot predate a claimed observation")
        if head and sealed <= parse_utc(head["sealed_at"], "sealed_at"):
            raise RegistryError("sealed_at must be later than parent batch")
        payload = _manifest_payload(
            trade_day=trade_day,
            sealed=sealed,
            registry=registry,
            parent_seal=actual_parent,
            parent_commit_seal=actual_parent_commit,
            observations=observations,
            signer_key_id=signer_key_id,
            signer_public_key_sha256=signer_public_hash,
        )
        payload["batch_seal_sha256"] = sha256(canonical_json(seal_base(payload)))
        payload["batch_id"] = f"batch-{trade_day}-{payload['batch_seal_sha256'][:24]}"
        signed = sign_payload(payload, private_key)
        parent = paths.private_subdir(paths.manifests, trade_day)
        output = parent / f"{signed['batch_id']}.json"
        create_only_bytes(
            output,
            canonical_json_line(signed),
            "daily batch manifest",
            temporary_dir=paths.temporary,
        )
        validate_manifest(paths, signed, public_key, registry)
        committed = require_utc(trusted_clock(), "committed_at")
        create_commit_receipt(
            paths=paths,
            manifest_path=output,
            manifest=signed,
            private_key=private_key,
            committed_at=committed,
        )
        return output


def seal_daily_batch_incremental_with_private_key(
    *,
    paths: WarehousePaths,
    registry: SourceRegistry,
    trade_day: str,
    private_key: Ed25519PrivateKey,
    signer_key_id: str,
    trusted_head_trade_day: str | None,
    expected_parent_batch_seal_sha256: str | None,
    expected_parent_commit_seal_sha256: str | None,
    trusted_clock: Callable[[], datetime] = _utc_now,
) -> Path:
    """Seal one day against the root-pinned head, without a full chain walk."""
    if ID_PATTERN.fullmatch(signer_key_id) is None:
        raise RegistryError("manifest signer key ID is invalid")
    if not isinstance(private_key, Ed25519PrivateKey):
        raise RegistryError("manifest signer private key object is invalid")
    public_key = private_key.public_key()
    signer_public_hash = public_key_sha256(public_key)
    with custody_lock(paths, "manifest-chain"):
        _recover_manifest_publications(paths)
        head = _require_incremental_head(
            paths=paths,
            registry=registry,
            public_key=public_key,
            trade_day=trusted_head_trade_day,
            expected_batch_seal_sha256=expected_parent_batch_seal_sha256,
            expected_commit_seal_sha256=expected_parent_commit_seal_sha256,
        )
        observations = load_observations(paths, registry, trade_day=trade_day)
        if not observations:
            raise RegistryError("cannot seal a day with no raw observations")
        latest_observation = max(
            parse_utc(item["observed_at"], "observed_at") for item in observations
        )
        fingerprint = input_fingerprint(
            registry.raw_sha256,
            sorted(item["observation_id"] for item in observations),
        )
        same_fingerprint = [
            item
            for item in _load_day_manifests(
                paths=paths,
                registry=registry,
                public_key=public_key,
                trade_day=trade_day,
                verify_evidence=False,
            )
            if item["input_fingerprint_sha256"] == fingerprint
        ]
        if len(same_fingerprint) > 1:
            raise RegistryError("manifest day repeats an identical fingerprint")
        if same_fingerprint:
            candidate = same_fingerprint[0]
            if (
                candidate["parent_batch_seal_sha256"]
                != expected_parent_batch_seal_sha256
                or candidate["parent_commit_seal_sha256"]
                != expected_parent_commit_seal_sha256
                or candidate["signer_key_id"] != signer_key_id
                or candidate["signer_public_key_sha256"] != signer_public_hash
            ):
                raise RegistryError("incremental manifest candidate forks root pin")
            if candidate["commit_receipt"] is None:
                create_commit_receipt(
                    paths=paths,
                    manifest_path=_path_for_manifest(paths, candidate),
                    manifest=candidate,
                    private_key=private_key,
                    committed_at=require_utc(trusted_clock(), "committed_at"),
                )
            return _path_for_manifest(paths, candidate)
        sealed = require_utc(trusted_clock(), "sealed_at")
        if sealed < latest_observation:
            raise RegistryError("sealed_at cannot predate a claimed observation")
        if head and sealed <= parse_utc(head["sealed_at"], "sealed_at"):
            raise RegistryError("sealed_at must be later than parent batch")
        payload = _manifest_payload(
            trade_day=trade_day,
            sealed=sealed,
            registry=registry,
            parent_seal=expected_parent_batch_seal_sha256,
            parent_commit_seal=expected_parent_commit_seal_sha256,
            observations=observations,
            signer_key_id=signer_key_id,
            signer_public_key_sha256=signer_public_hash,
        )
        payload["batch_seal_sha256"] = sha256(canonical_json(seal_base(payload)))
        payload["batch_id"] = f"batch-{trade_day}-{payload['batch_seal_sha256'][:24]}"
        signed = sign_payload(payload, private_key)
        output = (
            paths.private_subdir(paths.manifests, trade_day)
            / f"{signed['batch_id']}.json"
        )
        create_only_bytes(
            output,
            canonical_json_line(signed),
            "daily batch manifest",
            temporary_dir=paths.temporary,
        )
        validate_manifest_envelope(paths, signed, public_key, registry)
        create_commit_receipt(
            paths=paths,
            manifest_path=output,
            manifest=signed,
            private_key=private_key,
            committed_at=require_utc(trusted_clock(), "committed_at"),
        )
        return output


def verify_manifest_chain(
    *,
    paths: WarehousePaths,
    public_key_path: Path,
    registry: SourceRegistry,
    expected_genesis_seal_sha256: str | None,
    expected_head_seal_sha256: str | None,
    expected_head_commit_seal_sha256: str | None,
    offline: bool = False,
) -> list[dict[str, Any]]:
    with custody_lock(paths, "manifest-chain"):
        _recover_manifest_publications(paths)
        chain = load_manifest_chain(
            paths,
            load_public_key(public_key_path),
            registry,
            offline=offline,
        )
        require_chain_anchors(
            chain,
            expected_genesis_seal_sha256=expected_genesis_seal_sha256,
            expected_head_seal_sha256=expected_head_seal_sha256,
            expected_head_commit_seal_sha256=(expected_head_commit_seal_sha256),
        )
        return chain
