"""Shared offline-only CLI plumbing; it deliberately accepts key *FDs*, not paths."""

from __future__ import annotations

import argparse
import hashlib
import sys
from datetime import datetime
from pathlib import Path

from .installer_trust_anchor_v1 import canonical_public_keyring_v1
from .offline_signing_v1 import (
    OfflineSigningError,
    read_canonical_artifact_v1,
    sign_artifact_with_fd_v1,
    write_audit_create_only_v1,
    write_canonical_create_only_v1,
    consume_replay_token_create_only_v1,
)


def run(role: str, argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog=f"windows-fence-{role}-sign-v1")
    parser.add_argument("--draft", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--audit-output", type=Path, required=True)
    parser.add_argument("--public-keyring", type=Path, required=True)
    parser.add_argument("--private-key-fd", type=int, required=True)
    parser.add_argument("--preflight-receipt", type=Path)
    parser.add_argument("--now-utc")
    parser.add_argument("--execution-facts", type=Path)
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--replay-ledger-dir", type=Path)
    options = parser.parse_args(argv)
    try:
        keyring_raw = options.public_keyring.read_bytes()
        pins = canonical_public_keyring_v1(
            keyring_raw, hashlib.sha256(keyring_raw).hexdigest()
        )
        _raw, draft = read_canonical_artifact_v1(options.draft)
        pin = {"manifest": pins.manifest, "observer": pins.observer, "restart": pins.restart}[role]
        schema = draft.get("schema_version")
        if schema in {
            "windows_rpc_durable_fence_install_manifest_v1",
            "windows_rpc_durable_fence_restart_authorization_v1",
        } and (options.preflight_receipt is None or options.now_utc is None):
            raise OfflineSigningError("SIGNING_FRESH_PREFLIGHT_REQUIRED")
        if schema == "windows_rpc_durable_fence_zero_order_preflight_v1" and (
            options.execution_facts is None or options.snapshot is None
        ):
            raise OfflineSigningError("SIGNING_PREFLIGHT_SOURCE_FACTS_REQUIRED")
        if schema in {"windows_rpc_durable_fence_zero_order_preflight_v1", "windows_rpc_durable_fence_restart_authorization_v1"} and options.replay_ledger_dir is None:
            raise OfflineSigningError("SIGNING_REPLAY_LEDGER_REQUIRED")
        signed = sign_artifact_with_fd_v1(
            draft,
            private_key_fd=options.private_key_fd,
            pin=pin,
            observer_pin=pins.observer,
            fresh_preflight_raw=(None if options.preflight_receipt is None else options.preflight_receipt.read_bytes()),
            now=(None if options.now_utc is None else datetime.fromisoformat(options.now_utc.replace("Z", "+00:00"))),
            execution_facts_raw=(None if options.execution_facts is None else options.execution_facts.read_bytes()),
            snapshot_raw=(None if options.snapshot is None else options.snapshot.read_bytes()),
        )
        raw = write_canonical_create_only_v1(options.output, signed)
        if schema == "windows_rpc_durable_fence_zero_order_preflight_v1":
            consume_replay_token_create_only_v1(options.replay_ledger_dir, token_sha256=str(draft["challenge_nonce_sha256"]), purpose="preflight-challenge")
            consume_replay_token_create_only_v1(options.replay_ledger_dir, token_sha256=hashlib.sha256(str(draft["replay_guard_id"]).encode()).hexdigest(), purpose="preflight-replay-guard")
        if schema == "windows_rpc_durable_fence_restart_authorization_v1":
            consume_replay_token_create_only_v1(options.replay_ledger_dir, token_sha256=str(draft["dispatch_nonce_sha256"]), purpose="restart-dispatch")
            consume_replay_token_create_only_v1(options.replay_ledger_dir, token_sha256=hashlib.sha256(str(draft["authorization_id"]).encode()).hexdigest(), purpose="restart-authorization")
        write_audit_create_only_v1(options.audit_output, artifact_raw=raw, action=f"sign-{role}")
    except (OfflineSigningError, OSError, ValueError) as exc:
        print(f"offline {role} signing failed: {exc}", file=sys.stderr)
        return 2
    print(f"offline {role} artifact written: {options.output}")
    return 0
