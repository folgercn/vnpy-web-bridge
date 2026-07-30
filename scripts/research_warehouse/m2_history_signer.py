"""Idempotent daily signing primitives used by M2 history orchestration."""

from __future__ import annotations

from pathlib import Path

from .canonical import parse_json_strict, sha256
from .commit_anchors import load_commit_anchor_ledger
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .m2_monitor_facts import verify_daily_run_receipt
from .m2_ntp import query_trusted_clock
from .m2_receipts import load_run_receipt
from .manifest_commits import commit_receipt_path, load_commit_receipt
from .manifests import (
    find_committed_manifest_for_day,
    seal_daily_batch_with_private_key,
)
from .manifest_validation import validate_manifest
from .timeutil import format_utc, parse_utc


def sign_manifest_day(
    *,
    context,
    private_key,
    trade_day: str,
    signer_key_id: str,
    parent_seal: str | None,
    parent_commit: str | None,
    clock,
) -> dict:
    receipt = load_run_receipt(context.runtime.run_receipts / f"{trade_day}.json")
    verify_daily_run_receipt(
        receipt,
        paths=context.paths,
        registry=context.registry,
        calendar=context.calendar,
        calendar_availability_raw_sha256=context.availability.raw_sha256,
    )
    existing = find_committed_manifest_for_day(
        paths=context.paths,
        registry=context.registry,
        public_key=private_key.public_key(),
        trade_day=trade_day,
    )
    if existing is not None:
        manifest_path = (
            context.paths.manifests
            / trade_day
            / f"{existing['batch_id']}.json"
        )
        manifest_raw = read_regular_strict(
            manifest_path,
            "M2 existing signed manifest",
            limit=16 * 1024 * 1024,
        )
        validated_existing = validate_manifest(
            context.paths,
            parse_json_strict(
                manifest_raw,
                "M2 existing signed manifest",
            ),
            private_key.public_key(),
            context.registry,
        )
        existing_receipt_path = commit_receipt_path(
            manifest_path,
            validated_existing["batch_id"],
        )
        loaded_existing_commit = load_commit_receipt(
            existing_receipt_path,
            validated_existing,
            private_key.public_key(),
        )
        if (
            loaded_existing_commit is None
            or validated_existing["batch_seal_sha256"]
            != existing["batch_seal_sha256"]
            or loaded_existing_commit[1] != existing["commit_seal_sha256"]
        ):
            raise RegistryError(
                "M2 existing manifest changed during strict reread"
            )
        lost_response = (
            existing["parent_batch_seal_sha256"] == parent_seal
            and existing["parent_commit_seal_sha256"] == parent_commit
            and existing["batch_seal_sha256"] != parent_seal
        )
        recovered_available_at = None
        if lost_response:
            recovered_clock = query_trusted_clock().trusted_now
            committed_at = parse_utc(
                existing["commit_receipt"]["committed_at"],
                "M2 recovered manifest committed_at",
            )
            if recovered_clock <= committed_at:
                raise RegistryError(
                    "M2 recovered manifest availability did not follow commit"
                )
            recovered_available_at = format_utc(
                recovered_clock,
                "M2 recovered manifest available_at",
            )
        return {
            **(
                {"available_at": recovered_available_at}
                if recovered_available_at is not None
                else {}
            ),
            "batch_id": existing["batch_id"],
            "batch_seal_sha256": existing["batch_seal_sha256"],
            "commit_seal_sha256": existing["commit_seal_sha256"],
            "committed_at": existing["commit_receipt"]["committed_at"],
            "manifest_relative_path": str(
                manifest_path.relative_to(context.paths.root)
            ),
            "manifest_raw_sha256": sha256(manifest_raw),
            "parent_batch_seal_sha256": existing[
                "parent_batch_seal_sha256"
            ],
            "parent_commit_seal_sha256": existing[
                "parent_commit_seal_sha256"
            ],
            "status": (
                "DAILY_BATCH_COMMITTED_AWAITING_EXTERNAL_ANCHOR"
                if lost_response
                else "DAILY_BATCH_ALREADY_COMMITTED"
            ),
            "trade_day": trade_day,
        }
    manifest_path = seal_daily_batch_with_private_key(
        paths=context.paths,
        registry=context.registry,
        trade_day=trade_day,
        private_key=private_key,
        signer_key_id=signer_key_id,
        expected_parent_batch_seal_sha256=parent_seal,
        expected_parent_commit_seal_sha256=parent_commit,
        trusted_clock=lambda: clock.trusted_now,
    )
    manifest_raw = read_regular_strict(
        manifest_path,
        "M2 signed manifest",
        limit=16 * 1024 * 1024,
    )
    manifest = validate_manifest(
        context.paths,
        parse_json_strict(manifest_raw, "M2 signed manifest"),
        private_key.public_key(),
        context.registry,
    )
    receipt_path = commit_receipt_path(manifest_path, manifest["batch_id"])
    receipt_raw = read_regular_strict(
        receipt_path,
        "M2 signed manifest commit receipt",
        limit=2 * 1024 * 1024,
    )
    loaded_commit = load_commit_receipt(
        receipt_path,
        manifest,
        private_key.public_key(),
    )
    if loaded_commit is None:
        raise RegistryError("M2 signed manifest commit receipt is unavailable")
    commit_receipt, commit_seal = loaded_commit
    available_at = query_trusted_clock().trusted_now
    if available_at <= parse_utc(
        commit_receipt["committed_at"],
        "M2 manifest committed_at",
    ):
        raise RegistryError(
            "M2 manifest availability did not follow durable commit"
        )
    return {
        "available_at": format_utc(available_at, "M2 manifest available_at"),
        "batch_id": manifest["batch_id"],
        "batch_seal_sha256": manifest["batch_seal_sha256"],
        "commit_seal_sha256": commit_seal,
        "committed_at": commit_receipt["committed_at"],
        "manifest_relative_path": str(
            manifest_path.relative_to(context.paths.root)
        ),
        "manifest_raw_sha256": sha256(manifest_raw),
        "parent_batch_seal_sha256": manifest[
            "parent_batch_seal_sha256"
        ],
        "parent_commit_seal_sha256": manifest[
            "parent_commit_seal_sha256"
        ],
        "status": "DAILY_BATCH_COMMITTED_AWAITING_EXTERNAL_ANCHOR",
        "trade_day": trade_day,
    }


def verify_history_base(state, history: dict) -> None:
    base = history["base_manifest_sequence"]
    if state.payload["manifest_sequence"] < base:
        raise RegistryError("M2 history signer state predates acquisition base")
    if base == 0:
        return
    ledger = load_commit_anchor_ledger(
        Path(state.payload["commit_anchor_ledger_path"]),
        expected_raw_sha256=state.payload["commit_anchor_ledger_raw_sha256"],
        private=False,
    )
    entry = ledger.entries[base - 1]
    if (
        entry.batch_seal_sha256
        != history["base_manifest_head_seal_sha256"]
        or entry.commit_seal_sha256
        != history["base_manifest_head_commit_seal_sha256"]
    ):
        raise RegistryError("M2 history signer base chain diverged")
