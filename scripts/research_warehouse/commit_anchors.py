"""Trusted external availability anchors for committed manifests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from itertools import pairwise
from pathlib import Path
from typing import Any

from .canonical import canonical_json_line, parse_json_strict, sha256
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .manifest_contracts import SHA256_PATTERN
from .timeutil import parse_utc, require_utc

ANCHOR_SCHEMA = "vnpy_research_commit_anchor_ledger_v1"
LEDGER_KEYS = {"schema_version", "entries"}
ENTRY_KEYS = {
    "sequence",
    "batch_seal_sha256",
    "commit_seal_sha256",
    "available_at",
}


@dataclass(frozen=True)
class CommitAnchor:
    sequence: int
    batch_seal_sha256: str
    commit_seal_sha256: str
    available_at: datetime


@dataclass(frozen=True)
class CommitAnchorLedger:
    raw_sha256: str
    entries: tuple[CommitAnchor, ...]

    def require_chain(self, chain: list[dict[str, Any]]) -> None:
        if (
            not isinstance(self.raw_sha256, str)
            or SHA256_PATTERN.fullmatch(self.raw_sha256) is None
        ):
            raise RegistryError("trusted commit anchor ledger SHA256 is invalid")
        if not self.entries:
            raise RegistryError("commit anchor ledger must contain entries")
        for expected_sequence, entry in enumerate(self.entries, start=1):
            if entry.sequence != expected_sequence:
                raise RegistryError("commit anchor sequence is not contiguous")
            for value in (
                entry.batch_seal_sha256,
                entry.commit_seal_sha256,
            ):
                if (
                    not isinstance(value, str)
                    or SHA256_PATTERN.fullmatch(value) is None
                ):
                    raise RegistryError("commit anchor seal is invalid")
            require_utc(entry.available_at, "available_at")
        if len({entry.batch_seal_sha256 for entry in self.entries}) != len(
            self.entries
        ):
            raise RegistryError("commit anchor ledger repeats a batch seal")
        if len({entry.commit_seal_sha256 for entry in self.entries}) != len(
            self.entries
        ):
            raise RegistryError("commit anchor ledger repeats a commit seal")
        if any(
            current.available_at <= previous.available_at
            for previous, current in pairwise(self.entries)
        ):
            raise RegistryError("commit anchor available_at must strictly increase")
        if len(chain) != len(self.entries):
            raise RegistryError("trusted commit anchor ledger length mismatch")
        for manifest, anchor in zip(chain, self.entries, strict=True):
            if (
                manifest["batch_seal_sha256"] != anchor.batch_seal_sha256
                or manifest["commit_seal_sha256"] != anchor.commit_seal_sha256
            ):
                raise RegistryError(
                    "manifest commit does not match trusted external anchor"
                )
            if anchor.available_at < parse_utc(
                manifest["commit_receipt"]["committed_at"],
                "committed_at",
            ):
                raise RegistryError(
                    "external commit availability predates receipt creation"
                )

    def available_at_by_batch(self) -> dict[str, datetime]:
        return {entry.batch_seal_sha256: entry.available_at for entry in self.entries}


def _parse_entry(payload: object, expected_sequence: int) -> CommitAnchor:
    if not isinstance(payload, dict) or set(payload) != ENTRY_KEYS:
        raise RegistryError("commit anchor entry fields do not match v1 schema")
    if payload["sequence"] != expected_sequence:
        raise RegistryError("commit anchor sequence is not contiguous")
    for label in ("batch_seal_sha256", "commit_seal_sha256"):
        value = payload[label]
        if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
            raise RegistryError(f"commit anchor {label} is invalid")
    return CommitAnchor(
        sequence=expected_sequence,
        batch_seal_sha256=payload["batch_seal_sha256"],
        commit_seal_sha256=payload["commit_seal_sha256"],
        available_at=parse_utc(payload["available_at"], "available_at"),
    )


def load_commit_anchor_ledger(
    path: Path,
    *,
    expected_raw_sha256: str,
    private: bool = True,
) -> CommitAnchorLedger:
    if (
        not isinstance(expected_raw_sha256, str)
        or SHA256_PATTERN.fullmatch(expected_raw_sha256) is None
    ):
        raise RegistryError("trusted commit anchor ledger SHA256 is invalid")
    raw = read_regular_strict(
        path,
        "trusted external commit anchor ledger",
        limit=2 * 1024 * 1024,
        private=private,
    )
    if sha256(raw) != expected_raw_sha256:
        raise RegistryError("trusted commit anchor ledger hash mismatch")
    payload = parse_json_strict(raw, "trusted external commit anchor ledger")
    if not isinstance(payload, dict) or set(payload) != LEDGER_KEYS:
        raise RegistryError("commit anchor ledger fields do not match v1 schema")
    if payload["schema_version"] != ANCHOR_SCHEMA:
        raise RegistryError("commit anchor ledger schema mismatch")
    values = payload["entries"]
    if not isinstance(values, list) or not values:
        raise RegistryError("commit anchor ledger must contain entries")
    entries = tuple(
        _parse_entry(value, index) for index, value in enumerate(values, start=1)
    )
    if len({entry.batch_seal_sha256 for entry in entries}) != len(entries):
        raise RegistryError("commit anchor ledger repeats a batch seal")
    if len({entry.commit_seal_sha256 for entry in entries}) != len(entries):
        raise RegistryError("commit anchor ledger repeats a commit seal")
    if any(
        current.available_at <= previous.available_at
        for previous, current in pairwise(entries)
    ):
        raise RegistryError("commit anchor available_at must strictly increase")
    if raw != canonical_json_line(payload):
        raise RegistryError("commit anchor ledger is not canonical JSON")
    return CommitAnchorLedger(raw_sha256=expected_raw_sha256, entries=entries)
