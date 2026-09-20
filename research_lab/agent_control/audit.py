"""Append-only audit trail and integrity verification (#573 Milestone 0).

Rules:
1. Append-only storage: records can only be appended; in-place mutations or updates
   are strictly prohibited.
2. Tamper-detection: validates content hashes against research-json-v1 canonical SHA-256.
"""

from __future__ import annotations

from collections.abc import Sequence

from research_lab.agent_control.contracts import (
    AgentAuditRecord,
    validate_audit_hash,
)


class AppendOnlyAuditTrail:
    """In-memory append-only audit trail enforcing integrity and tamper-detection."""

    def __init__(self, initial_records: Sequence[AgentAuditRecord] | None = None) -> None:
        self._records: list[AgentAuditRecord] = []
        if initial_records:
            for r in initial_records:
                self.append(r)

    def append(self, record: AgentAuditRecord) -> None:
        """Append an immutable audit record, validating its canonical content hash."""
        # Validate hash before appending
        validate_audit_hash(record.to_dict())
        self._records.append(record)

    def get_records(self) -> list[AgentAuditRecord]:
        """Return a shallow copy of stored immutable records."""
        return list(self._records)

    def verify_all(self) -> bool:
        """Verify the cryptographic integrity of all audit records in the trail.

        Raises TamperDetectionError if any record has been modified or corrupted.
        """
        for record in self._records:
            validate_audit_hash(record.to_dict())
        return True

    def __len__(self) -> int:
        return len(self._records)
