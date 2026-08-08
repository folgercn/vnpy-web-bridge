"""Typed DTOs for Control's Phase C read/command boundary.

No DTO imports custody, signing, TradeService, gateway, or commodity runtime
code.  Control only forwards these values to independently owned adapters.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from shared.phase_c_workflow.v1 import (
    AUTHORIZATION_COMMAND_SCHEMA_VERSION,
    FALSE_AUTHORITY_FLAGS,
    SIGNING_REQUEST_SCHEMA_VERSION,
)


class StrictDTO(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AuthorityNegativeDTO(StrictDTO):
    production_allowed: Literal[False] = False
    live_trading_authorized: Literal[False] = False
    countable_forward: Literal[False] = False


class SigningRequestCreateDTO(StrictDTO):
    request_id: str = Field(min_length=4, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$")
    domain: Literal["map_acceptance", "c_fast_acceptance", "runtime_authorization"]
    artifact: dict[str, Any]


class SigningRequestDTO(AuthorityNegativeDTO):
    schema_version: Literal[SIGNING_REQUEST_SCHEMA_VERSION] = SIGNING_REQUEST_SCHEMA_VERSION
    request_id: str
    domain: str
    requested_by: str
    artifact: dict[str, Any]
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    browser_signing: Literal[False] = False
    private_key_access: Literal[False] = False


class SignedArtifactUploadDTO(StrictDTO):
    idempotency_key: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$")
    expected_custody_version: int = Field(ge=0)
    signing_request_id: str = Field(min_length=4, max_length=128)
    signed_artifact: dict[str, Any]


class CustodyReceiptDTO(AuthorityNegativeDTO):
    receipt_id: str
    receipt_type: Literal["verify", "install"]
    artifact_id: str
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    custody_version: int = Field(ge=0)
    idempotency_key: str
    verified: Literal[True] = True
    installed: Literal[True] = True
    fake_adapter: Literal[True] = True


class AuthorizationCommandDTO(StrictDTO):
    schema_version: Literal[AUTHORIZATION_COMMAND_SCHEMA_VERSION] = AUTHORIZATION_COMMAND_SCHEMA_VERSION
    command_id: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$")
    idempotency_key: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$")
    expected_version: int = Field(ge=0)
    action: Literal["enable", "revoke"]
    authorization_artifact_id: str = Field(min_length=4, max_length=256)
    custody_receipt_id: str = Field(min_length=4, max_length=256)
    reason: str = Field(min_length=3, max_length=500)


class AuthorizationStatusDTO(AuthorityNegativeDTO):
    version: int = Field(ge=0)
    requested_state: Literal["DISABLED", "ENABLE_REQUESTED", "REVOKED"]
    effective_state: Literal["DISABLED"] = "DISABLED"
    artifact_id: str | None = None
    receipt_id: str | None = None
    runtime_mutation_allowed: Literal[False] = False
    fake_adapter: Literal[True] = True


class ExecutionProjectionDTO(AuthorityNegativeDTO):
    status: Literal["OFFLINE_FAKE", "ARCHIVED"]
    execution_mutation_allowed: Literal[False] = False
    runtime_state_owner: Literal["execution-adapter"] = "execution-adapter"
    custody_state_owner: Literal["custody-adapter"] = "custody-adapter"
    fake_adapter: Literal[True] = True
    audit: list[dict[str, Any]] = Field(default_factory=list)
    archive: list[dict[str, Any]] = Field(default_factory=list)


class WorkflowStatusDTO(AuthorityNegativeDTO):
    map_status: Literal["PENDING", "READY"]
    c_fast_status: Literal["PENDING", "READY"]
    signing: Literal["EXPORT_ONLY"] = "EXPORT_ONLY"
    browser_signing: Literal[False] = False
    custody_writer: Literal["fake-custody-adapter"] = "fake-custody-adapter"
    execution_writer: Literal["fake-execution-adapter"] = "fake-execution-adapter"
    execution_mutation_allowed: Literal[False] = False


def as_negative(value: dict[str, Any]) -> dict[str, Any]:
    """Force the authority-negative contract on projections from an adapter."""
    return {**value, **FALSE_AUTHORITY_FLAGS}


__all__ = [name for name in globals() if name.endswith("DTO") or name == "as_negative"]
