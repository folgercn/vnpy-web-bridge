"""Fail-closed Windows RPC durable-fence foundation primitives."""

from .contracts import (
    FOUNDATION_STATE_SCHEMA_VERSION,
    FrozenNoneState,
    StoreContractError,
    canonical_json_bytes,
    parse_frozen_none_state,
)
from .final_admission_v1 import (
    FinalFencedAdmissionV1,
    WindowsRpcFencedAdmissionV1,
    WindowsRpcFinalAdmissionV2,
)
from .final_store_v1 import (
    FINAL_LEDGER_SCHEMA_VERSION,
    FINAL_STORE_SCHEMA_VERSION,
    DurableFinalAdmissionStoreV1,
)
from .store import (
    StoreExpectation,
    StoreRecovery,
    recover_frozen_none_store,
)
from .win32_fs import (
    FilesystemFactsAdapter,
    PathSecurityFacts,
    PortableFilesystemFactsAdapter,
    SecureDirectoryInventory,
    SecureFileRead,
    WindowsFilesystemFactsAdapter,
)

__all__ = [
    "FINAL_LEDGER_SCHEMA_VERSION",
    "FINAL_STORE_SCHEMA_VERSION",
    "FOUNDATION_STATE_SCHEMA_VERSION",
    "DurableFinalAdmissionStoreV1",
    "FilesystemFactsAdapter",
    "FinalFencedAdmissionV1",
    "FrozenNoneState",
    "PathSecurityFacts",
    "PortableFilesystemFactsAdapter",
    "SecureDirectoryInventory",
    "SecureFileRead",
    "StoreContractError",
    "StoreExpectation",
    "StoreRecovery",
    "WindowsFilesystemFactsAdapter",
    "WindowsRpcFencedAdmissionV1",
    "WindowsRpcFinalAdmissionV2",
    "canonical_json_bytes",
    "parse_frozen_none_state",
    "recover_frozen_none_store",
]
