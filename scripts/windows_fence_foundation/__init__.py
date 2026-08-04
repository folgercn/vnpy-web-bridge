"""Fail-closed Windows RPC durable-fence foundation primitives."""

from .contracts import (
    FOUNDATION_STATE_SCHEMA_VERSION,
    FrozenNoneState,
    StoreContractError,
    canonical_json_bytes,
    parse_frozen_none_state,
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
    "FOUNDATION_STATE_SCHEMA_VERSION",
    "FilesystemFactsAdapter",
    "FrozenNoneState",
    "PathSecurityFacts",
    "PortableFilesystemFactsAdapter",
    "SecureDirectoryInventory",
    "SecureFileRead",
    "StoreContractError",
    "StoreExpectation",
    "StoreRecovery",
    "WindowsFilesystemFactsAdapter",
    "canonical_json_bytes",
    "parse_frozen_none_state",
    "recover_frozen_none_store",
]
