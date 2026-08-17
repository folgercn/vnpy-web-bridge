"""Compatibility facade for layered custody filesystem services."""

from .custody_locks import custody_identity, custody_lock, stable_custody_identity
from .custody_paths import SAFE_COMPONENT, CustodyTransitionTrust, WarehousePaths
from .file_integrity import MAX_RAW_BYTES, read_regular_strict
from .publication import (
    create_download_temp,
    create_only_bytes,
    publish_temp_create_only,
    recover_atomic_publishes,
    stream_to_fd,
)

__all__ = [
    "MAX_RAW_BYTES",
    "SAFE_COMPONENT",
    "CustodyTransitionTrust",
    "WarehousePaths",
    "create_download_temp",
    "create_only_bytes",
    "custody_identity",
    "custody_lock",
    "publish_temp_create_only",
    "read_regular_strict",
    "recover_atomic_publishes",
    "stable_custody_identity",
    "stream_to_fd",
]
