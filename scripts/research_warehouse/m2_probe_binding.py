"""Domain-separated canonical bindings for normalized M2 probe results."""

from __future__ import annotations

from typing import Any

from .canonical import canonical_json_line, sha256
from .errors import RegistryError
from .m2_isolation_contracts import require_sha

PROBE_SCHEMA = "vnpy_research_m2_normalized_probe_v1"
PROBE_CLASSES = {
    "identity",
    "launchd",
    "environment",
    "filesystem",
    "network",
    "process",
}


def probe_result_sha256(
    value: dict[str, Any],
    *,
    probe_class: str,
    host_identity: str,
) -> str:
    if probe_class not in PROBE_CLASSES:
        raise RegistryError("M2 probe class is invalid")
    require_sha(host_identity, "M2 probe host identity")
    if not {"observed_at", "probe_result_sha256"} <= set(value):
        raise RegistryError("M2 probe metadata is incomplete")
    result = {
        key: item
        for key, item in value.items()
        if key not in {"observed_at", "probe_result_sha256"}
    }
    return sha256(
        canonical_json_line(
            {
                "schema_version": PROBE_SCHEMA,
                "probe_class": probe_class,
                "host_identity": host_identity,
                "observed_at": value["observed_at"],
                "result": result,
            }
        )
    )


def verify_probe_result_sha256(
    value: dict[str, Any],
    *,
    probe_class: str,
    host_identity: str,
) -> None:
    claimed = require_sha(
        value["probe_result_sha256"],
        f"M2 {probe_class} probe result",
    )
    if claimed != probe_result_sha256(
        value,
        probe_class=probe_class,
        host_identity=host_identity,
    ):
        raise RegistryError(f"M2 {probe_class} probe result SHA256 mismatch")
