"""Frozen contracts for the M2 vnpyresearch deployment boundary."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import canonical_json_line, parse_json_strict, sha256
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .manifest_contracts import SHA256_PATTERN

POLICY_SCHEMA = "vnpy_research_m2_isolation_policy_v1"
EVIDENCE_SCHEMA = "vnpy_research_m2_isolation_evidence_v1"
POLICY_RAW_SHA256 = (
    "e62e4244ca3835e3991d0c7076a4304f6f254856ad777c0986c1d79a5614f785"
)
PLIST_SHA256 = {
    "com.vnpy.research-warehouse": (
        "be189608d7a590b2cbf524970ef4fa134993924ffdb57049f2a43bce39de557d"
    ),
    "com.vnpy.research-warehouse-monitor": (
        "51bf29a2bdd36951be8cb275ff1108219317df52baebc69ce67f88a91aa5c88c"
    ),
}
PF_ANCHOR_SHA256 = (
    "9692ed110a0db70be5cf096ae2e0ace15544b0c2c20e89ce4cc8dc79363d936a"
)
AUTHORITY_FIELDS = (
    "account_data_read",
    "control_authorized",
    "deployment_authorized",
    "execution_authorized",
    "network_beyond_allowlist_authorized",
    "order_authorized",
    "permit_authorized",
    "position_mutation_authorized",
    "production_authorized",
    "rpc_authorized",
    "trading_authorized",
)
POLICY_KEYS = {
    "schema_version",
    "policy_id",
    "service_user",
    "service_group",
    "home",
    "custody_root",
    "runtime_root",
    "backup_root",
    "umask",
    "launchd_labels",
    "allowed_environment",
    "forbidden_environment_names",
    "registry_raw_sha256",
    "allowed_https_hosts",
    "allowed_egress_classes",
    "forbidden_network_targets",
    "forbidden_paths",
    "monitor_thresholds",
    "authority",
}
EVIDENCE_KEYS = {
    "schema_version",
    "captured_at",
    "host_identity",
    "policy_raw_sha256",
    "registry_raw_sha256",
    "identity",
    "launchd",
    "environment",
    "filesystem",
    "network",
    "process",
    "monitor_input",
    "authority",
}


@dataclass(frozen=True)
class IsolationPolicy:
    raw_sha256: str
    payload: dict[str, Any]

    @property
    def user(self) -> str:
        return self.payload["service_user"]

    @property
    def group(self) -> str:
        return self.payload["service_group"]


def false_authority() -> dict[str, bool]:
    return {field: False for field in AUTHORITY_FIELDS}


def _exact_dict(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise RegistryError(f"{label} fields do not match v1")
    return value


def _string_list(value: object, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
        or len(value) != len(set(value))
    ):
        raise RegistryError(f"{label} must be a unique non-empty string list")
    return list(value)


def load_isolation_policy(path: Path) -> IsolationPolicy:
    raw = read_regular_strict(
        path,
        "M2 isolation policy",
        limit=1024 * 1024,
        private=False,
    )
    if sha256(raw) != POLICY_RAW_SHA256:
        raise RegistryError("M2 isolation policy raw SHA256 mismatch")
    payload = parse_json_strict(raw, "M2 isolation policy")
    _exact_dict(payload, POLICY_KEYS, "M2 isolation policy")
    if (
        payload["schema_version"] != POLICY_SCHEMA
        or payload["service_user"] != "vnpyresearch"
        or payload["service_group"] != "vnpyresearch"
        or payload["umask"] != "077"
        or payload["registry_raw_sha256"]
        != "638cb64fa8799b29b2f5ae915218d25f4cc15b6482555355661920c482e54dae"
        or payload["authority"] != false_authority()
    ):
        raise RegistryError("M2 isolation policy identity mismatch")
    if payload["allowed_environment"] != {
        "HOME": payload["home"],
        "LANG": "C.UTF-8",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "PYTHONNOUSERSITE": "1",
        "TMPDIR": f"{payload['runtime_root']}/tmp",
    }:
        raise RegistryError("M2 isolation environment is not minimal")
    for field in (
        "launchd_labels",
        "forbidden_environment_names",
        "allowed_https_hosts",
        "allowed_egress_classes",
        "forbidden_network_targets",
        "forbidden_paths",
    ):
        _string_list(payload[field], field)
    if payload["allowed_https_hosts"] != ["www.ine.cn", "www.shfe.com.cn"]:
        raise RegistryError("M2 registry host allowlist mismatch")
    if payload["allowed_egress_classes"] != [
        "DNS",
        "NTP",
        "REGISTRY_HTTPS",
    ]:
        raise RegistryError("M2 egress class allowlist mismatch")
    thresholds = _exact_dict(
        payload["monitor_thresholds"],
        {
            "backup_max_age_seconds",
            "disk_free_min_bytes",
            "last_success_max_age_seconds",
        },
        "M2 monitor thresholds",
    )
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value <= 0
        for value in thresholds.values()
    ):
        raise RegistryError("M2 monitor thresholds must be positive integers")
    return IsolationPolicy(raw_sha256=POLICY_RAW_SHA256, payload=payload)


def load_isolation_evidence(
    path: Path,
    *,
    expected_raw_sha256: str,
) -> dict[str, Any]:
    require_sha(expected_raw_sha256, "expected M2 evidence raw SHA256")
    raw = read_regular_strict(
        path,
        "M2 isolation evidence",
        limit=4 * 1024 * 1024,
    )
    if sha256(raw) != expected_raw_sha256:
        raise RegistryError("M2 isolation evidence raw SHA256 mismatch")
    payload = parse_json_strict(raw, "M2 isolation evidence")
    _exact_dict(payload, EVIDENCE_KEYS, "M2 isolation evidence")
    if (
        payload["schema_version"] != EVIDENCE_SCHEMA
        or canonical_json_line(payload) != raw
    ):
        raise RegistryError("M2 isolation evidence is not canonical v1")
    return payload


def require_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise RegistryError(f"{label} must be a lowercase SHA256")
    return value
