"""Verify static deployment assets and captured M2 isolation evidence."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta
from typing import Any

from .errors import RegistryError
from .m2_isolation_contracts import (
    PF_ANCHOR_SHA256,
    PLIST_SHA256,
    IsolationPolicy,
    false_authority,
    require_sha,
)
from .m2_monitor import evaluate_monitor
from .timeutil import parse_utc

IDENTITY_KEYS = {
    "user",
    "group",
    "uid",
    "gid",
    "supplementary_gids",
    "home",
    "inherited_fujun_home_acl",
    "web_bridge_uid",
    "web_bridge_gid",
}
LAUNCHD_KEYS = {"loaded_labels", "plist_raw_sha256s", "jobs_run_as_user"}
FILESYSTEM_KEYS = {
    "root_facts",
    "forbidden_path_reads",
    "fujun_home_traversable",
    "writable_paths",
    "shared_writable_mount",
}
NETWORK_KEYS = {
    "pf_enabled",
    "pf_anchor_loaded",
    "pf_anchor_raw_sha256",
    "default_block_for_service_user",
    "literal_ip_tables_only",
    "pf_table_entries",
    "resolved_registry_hosts",
    "allowed_egress_classes_observed",
    "forbidden_target_connectivity",
    "docker_socket_connectivity",
    "docker_network_membership",
    "unexpected_egress",
}
PROCESS_KEYS = {
    "service_process_uid",
    "service_process_gid",
    "shared_process_identity",
    "shared_credential_scope",
    "shared_network_namespace",
}
ROOT_FACT_KEYS = {"owner_uid", "owner_gid", "mode", "device"}


def _exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise RegistryError(f"{label} fields do not match v1")
    return value


def _ip_list(value: object, label: str, *, public: bool) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) != len(set(value))
    ):
        raise RegistryError(f"{label} must be a unique non-empty IP list")
    result = []
    for item in value:
        if not isinstance(item, str):
            raise RegistryError(f"{label} contains a non-string IP")
        try:
            address = ipaddress.ip_address(item)
        except ValueError as exc:
            raise RegistryError(f"{label} contains an invalid IP") from exc
        if address.is_unspecified or address.is_multicast or (
            public and not address.is_global
        ):
            raise RegistryError(f"{label} contains a forbidden IP")
        result.append(address.compressed)
    if result != value:
        raise RegistryError(f"{label} IPs are not canonical")
    return result


def verify_isolation_evidence(
    evidence: dict[str, Any],
    *,
    policy: IsolationPolicy,
    now: datetime,
) -> dict[str, Any]:
    _exact(
        evidence,
        {
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
        },
        "M2 isolation evidence",
    )
    if evidence["schema_version"] != "vnpy_research_m2_isolation_evidence_v1":
        raise RegistryError("M2 evidence schema mismatch")
    captured = parse_utc(evidence["captured_at"], "M2 evidence captured_at")
    if (
        now.tzinfo is None
        or now.utcoffset() is None
        or captured > now
        or now - captured > timedelta(minutes=30)
    ):
        raise RegistryError("M2 evidence time is invalid")
    if (
        require_sha(evidence["host_identity"], "M2 host identity")
        == "0" * 64
        or evidence["policy_raw_sha256"] != policy.raw_sha256
        or evidence["registry_raw_sha256"]
        != policy.payload["registry_raw_sha256"]
        or evidence["authority"] != false_authority()
    ):
        raise RegistryError("M2 evidence top-level binding mismatch")
    identity = _exact(evidence["identity"], IDENTITY_KEYS, "M2 identity")
    if (
        identity["user"] != policy.user
        or identity["group"] != policy.group
        or identity["home"] != policy.payload["home"]
        or any(
            isinstance(identity[field], bool)
            or not isinstance(identity[field], int)
            or identity[field] <= 0
            for field in ("uid", "gid", "web_bridge_uid", "web_bridge_gid")
        )
        or identity["uid"] == identity["web_bridge_uid"]
        or identity["gid"] == identity["web_bridge_gid"]
        or identity["inherited_fujun_home_acl"] is not False
        or identity["supplementary_gids"] != [identity["gid"]]
    ):
        raise RegistryError("M2 service identity is not isolated")
    launchd = _exact(evidence["launchd"], LAUNCHD_KEYS, "M2 launchd")
    if (
        launchd["loaded_labels"] != policy.payload["launchd_labels"]
        or launchd["plist_raw_sha256s"] != PLIST_SHA256
        or launchd["jobs_run_as_user"] != {
            label: policy.user for label in policy.payload["launchd_labels"]
        }
    ):
        raise RegistryError("M2 launchd evidence mismatch")
    if evidence["environment"] != policy.payload["allowed_environment"]:
        raise RegistryError("M2 process environment is not exact minimal environment")
    filesystem = _exact(
        evidence["filesystem"],
        FILESYSTEM_KEYS,
        "M2 filesystem",
    )
    expected_roots = {
        policy.payload[field]
        for field in ("home", "custody_root", "runtime_root", "backup_root")
    }
    roots = filesystem["root_facts"]
    if not isinstance(roots, dict) or set(roots) != expected_roots:
        raise RegistryError("M2 filesystem root set mismatch")
    for facts in roots.values():
        _exact(facts, ROOT_FACT_KEYS, "M2 root fact")
        if (
            facts["owner_uid"] != identity["uid"]
            or facts["owner_gid"] != identity["gid"]
            or facts["mode"] != "0700"
            or isinstance(facts["device"], bool)
            or not isinstance(facts["device"], int)
        ):
            raise RegistryError("M2 filesystem root ownership mismatch")
    if (
        filesystem["forbidden_path_reads"]
        != {path: False for path in policy.payload["forbidden_paths"]}
        or filesystem["fujun_home_traversable"] is not False
        or filesystem["shared_writable_mount"] is not False
        or not isinstance(filesystem["writable_paths"], list)
        or not set(filesystem["writable_paths"]).issubset(expected_roots)
    ):
        raise RegistryError("M2 forbidden filesystem boundary failed")
    network = _exact(evidence["network"], NETWORK_KEYS, "M2 network")
    tables = network["pf_table_entries"]
    if not isinstance(tables, dict) or set(tables) != {
        "DNS",
        "NTP",
        "REGISTRY_HTTPS",
    }:
        raise RegistryError("M2 PF table evidence mismatch")
    _ip_list(tables["DNS"], "M2 DNS table", public=False)
    _ip_list(tables["NTP"], "M2 NTP table", public=False)
    registry_ips = _ip_list(
        tables["REGISTRY_HTTPS"],
        "M2 registry HTTPS table",
        public=True,
    )
    resolutions = network["resolved_registry_hosts"]
    if (
        not isinstance(resolutions, dict)
        or set(resolutions) != set(policy.payload["allowed_https_hosts"])
    ):
        raise RegistryError("M2 registry resolution evidence mismatch")
    resolved = set()
    for host, addresses in resolutions.items():
        resolved.update(
            _ip_list(
                addresses,
                f"M2 registry resolution {host}",
                public=True,
            )
        )
    if set(registry_ips) != resolved:
        raise RegistryError("M2 registry PF table/resolution binding mismatch")
    if (
        network["pf_enabled"] is not True
        or network["pf_anchor_loaded"] is not True
        or network["pf_anchor_raw_sha256"] != PF_ANCHOR_SHA256
        or network["default_block_for_service_user"] is not True
        or network["literal_ip_tables_only"] is not True
        or network["allowed_egress_classes_observed"]
        != policy.payload["allowed_egress_classes"]
        or network["forbidden_target_connectivity"]
        != {
            target: False
            for target in policy.payload["forbidden_network_targets"]
        }
        or network["docker_socket_connectivity"] is not False
        or network["docker_network_membership"] is not False
        or network["unexpected_egress"] != []
    ):
        raise RegistryError("M2 egress isolation evidence failed")
    process = _exact(evidence["process"], PROCESS_KEYS, "M2 process")
    if (
        process["service_process_uid"] != identity["uid"]
        or process["service_process_gid"] != identity["gid"]
        or process["shared_process_identity"] is not False
        or process["shared_credential_scope"] is not False
        or process["shared_network_namespace"] is not False
    ):
        raise RegistryError("M2 process isolation evidence failed")
    evaluate_monitor(
        evidence["monitor_input"],
        policy=policy,
        now=captured,
    )
    monitor = evaluate_monitor(
        evidence["monitor_input"],
        policy=policy,
        now=now,
    )
    if monitor["status"] != "HEALTHY":
        raise RegistryError(
            "M2 monitor is degraded: " + ",".join(monitor["incidents"])
        )
    return {
        "schema_version": "vnpy_research_m2_isolation_result_v1",
        "status": "M2_RESEARCH_ISOLATION_VERIFIED",
        "policy_raw_sha256": policy.raw_sha256,
        "host_identity": evidence["host_identity"],
        "monitor": monitor,
        "authority": false_authority(),
    }
