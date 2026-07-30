"""Verify static deployment assets and captured M2 isolation evidence."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta
from typing import Any

from .errors import RegistryError
from .m2_isolation_contracts import (
    LOCK_RUNNER_SHA256,
    PF_ANCHOR_SHA256,
    PLIST_SHA256,
    WRAPPER_SHA256,
    IsolationPolicy,
    false_authority,
    require_sha,
)
from .m2_monitor import evaluate_monitor
from .m2_probe_binding import verify_probe_result_sha256
from .m2_release_artifacts import VerifiedReleaseArtifacts
from .m2_success_binding import verify_release_success_binding
from .timeutil import parse_utc

IDENTITY_KEYS = {
    "observed_at",
    "probe_result_sha256",
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
LAUNCHD_KEYS = {
    "observed_at",
    "probe_result_sha256",
    "loaded_labels",
    "plist_raw_sha256s",
    "jobs_run_as_user",
    "program_arguments",
}
ENVIRONMENT_KEYS = {"observed_at", "probe_result_sha256", "values"}
FILESYSTEM_KEYS = {
    "observed_at",
    "probe_result_sha256",
    "root_facts",
    "code_root_facts",
    "executable_facts",
    "forbidden_path_reads",
    "fujun_home_traversable",
    "writable_paths",
    "shared_writable_mount",
}
NETWORK_KEYS = {
    "observed_at",
    "probe_result_sha256",
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
    "observed_at",
    "probe_result_sha256",
    "service_process_uid",
    "service_process_gid",
    "shared_process_identity",
    "shared_credential_scope",
    "shared_network_namespace",
}
ROOT_FACT_KEYS = {"owner_uid", "owner_gid", "mode", "device"}
CODE_ROOT_FACT_KEYS = {
    "owner_uid",
    "owner_gid",
    "mode",
    "service_user_writable",
    "symlink_free",
}
EXECUTABLE_FACT_KEYS = {
    "raw_sha256",
    "owner_uid",
    "owner_gid",
    "mode",
    "regular",
    "symlink",
    "nlink",
    "device",
    "inode",
    "parent_chain_service_writable",
}
ACTIVATION_KEYS = {
    "policy_activated_at",
    "pf_loaded_at",
    "launchd_loaded_at",
    "policy_raw_sha256",
    "pf_anchor_raw_sha256",
    "plist_raw_sha256s",
}


def _exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise RegistryError(f"{label} fields do not match v1")
    return value


def _ip_list(value: object, label: str, *, public: bool) -> list[str]:
    if not isinstance(value, list) or not value or len(value) != len(set(value)):
        raise RegistryError(f"{label} must be a unique non-empty IP list")
    result = []
    for item in value:
        if not isinstance(item, str):
            raise RegistryError(f"{label} contains a non-string IP")
        try:
            address = ipaddress.ip_address(item)
        except ValueError as exc:
            raise RegistryError(f"{label} contains an invalid IP") from exc
        if (
            address.is_unspecified
            or address.is_multicast
            or (public and not address.is_global)
        ):
            raise RegistryError(f"{label} contains a forbidden IP")
        result.append(address.compressed)
    if result != value:
        raise RegistryError(f"{label} IPs are not canonical")
    return result


def verify_isolation_evidence_semantics(
    evidence: dict[str, Any],
    *,
    policy: IsolationPolicy,
    now: datetime,
    release_artifacts: VerifiedReleaseArtifacts,
) -> dict[str, Any]:
    _exact(
        evidence,
        {
            "schema_version",
            "captured_at",
            "host_identity",
            "policy_raw_sha256",
            "registry_raw_sha256",
            "release_tree_raw_sha256",
            "release_tree_manifest_raw_sha256",
            "release_lock_identity",
            "activation",
            "identity",
            "launchd",
            "environment",
            "filesystem",
            "network",
            "process",
            "monitor_input",
            "success_receipt",
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
        require_sha(evidence["host_identity"], "M2 host identity") == "0" * 64
        or evidence["policy_raw_sha256"] != policy.raw_sha256
        or evidence["registry_raw_sha256"] != policy.payload["registry_raw_sha256"]
        or evidence["authority"] != false_authority()
    ):
        raise RegistryError("M2 evidence top-level binding mismatch")
    activation = _exact(
        evidence["activation"],
        ACTIVATION_KEYS,
        "M2 activation",
    )
    activation_times = [
        parse_utc(activation[field], f"M2 activation {field}")
        for field in (
            "policy_activated_at",
            "pf_loaded_at",
            "launchd_loaded_at",
        )
    ]
    activated = max(activation_times)
    if (
        activated > captured
        or activation["policy_raw_sha256"] != policy.raw_sha256
        or activation["pf_anchor_raw_sha256"] != PF_ANCHOR_SHA256
        or activation["plist_raw_sha256s"] != PLIST_SHA256
    ):
        raise RegistryError("M2 activation binding mismatch")

    def verify_probe(
        value: dict[str, Any],
        label: str,
        probe_class: str,
    ) -> None:
        observed = parse_utc(value["observed_at"], f"{label} observed_at")
        if observed < activated or observed > captured:
            raise RegistryError(f"{label} predates active policy")
        verify_probe_result_sha256(
            value,
            probe_class=probe_class,
            host_identity=evidence["host_identity"],
        )

    identity = _exact(evidence["identity"], IDENTITY_KEYS, "M2 identity")
    verify_probe(identity, "M2 identity", "identity")
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
    verify_probe(launchd, "M2 launchd", "launchd")
    if (
        launchd["loaded_labels"] != policy.payload["launchd_labels"]
        or launchd["plist_raw_sha256s"] != PLIST_SHA256
        or launchd["jobs_run_as_user"]
        != {label: policy.user for label in policy.payload["launchd_labels"]}
        or launchd["program_arguments"]
        != {
            label: [policy.payload["program_paths"][label]]
            for label in policy.payload["launchd_labels"]
        }
    ):
        raise RegistryError("M2 launchd evidence mismatch")
    environment = _exact(
        evidence["environment"],
        ENVIRONMENT_KEYS,
        "M2 environment",
    )
    verify_probe(environment, "M2 environment", "environment")
    if environment["values"] != policy.payload["allowed_environment"]:
        raise RegistryError("M2 process environment is not exact minimal environment")
    filesystem = _exact(
        evidence["filesystem"],
        FILESYSTEM_KEYS,
        "M2 filesystem",
    )
    verify_probe(filesystem, "M2 filesystem", "filesystem")
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
    code_roots = filesystem["code_root_facts"]
    expected_code_roots = {
        policy.payload["libexec_root"],
        policy.payload["release_root"],
    }
    if not isinstance(code_roots, dict) or set(code_roots) != expected_code_roots:
        raise RegistryError("M2 root-owned code root set mismatch")
    for facts in code_roots.values():
        _exact(facts, CODE_ROOT_FACT_KEYS, "M2 code root fact")
        if (
            facts["owner_uid"] != 0
            or facts["owner_gid"] != 0
            or facts["mode"] != "0755"
            or facts["service_user_writable"] is not False
            or facts["symlink_free"] is not True
        ):
            raise RegistryError("M2 code root is service-user writable")
    executables = filesystem["executable_facts"]
    expected_executables = {
        **WRAPPER_SHA256,
        f"{policy.payload['libexec_root']}/release-lock-runner": (LOCK_RUNNER_SHA256),
    }
    if not isinstance(executables, dict) or set(executables) != set(
        expected_executables
    ):
        raise RegistryError("M2 executable evidence set mismatch")
    for path, facts in executables.items():
        _exact(facts, EXECUTABLE_FACT_KEYS, "M2 executable fact")
        if (
            facts["raw_sha256"] != expected_executables[path]
            or facts["owner_uid"] != 0
            or facts["owner_gid"] != 0
            or facts["mode"] != "0555"
            or facts["regular"] is not True
            or facts["symlink"] is not False
            or facts["nlink"] != 1
            or any(
                isinstance(facts[field], bool)
                or not isinstance(facts[field], int)
                or facts[field] <= 0
                for field in ("device", "inode")
            )
            or facts["parent_chain_service_writable"] is not False
        ):
            raise RegistryError("M2 executable custody mismatch")
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
    verify_probe(network, "M2 network", "network")
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
    if not isinstance(resolutions, dict) or set(resolutions) != set(
        policy.payload["allowed_https_hosts"]
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
        != {target: False for target in policy.payload["forbidden_network_targets"]}
        or network["docker_socket_connectivity"] is not False
        or network["docker_network_membership"] is not False
        or network["unexpected_egress"] != []
    ):
        raise RegistryError("M2 egress isolation evidence failed")
    process = _exact(evidence["process"], PROCESS_KEYS, "M2 process")
    verify_probe(process, "M2 process", "process")
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
    verify_release_success_binding(
        evidence,
        policy=policy,
        release_artifacts=release_artifacts,
        identity=identity,
        activated=activated,
        captured=captured,
    )
    monitor = evaluate_monitor(
        evidence["monitor_input"],
        policy=policy,
        now=now,
    )
    if monitor["status"] != "HEALTHY":
        raise RegistryError("M2 monitor is degraded: " + ",".join(monitor["incidents"]))
    return {
        "schema_version": "vnpy_research_m2_isolation_semantics_result_v1",
        "status": "M2_RESEARCH_ISOLATION_SEMANTICS_VERIFIED",
        "policy_raw_sha256": policy.raw_sha256,
        "release_tree_raw_sha256": evidence["release_tree_raw_sha256"],
        "release_tree_manifest_raw_sha256": evidence[
            "release_tree_manifest_raw_sha256"
        ],
        "host_identity": evidence["host_identity"],
        "monitor": monitor,
        "authority": false_authority(),
    }
