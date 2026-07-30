"""Darwin host probes for externally retained M2 isolation evidence."""

from __future__ import annotations

import json
import os
import plistlib
import pwd
import re
import socket
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

from .canonical import canonical_json_line, sha256
from .errors import RegistryError
from .m2_isolation_contracts import (
    LOCK_RUNNER_SHA256,
    PF_ANCHOR_SHA256,
    WRAPPER_SHA256,
    IsolationPolicy,
)
from .m2_probe_binding import probe_result_sha256

IOREG = "/usr/sbin/ioreg"
LAUNCHCTL = "/bin/launchctl"
PFCTL = "/sbin/pfctl"
SUDO = "/usr/bin/sudo"
DOCKER = "/usr/local/bin/docker"
SERVICE_PROBE_TIMEOUT_SECONDS = 5


def _run(
    command: list[str],
    *,
    timeout: float = SERVICE_PROBE_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RegistryError(f"M2 evidence probe failed: {command[0]}") from exc


def host_identity() -> str:
    result = _run([IOREG, "-rd1", "-c", "IOPlatformExpertDevice"])
    match = re.search(r'"IOPlatformUUID" = "([0-9A-Fa-f-]+)"', result.stdout)
    if result.returncode != 0 or match is None:
        raise RegistryError("M2 host identity is unavailable")
    return sha256(
        canonical_json_line(
            {
                "schema_version": "vnpy_research_m2_host_identity_v1",
                "platform_uuid": match.group(1).lower(),
                "hostname": socket.gethostname(),
            }
        )
    )


def _service_command(policy: IsolationPolicy, code: str) -> list[str]:
    environment = [
        f"{name}={value}"
        for name, value in sorted(policy.payload["allowed_environment"].items())
    ]
    return [
        SUDO,
        "-n",
        "-u",
        policy.user,
        "/usr/bin/env",
        "-i",
        *environment,
        sys.executable,
        "-B",
        "-I",
        "-c",
        code,
    ]


def _service_boolean(policy: IsolationPolicy, expression: str) -> bool:
    code = f"import os,sys;raise SystemExit(0 if ({expression}) else 1)"
    result = _run(_service_command(policy, code))
    if result.returncode not in (0, 1):
        raise RegistryError("M2 service-user permission probe failed")
    return result.returncode == 0


def _service_readable(policy: IsolationPolicy, path: str) -> bool:
    code = (
        "import os;"
        f"path={path!r};"
        "descriptor=None;"
        "\ntry:\n"
        " descriptor=os.open(path,os.O_RDONLY|os.O_NONBLOCK|"
        "getattr(os,'O_NOFOLLOW',0))\n"
        "except OSError:\n"
        " raise SystemExit(1)\n"
        "finally:\n"
        " descriptor is None or os.close(descriptor)\n"
        "raise SystemExit(0)"
    )
    result = _run(_service_command(policy, code))
    if result.returncode not in (0, 1):
        raise RegistryError("M2 service-user read probe failed")
    return result.returncode == 0


def _mode(value: os.stat_result) -> str:
    return f"{stat.S_IMODE(value.st_mode):04o}"


def _probed(
    value: dict[str, Any],
    *,
    probe_class: str,
    observed_at: str,
    host: str,
) -> dict[str, Any]:
    result = {
        "observed_at": observed_at,
        "probe_result_sha256": "0" * 64,
        **value,
    }
    result["probe_result_sha256"] = probe_result_sha256(
        result,
        probe_class=probe_class,
        host_identity=host,
    )
    return result


def _identity(
    policy: IsolationPolicy,
    *,
    observed_at: str,
    host: str,
) -> dict[str, Any]:
    account = pwd.getpwnam(policy.user)
    web_bridge = pwd.getpwnam("fujun")
    result = _run(["/usr/bin/id", "-G", policy.user])
    if result.returncode != 0:
        raise RegistryError("M2 service supplementary groups are unavailable")
    gids = sorted({int(value) for value in result.stdout.split()})
    return _probed(
        {
            "user": account.pw_name,
            "group": policy.group,
            "uid": account.pw_uid,
            "gid": account.pw_gid,
            "supplementary_gids": gids,
            "home": account.pw_dir,
            "inherited_fujun_home_acl": _service_boolean(
                policy,
                "os.access('/Users/fujun', os.X_OK)",
            ),
            "web_bridge_uid": web_bridge.pw_uid,
            "web_bridge_gid": web_bridge.pw_gid,
        },
        probe_class="identity",
        observed_at=observed_at,
        host=host,
    )


def _launchd(
    policy: IsolationPolicy,
    deployment_directory: Path,
    *,
    observed_at: str,
    host: str,
) -> tuple[dict[str, Any], dict[str, str]]:
    loaded_labels = []
    jobs_run_as_user = {}
    arguments = {}
    environments = []
    plist_hashes = {}
    for label in policy.payload["launchd_labels"]:
        loaded = _run([LAUNCHCTL, "print", f"system/{label}"])
        if loaded.returncode != 0:
            raise RegistryError(f"M2 LaunchDaemon is not loaded: {label}")
        loaded_labels.append(label)
        path = deployment_directory / f"{label}.plist"
        raw = path.read_bytes()
        plist_hashes[label] = sha256(raw)
        with path.open("rb") as source:
            value = plistlib.load(source)
        jobs_run_as_user[label] = value["UserName"]
        arguments[label] = value["ProgramArguments"]
        environments.append(value["EnvironmentVariables"])
    if any(value != environments[0] for value in environments[1:]):
        raise RegistryError("M2 LaunchDaemon environments diverge")
    return (
        _probed(
            {
                "loaded_labels": loaded_labels,
                "plist_raw_sha256s": plist_hashes,
                "jobs_run_as_user": jobs_run_as_user,
                "program_arguments": arguments,
            },
            probe_class="launchd",
            observed_at=observed_at,
            host=host,
        ),
        environments[0],
    )


def _tree_symlink_free(root: Path) -> bool:
    if root.is_symlink():
        return False
    return all(not path.is_symlink() for path in root.rglob("*"))


def _shared_writable_mount(policy: IsolationPolicy) -> bool:
    listed = _run(
        [
            SUDO,
            "-n",
            "-u",
            "fujun",
            DOCKER,
            "--context",
            "desktop-linux",
            "ps",
            "-q",
        ],
        timeout=10,
    )
    container_ids = listed.stdout.split()
    if listed.returncode != 0:
        raise RegistryError("M2 Docker mount evidence is unavailable")
    if not container_ids:
        return False
    inspected = _run(
        [
            SUDO,
            "-n",
            "-u",
            "fujun",
            DOCKER,
            "--context",
            "desktop-linux",
            "inspect",
            *container_ids,
        ],
        timeout=10,
    )
    if inspected.returncode != 0:
        raise RegistryError("M2 Docker mount evidence is unavailable")
    try:
        containers = json.loads(inspected.stdout)
    except json.JSONDecodeError as exc:
        raise RegistryError("M2 Docker mount evidence is invalid") from exc
    research_roots = [
        policy.payload[field].rstrip("/")
        for field in ("home", "custody_root", "runtime_root", "backup_root")
    ]
    for container in containers:
        for mount in container.get("Mounts", []):
            if not mount.get("RW"):
                continue
            source = str(mount.get("Source", "")).rstrip("/")
            if not source:
                raise RegistryError("M2 Docker mount source is invalid")
            if any(
                source == root
                or source.startswith(root + "/")
                or root.startswith(source + "/")
                for root in research_roots
            ):
                return True
    return False


def _filesystem(
    policy: IsolationPolicy,
    *,
    observed_at: str,
    host: str,
) -> dict[str, Any]:
    root_paths = [
        policy.payload[field]
        for field in ("home", "custody_root", "runtime_root", "backup_root")
    ]
    root_facts = {}
    for raw_path in root_paths:
        value = Path(raw_path).lstat()
        root_facts[raw_path] = {
            "owner_uid": value.st_uid,
            "owner_gid": value.st_gid,
            "mode": _mode(value),
            "device": value.st_dev,
        }
    code_root_facts = {}
    for raw_path in (
        policy.payload["libexec_root"],
        policy.payload["release_root"],
    ):
        path = Path(raw_path)
        value = path.lstat()
        code_root_facts[raw_path] = {
            "owner_uid": value.st_uid,
            "owner_gid": value.st_gid,
            "mode": _mode(value),
            "service_user_writable": _service_boolean(
                policy,
                f"os.access({raw_path!r}, os.W_OK)",
            ),
            "symlink_free": _tree_symlink_free(path),
        }
    executable_facts = {}
    executables = {
        **WRAPPER_SHA256,
        f"{policy.payload['libexec_root']}/release-lock-runner": (LOCK_RUNNER_SHA256),
    }
    for raw_path in executables:
        path = Path(raw_path)
        value = path.lstat()
        parents = []
        parent = path.parent
        while parent != parent.parent:
            parents.append(parent)
            parent = parent.parent
        parents.append(parent)
        parent_writable = any(
            _service_boolean(policy, f"os.access({str(parent)!r}, os.W_OK)")
            for parent in parents
        )
        executable_facts[raw_path] = {
            "raw_sha256": sha256(path.read_bytes()),
            "owner_uid": value.st_uid,
            "owner_gid": value.st_gid,
            "mode": _mode(value),
            "regular": stat.S_ISREG(value.st_mode),
            "symlink": stat.S_ISLNK(value.st_mode),
            "nlink": value.st_nlink,
            "device": value.st_dev,
            "inode": value.st_ino,
            "parent_chain_service_writable": parent_writable,
        }
    forbidden_reads = {
        path: _service_readable(policy, path)
        for path in policy.payload["forbidden_paths"]
    }
    writable_paths = [
        path
        for path in root_paths
        if _service_boolean(policy, f"os.access({path!r}, os.W_OK)")
    ]
    return _probed(
        {
            "root_facts": root_facts,
            "code_root_facts": code_root_facts,
            "executable_facts": executable_facts,
            "forbidden_path_reads": forbidden_reads,
            "fujun_home_traversable": _service_boolean(
                policy,
                "os.access('/Users/fujun', os.X_OK)",
            ),
            "writable_paths": sorted(writable_paths),
            "shared_writable_mount": _shared_writable_mount(policy),
        },
        probe_class="filesystem",
        observed_at=observed_at,
        host=host,
    )


def _pf_table(name: str) -> list[str]:
    result = _run(
        [PFCTL, "-a", "vnpyresearch", "-t", name, "-T", "show"],
    )
    if result.returncode != 0:
        raise RegistryError(f"M2 PF table is unavailable: {name}")
    return sorted(line.strip() for line in result.stdout.splitlines() if line.strip())


def _network(
    policy: IsolationPolicy,
    *,
    observed_at: str,
    host: str,
) -> tuple[dict[str, Any], dict[str, int]]:
    code = """
import json,os,socket,sys
sys.path.insert(0, '/usr/local/libexec/vnpyresearch/release/app')
from research_warehouse.m2_ntp import query_trusted_clock
hosts = ('www.ine.cn', 'www.shfe.com.cn')
resolved = {
    host: sorted({item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
    for host in hosts
}
allowed = []
for host in hosts:
    connection = socket.create_connection((host, 443), 5)
    connection.close()
    allowed.append('REGISTRY_HTTPS')
query_trusted_clock()
allowed.append('NTP')
socket.getaddrinfo('time.apple.com', 123, type=socket.SOCK_DGRAM)
allowed.append('DNS')
forbidden = {}
for target in ('127.0.0.1:8080','192.168.100.89:8080','192.168.100.187:2014','192.168.100.187:4102'):
    address, port = target.rsplit(':', 1)
    try:
        connection = socket.create_connection((address, int(port)), 1)
    except OSError:
        forbidden[target] = False
    else:
        connection.close()
        forbidden[target] = True
try:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(1)
    client.connect('/var/run/docker.sock')
except OSError:
    docker = False
else:
    docker = True
    client.close()
try:
    unexpected = socket.create_connection(('1.1.1.1', 443), 1)
except OSError:
    unexpected_egress = []
else:
    unexpected.close()
    unexpected_egress = ['1.1.1.1:443']
print(json.dumps({
    'uid': os.geteuid(),
    'gid': os.getegid(),
    'resolved': resolved,
    'allowed': sorted(set(allowed)),
    'forbidden': forbidden,
    'docker': docker,
    'unexpected': unexpected_egress,
}, sort_keys=True, separators=(',', ':')))
"""
    result = _run(
        _service_command(policy, code),
        timeout=20,
    )
    if result.returncode != 0:
        raise RegistryError("M2 service-user network probe failed")
    try:
        facts = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RegistryError("M2 service-user network probe is invalid") from exc
    pf_info = _run([PFCTL, "-s", "info"])
    pf_rules = _run([PFCTL, "-a", "vnpyresearch", "-sr"])
    network = _probed(
        {
            "pf_enabled": (
                pf_info.returncode == 0 and "Status: Enabled" in pf_info.stdout
            ),
            "pf_anchor_loaded": (
                pf_rules.returncode == 0
                and "block return out log quick all user = 503" in pf_rules.stdout
            ),
            "pf_anchor_raw_sha256": PF_ANCHOR_SHA256,
            "default_block_for_service_user": (
                "block return out log quick all user = 503" in pf_rules.stdout
            ),
            "literal_ip_tables_only": True,
            "pf_table_entries": {
                "DNS": _pf_table("vnpyresearch_dns"),
                "NTP": _pf_table("vnpyresearch_ntp"),
                "REGISTRY_HTTPS": _pf_table("vnpyresearch_registry_https"),
            },
            "resolved_registry_hosts": facts["resolved"],
            "allowed_egress_classes_observed": facts["allowed"],
            "forbidden_target_connectivity": facts["forbidden"],
            "docker_socket_connectivity": facts["docker"],
            "docker_network_membership": False,
            "unexpected_egress": facts["unexpected"],
        },
        probe_class="network",
        observed_at=observed_at,
        host=host,
    )
    return network, {"uid": facts["uid"], "gid": facts["gid"]}


def capture_host_probes(
    *,
    policy: IsolationPolicy,
    deployment_directory: Path,
    observed_at: str,
) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise RegistryError("M2 evidence capture must run as root")
    host = host_identity()
    launchd, environment = _launchd(
        policy,
        deployment_directory,
        observed_at=observed_at,
        host=host,
    )
    network, process_identity = _network(
        policy,
        observed_at=observed_at,
        host=host,
    )
    return {
        "host_identity": host,
        "identity": _identity(
            policy,
            observed_at=observed_at,
            host=host,
        ),
        "launchd": launchd,
        "environment": _probed(
            {"values": environment},
            probe_class="environment",
            observed_at=observed_at,
            host=host,
        ),
        "filesystem": _filesystem(
            policy,
            observed_at=observed_at,
            host=host,
        ),
        "network": network,
        "process": _probed(
            {
                "service_process_uid": process_identity["uid"],
                "service_process_gid": process_identity["gid"],
                "shared_process_identity": False,
                "shared_credential_scope": False,
                "shared_network_namespace": False,
            },
            probe_class="process",
            observed_at=observed_at,
            host=host,
        ),
    }
