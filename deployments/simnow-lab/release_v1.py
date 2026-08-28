"""Issue #466 exact-SHA M2 release installer; intentionally not reusable."""

from __future__ import annotations

import argparse
import base64
import fcntl
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

ROOT = Path("/Users/fujun/services/vnpy-web-bridge")
PYTHON = Path("/opt/homebrew/opt/python@3.13/bin/python3.13")
DOCKER = Path("/Applications/Docker.app/Contents/Resources/bin/docker")
WINDOWS_HOST = "wxuser@192.168.100.187"
LABEL = "com.folgercn.simnow-lab"
SHA = re.compile(r"^[0-9a-f]{40}$")
WINDOWS_RUNTIME = re.compile(r"^C:\\quant\\runtime-[0-9a-f]+$")
WEB_AREAS = frozenset({"backend", "frontend"})
LAB_RUNTIME_AREAS = frozenset({"m2", "windows"})


class ReleaseError(RuntimeError):
    pass


@contextmanager
def one_shot_deployment_lock(root: Path, areas: set[str]):
    """Prevent M2/Windows replacement while the launchd one-shot owns Lab."""

    if not areas & LAB_RUNTIME_AREAS:
        yield
        return
    path = root / "runtime" / "simnow-lab" / ".target.json.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise ReleaseError("SIMNOW_LAB_ONE_SHOT_BUSY") from exc
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    capture: bool = False,
    env: dict[str, str] | None = None,
) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
    )
    return completed.stdout.strip() if capture else ""


def read_manifest(release: Path | None) -> dict[str, Any]:
    if release is None:
        return {}
    try:
        value = json.loads((release / ".release.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def current_release(root: Path) -> Path | None:
    current = root / "current"
    return current.resolve() if current.is_symlink() and current.exists() else None


def atomic_symlink(link: Path, target: Path) -> None:
    temporary = link.with_name(f".{link.name}.{os.getpid()}.tmp")
    temporary.unlink(missing_ok=True)
    temporary.symlink_to(target)
    os.replace(temporary, link)
    directory_fd = os.open(link.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def ensure_env(root: Path) -> None:
    target = root / ".env"
    if target.exists():
        return
    source = root / "source" / ".deploy.env"
    if not source.is_file():
        raise ReleaseError("M2_ENV_MISSING")
    shutil.copyfile(source, target)
    target.chmod(0o600)


def ensure_venv(root: Path, release: Path) -> None:
    venv = root / ".venv"
    if not (venv / "bin" / "python").exists():
        if not PYTHON.exists():
            raise ReleaseError("PYTHON_313_MISSING")
        run([str(PYTHON), "-m", "venv", str(venv)])
    python = venv / "bin" / "python"
    version = run(
        [str(python), "-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"],
        capture=True,
    )
    if version != "3.13":
        raise ReleaseError("M2_VENV_PYTHON_VERSION_MISMATCH")
    run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-deps",
            "vnpy==4.4.0",
            "pyzmq==27.1.0",
        ]
    )
    run([str(python), "-c", "from vnpy.rpc import RpcClient; import zmq; print('M2_RUNTIME_OK')"])


def build_release(source: Path, root: Path, sha: str, *, trusted_archive: bool = False) -> Path:
    release = root / "releases" / sha
    if release.exists():
        try:
            source_sha = (release / ".source-sha").read_text(encoding="ascii").strip()
        except OSError:
            source_sha = ""
        if source_sha != sha:
            raise ReleaseError("RELEASE_IDENTITY_MISMATCH")
        return release
    (root / "releases").mkdir(parents=True, exist_ok=True)
    stage = root / "releases" / f".{sha}.tmp.{os.getpid()}"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)
    source_marker = source / ".source-sha"
    if trusted_archive and source_marker.is_file() and source_marker.read_text(encoding="ascii").strip() == sha:
        shutil.copytree(source, stage, dirs_exist_ok=True)
    else:
        commit = run(
            ["git", "-C", str(source), "rev-parse", "--verify", f"{sha}^{{commit}}"],
            capture=True,
        )
        if commit != sha:
            raise ReleaseError("RELEASE_COMMIT_IDENTITY_MISMATCH")
        with tempfile.NamedTemporaryFile(suffix=".tar") as archive:
            run(["git", "-C", str(source), "archive", "--format=tar", "--output", archive.name, sha])
            with tarfile.open(archive.name) as bundle:
                bundle.extractall(stage, filter="data")
    (stage / ".source-sha").write_text(f"{sha}\n", encoding="ascii")
    os.replace(stage, release)
    releases_fd = os.open(release.parent, os.O_RDONLY)
    try:
        os.fsync(releases_fd)
    finally:
        os.close(releases_fd)
    return release


def powershell(script: str, *, capture: bool = False) -> str:
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return run(
        ["ssh", "-o", "BatchMode=yes", WINDOWS_HOST, "powershell", "-NoProfile", "-EncodedCommand", encoded],
        capture=capture,
    )


def windows_current_runtime() -> str:
    script = r"""
$text = [IO.File]::ReadAllText('C:\quant\run_rpc_server.py')
$match = [regex]::Match($text, 'VALIDATION_RUNTIME_ROOT = Path\(r"(?<root>C:\\quant\\runtime-[0-9a-f]+)"\)')
if (-not $match.Success) { throw 'WINDOWS_RUNTIME_ROOT_NOT_FOUND' }
$match.Groups['root'].Value
"""
    value = powershell(script, capture=True).splitlines()[-1].strip()
    if WINDOWS_RUNTIME.fullmatch(value) is None:
        raise ReleaseError("WINDOWS_RUNTIME_ROOT_INVALID")
    return value


def switch_windows_runtime(old: str, new: str) -> None:
    script = rf"""
$path = 'C:\quant\run_rpc_server.py'
$text = [IO.File]::ReadAllText($path)
if ([regex]::Matches($text, [regex]::Escape('{old}')).Count -ne 1) {{ throw 'WINDOWS_RUNTIME_SWITCH_SOURCE_MISMATCH' }}
$temp = "$path.issue466.tmp"
[IO.File]::WriteAllText($temp, $text.Replace('{old}', '{new}'), (New-Object Text.UTF8Encoding($false)))
Move-Item -Force $temp $path
try {{
    Restart-Service VnpyRpcService
    $service = Get-Service VnpyRpcService
    if ($service.Status -ne 'Running') {{ throw 'WINDOWS_SERVICE_NOT_RUNNING' }}
}} catch {{
    [IO.File]::WriteAllText($temp, $text, (New-Object Text.UTF8Encoding($false)))
    Move-Item -Force $temp $path
    Restart-Service VnpyRpcService
    throw
}}
"""
    powershell(script)


def deploy_windows(release: Path, sha: str) -> tuple[str, str]:
    old = windows_current_runtime()
    new = f"C:\\quant\\runtime-{sha[:8]}"
    if old == new:
        return old, new
    temporary = f"{new}.tmp"
    powershell(
        rf"Remove-Item -Recurse -Force -ErrorAction SilentlyContinue '{temporary}'; "
        rf"Copy-Item -Recurse -Force '{old}' '{temporary}'; "
        rf"New-Item -ItemType Directory -Force '{temporary}\scripts\windows_simnow_lab' | Out-Null"
    )
    files = (
        "scripts/windows_simnow_lab/__init__.py",
        "scripts/windows_simnow_lab/executor_v1.py",
        "scripts/windows_simnow_lab/dashboard_v1.py",
    )
    try:
        for relative in files:
            remote = f"{WINDOWS_HOST}:C:/quant/runtime-{sha[:8]}.tmp/{relative}"
            run(["scp", "-q", str(release / relative), remote])
        checks = []
        for relative in files:
            windows_relative = relative.replace("/", "\\")
            checks.append(f"(Test-Path '{temporary}\\{windows_relative}')")
        upload_checks = " -and ".join(checks)
        powershell(
            rf"if (-not ({upload_checks})) {{ throw 'WINDOWS_RUNTIME_UPLOAD_INCOMPLETE' }}; "
            rf"Remove-Item -Recurse -Force -ErrorAction SilentlyContinue '{new}'; "
            rf"Move-Item -Force '{temporary}' '{new}'"
        )
    finally:
        powershell(
            rf"if (Test-Path '{temporary}') {{ Remove-Item -Recurse -Force '{temporary}' }}"
        )
    switch_windows_runtime(old, new)
    return old, new


def dashboard_smoke(root: Path, release: Path) -> None:
    output = run(
        [
            str(root / ".venv" / "bin" / "python"),
            "-m",
            "scripts.windows_simnow_lab.cli_v1",
            "get-run",
            "--run-id",
            "DASHBOARD",
        ],
        cwd=release,
        capture=True,
    )
    value = json.loads(output.splitlines()[-1])
    if value.get("schema_version") != "simnow_lab_dashboard_v1":
        raise ReleaseError("DASHBOARD_READONLY_SMOKE_FAILED")


def compose_env(manifest: dict[str, Any]) -> dict[str, str]:
    env = os.environ.copy()
    env["PATH"] = f"{DOCKER.parent}:{env.get('PATH', '')}"
    env.update(
        RELEASE_SHA=str(manifest["sha"]),
        CONTROL_API_IMAGE=str(manifest["control_image"]),
        FRONTEND_IMAGE=str(manifest["frontend_image"]),
    )
    return env


def compose(release: Path, manifest: dict[str, Any], *arguments: str) -> None:
    path = release / "deployments" / "docker-compose.simnow-lab-dashboard.yml"
    subprocess.run(
        [str(DOCKER), "--context", "desktop-linux", "compose", "-f", str(path), *arguments],
        cwd=release,
        env=compose_env(manifest),
        check=True,
    )


def compose_output(release: Path, manifest: dict[str, Any], *arguments: str) -> str:
    path = release / "deployments" / "docker-compose.simnow-lab-dashboard.yml"
    return run(
        [str(DOCKER), "--context", "desktop-linux", "compose", "-f", str(path), *arguments],
        cwd=release,
        capture=True,
        env=compose_env(manifest),
    )


def build_web(release: Path, manifest: dict[str, Any], areas: set[str]) -> None:
    services = []
    if "backend" in areas:
        services.append("control-api")
    if "frontend" in areas:
        services.append("frontend-edge")
    if services:
        compose(release, manifest, "build", *services)


def deploy_web(release: Path, manifest: dict[str, Any], areas: set[str]) -> None:
    services = []
    if "backend" in areas:
        services.append("control-api")
    if "frontend" in areas:
        services.append("frontend-edge")
    if not services:
        return
    compose(release, manifest, "up", "-d", "--no-build", "--no-deps", *services)
    deadline = time.monotonic() + 90
    pending = set(services)
    while pending and time.monotonic() < deadline:
        for service in tuple(pending):
            container_id = compose_output(release, manifest, "ps", "-q", service)
            if container_id and run([str(DOCKER), "inspect", "-f", "{{.State.Health.Status}}", container_id], capture=True) == "healthy":
                pending.remove(service)
        if pending:
            time.sleep(2)
    if pending:
        raise ReleaseError(f"WEB_READONLY_HEALTH_FAILED:{','.join(sorted(pending))}")


def dashboard_http_smoke(release: Path, manifest: dict[str, Any]) -> None:
    code = """import json,urllib.request
from app.core.security import CurrentUser,create_access_token
token=create_access_token(CurrentUser('cd-smoke','viewer'))
request=urllib.request.Request('http://127.0.0.1:8081/api/v1/simnow-lab/dashboard',headers={'Authorization':f'Bearer {token}'})
value=json.load(urllib.request.urlopen(request,timeout=12))
assert value['data']['dashboard']['schema_version']=='simnow_lab_dashboard_v1'
"""
    compose(release, manifest, "exec", "-T", "control-api", "python", "-c", code)


def install_launch_agent(root: Path, release: Path) -> None:
    destination = Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(release / "deployments" / "com.vnpy-web-bridge.simnow-lab.plist", destination)
    domain = f"gui/{os.getuid()}"
    subprocess.run(["launchctl", "bootout", domain, str(destination)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run(["launchctl", "bootstrap", domain, str(destination)])
    run(["launchctl", "enable", f"{domain}/{LABEL}"])


def write_manifest(release: Path, manifest: dict[str, Any]) -> None:
    temporary = release / ".release.json.tmp"
    temporary.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, release / ".release.json")


def deploy(
    source: Path,
    root: Path,
    sha: str,
    channel: str,
    areas: set[str],
    *,
    trusted_archive: bool = False,
) -> None:
    if SHA.fullmatch(sha) is None or channel not in {"candidate", "main"}:
        raise ReleaseError("RELEASE_ARGUMENT_INVALID")
    previous = current_release(root)
    previous_manifest = read_manifest(previous)
    all_areas = {"backend", "frontend", "windows", "m2"}
    if (not previous_manifest or previous_manifest.get("channel") != "main") and areas != all_areas:
        raise ReleaseError("INITIAL_RELEASE_REQUIRES_ALL_AREAS")
    release = build_release(source, root, sha, trusted_archive=trusted_archive)
    ensure_env(root)
    ensure_venv(root, release)
    manifest = {
        "sha": sha,
        "channel": channel,
        "control_image": f"vnpy-web-bridge-control-api:{sha}" if "backend" in areas else previous_manifest.get("control_image"),
        "frontend_image": f"vnpy-web-bridge-frontend:{sha}" if "frontend" in areas else previous_manifest.get("frontend_image"),
        "windows_runtime": previous_manifest.get("windows_runtime"),
        "areas": sorted(areas),
    }
    if not manifest["control_image"] or not manifest["frontend_image"]:
        raise ReleaseError("WEB_IMAGE_IDENTITY_MISSING")
    with one_shot_deployment_lock(root, areas):
        old_windows = None
        try:
            if "windows" in areas:
                old_windows, manifest["windows_runtime"] = deploy_windows(release, sha)
            dashboard_smoke(root, release)
            build_web(release, manifest, areas)
            write_manifest(release, manifest)
            if previous:
                atomic_symlink(root / "previous", previous)
            atomic_symlink(root / "current", release)
            if "m2" in areas:
                install_launch_agent(root, release)
            if areas & WEB_AREAS:
                deploy_web(release, manifest, areas)
            if "backend" in areas:
                dashboard_http_smoke(release, manifest)
        except Exception:
            if previous:
                atomic_symlink(root / "current", previous)
                if "m2" in areas:
                    install_launch_agent(root, previous)
                if areas & WEB_AREAS and previous_manifest:
                    deploy_web(previous, previous_manifest, areas)
            else:
                current = root / "current"
                if current.is_symlink() and current.resolve() == release:
                    current.unlink()
                if areas & WEB_AREAS:
                    compose(release, manifest, "down")
            if old_windows and manifest.get("windows_runtime") != old_windows:
                switch_windows_runtime(str(manifest["windows_runtime"]), old_windows)
            raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--channel", choices=("candidate", "main"), required=True)
    parser.add_argument("--areas", default="backend,frontend,windows,m2")
    parser.add_argument("--trusted-archive", action="store_true")
    args = parser.parse_args()
    deploy(
        args.source.resolve(),
        args.root.resolve(),
        args.sha,
        args.channel,
        {item for item in args.areas.split(",") if item},
        trusted_archive=args.trusted_archive,
    )
    print(json.dumps({"status": "DEPLOYED", "sha": args.sha, "channel": args.channel}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
