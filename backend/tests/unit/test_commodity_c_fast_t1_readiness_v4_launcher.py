from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[3]
LAUNCHER = ROOT / "scripts/commodity_c_fast_t1_readiness_v4_launcher.py"
VERIFIER = ROOT / "scripts/commodity_c_fast_t1_readiness_v4.py"
FIXED_FLAGS = ("-I", "-S", "-s", "-E", "-B")


def run_fresh(
    *arguments: str,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *arguments],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def test_launcher_rejects_non_isolated_interpreter() -> None:
    result = run_fresh(str(LAUNCHER))

    assert result.returncode != 0
    assert "requires a fixed interpreter with -I -S -s -E -B" in result.stderr


def test_verifier_rejects_direct_entry_before_dependency_imports(
    tmp_path: Path,
) -> None:
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    sentinel = tmp_path / "imported"
    (shadow / "commodity_c_fast_t1_one_shot.py").write_text(
        f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('bad')\n",
        encoding="utf-8",
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(shadow)

    result = run_fresh(str(VERIFIER), env=env)

    assert result.returncode != 0
    assert "readiness-v4 is not a direct entry point" in result.stderr
    assert not sentinel.exists()


def test_fixed_startup_ignores_sitecustomize_and_pythonpath_shadow(
    tmp_path: Path,
) -> None:
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    sentinel = tmp_path / "startup-hook-ran"
    payload = (
        "from pathlib import Path\n"
        f"Path({str(sentinel)!r}).write_text('bad')\n"
    )
    (shadow / "sitecustomize.py").write_text(payload, encoding="utf-8")
    (shadow / "hashlib.py").write_text(payload, encoding="utf-8")
    (shadow / "commodity_c_fast_t1_readiness_v4.py").write_text(
        payload,
        encoding="utf-8",
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(shadow)

    result = run_fresh(*FIXED_FLAGS, str(LAUNCHER), env=env)

    assert result.returncode == 2
    assert "trusted launcher failed" in result.stderr
    assert not sentinel.exists()


def test_dependency_scan_rejects_startup_hook_in_fresh_process(
    tmp_path: Path,
) -> None:
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    (site_packages / "injected.pth").write_text(
        "import attacker\n",
        encoding="utf-8",
    )
    code = """
import runpy
import sys
from pathlib import Path
namespace = runpy.run_path(sys.argv[1])
try:
    namespace["scan_dependency_closure"](Path(sys.argv[2]))
except namespace["ReadinessLauncherError"] as exc:
    assert "startup hook is forbidden" in str(exc)
else:
    raise AssertionError("startup hook was accepted")
"""

    result = run_fresh(
        *FIXED_FLAGS,
        "-c",
        code,
        str(LAUNCHER),
        str(site_packages),
    )

    assert result.returncode == 0, result.stderr


def test_retained_source_survives_path_drift_and_manifest_detects_it(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "runtime"
    scripts = source_root / "scripts"
    scripts.mkdir(parents=True)
    verifier = scripts / "commodity_c_fast_t1_readiness_v4.py"
    verifier.write_text("VALUE = 'trusted'\n", encoding="utf-8")
    code = """
import runpy
import sys
from pathlib import Path
namespace = runpy.run_path(sys.argv[1])
root = Path(sys.argv[2])
verifier = root / "scripts/commodity_c_fast_t1_readiness_v4.py"
first, retained = namespace["scan_source_closure"](root)
scope = {}
raw, retained_path, _ = retained["commodity_c_fast_t1_readiness_v4"]
exec(compile(raw, str(retained_path), "exec"), scope)
assert scope["VALUE"] == "trusted"
verifier.write_text("VALUE = 'drifted'\\n", encoding="utf-8")
second, _ = namespace["scan_source_closure"](root)
assert first != second
assert scope["VALUE"] == "trusted"
"""

    result = run_fresh(
        *FIXED_FLAGS,
        "-c",
        code,
        str(LAUNCHER),
        str(source_root),
    )

    assert result.returncode == 0, result.stderr


def test_source_closure_rejects_symlink_escape_in_fresh_process(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "runtime"
    scripts = source_root / "scripts"
    scripts.mkdir(parents=True)
    target = tmp_path / "outside.py"
    target.write_text("VALUE = 'outside'\n", encoding="utf-8")
    (scripts / "commodity_c_fast_t1_readiness_v4.py").symlink_to(target)
    code = """
import runpy
import sys
from pathlib import Path
namespace = runpy.run_path(sys.argv[1])
try:
    namespace["scan_source_closure"](Path(sys.argv[2]))
except namespace["ReadinessLauncherError"] as exc:
    assert "symlink is forbidden" in str(exc)
else:
    raise AssertionError("symlink source escape was accepted")
"""

    result = run_fresh(
        *FIXED_FLAGS,
        "-c",
        code,
        str(LAUNCHER),
        str(source_root),
    )

    assert result.returncode == 0, result.stderr


def test_retained_loader_owns_namespace_package_in_fresh_process(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "runtime"
    package = source_root / "scripts/c_fast_t1"
    package.mkdir(parents=True)
    (source_root / "scripts/commodity_c_fast_t1_readiness_v4.py").write_text(
        "VALUE = 'readiness'\n",
        encoding="utf-8",
    )
    (package / "verified.py").write_text(
        "VALUE = 'retained-namespace'\n",
        encoding="utf-8",
    )
    code = """
import importlib
import runpy
import sys
from pathlib import Path
namespace = runpy.run_path(sys.argv[1])
root = Path(sys.argv[2])
_, retained = namespace["scan_source_closure"](root)
loader = namespace["_RetainedSourceLoader"](retained, root / "scripts")
sys.meta_path.insert(0, loader)
module = importlib.import_module("c_fast_t1.verified")
assert module.VALUE == "retained-namespace"
assert module.__spec__.loader is loader
assert sys.modules["c_fast_t1"].__spec__.loader is loader
"""

    result = run_fresh(
        *FIXED_FLAGS,
        "-c",
        code,
        str(LAUNCHER),
        str(source_root),
    )

    assert result.returncode == 0, result.stderr
