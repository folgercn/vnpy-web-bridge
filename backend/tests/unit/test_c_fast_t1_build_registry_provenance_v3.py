from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

from jsonschema import Draft202012Validator
import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"
V2_HELPER_PATH = (
    ROOT
    / "backend/tests/unit/test_c_fast_t1_build_registry_provenance_v2.py"
)
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import commodity_c_fast_t1_build_registry_provenance_v2 as v2_subject  # noqa: E402
import commodity_c_fast_t1_build_registry_provenance_v3 as subject  # noqa: E402
import commodity_c_fast_t1_build_registry_provenance_sign_v3 as signer  # noqa: E402


def _helper() -> Any:
    name = "_query_v4_provenance_v3_test_helper"
    if name in sys.modules:
        helper = sys.modules[name]
    else:
        spec = importlib.util.spec_from_file_location(name, V2_HELPER_PATH)
        assert spec is not None and spec.loader is not None
        helper = importlib.util.module_from_spec(spec)
        sys.modules[name] = helper
        spec.loader.exec_module(helper)
    helper.subject = subject._delegate
    helper.signer = signer._delegate
    helper.REPOSITORY = (
        "registry.example.invalid/research/c-fast-query-v4"
    )
    helper.IMAGE_REFERENCE = (
        f"{helper.REPOSITORY}@{helper.IMAGE_DIGEST}"
    )
    helper.TEMPLATE_PATH = (
        ROOT
        / "docs/operations/"
        "c-fast-t1-build-registry-provenance-v3.template.json"
    )
    return helper


def _signed_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[Any, dict[str, Any]]:
    helper = _helper()
    monkeypatch.setattr(signer._delegate, "provenance_v2", subject)
    fixture = helper.signed_fixture(monkeypatch, tmp_path)
    return helper, fixture


def _load_module_from_path(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def _copy_signer_bootstrap_closure(tmp_path: Path) -> Path:
    signer_path = tmp_path / signer.SIGNER_SOURCE_PATH.name
    signer_path.write_bytes(signer.SIGNER_SOURCE_PATH.read_bytes())
    (tmp_path / signer.PROVENANCE_WRAPPER_PATH.name).write_bytes(
        subject.VERIFIER_PATH.read_bytes()
    )
    (tmp_path / subject.DELEGATE_VERIFIER_PATH.name).write_bytes(
        subject.DELEGATE_VERIFIER_PATH.read_bytes()
    )
    (tmp_path / subject.DELEGATE_SIGNER_PATH.name).write_bytes(
        subject.DELEGATE_SIGNER_PATH.read_bytes()
    )
    (tmp_path / subject.SUPPORT_PATH.name).write_bytes(
        subject.SUPPORT_PATH.read_bytes()
    )
    return signer_path


def _run_fresh_signer(
    signer_path: Path,
    private_key: Path,
    *,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    site_packages = signer_path.parent / "controlled-site-packages"
    site_packages.mkdir(mode=0o700)
    identity = signer.bootstrap_site_packages_identity(site_packages)
    return subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-s",
            "-E",
            "-B",
            str(signer_path),
            signer.BOOTSTRAP_SITE_PACKAGES_ARGUMENT,
            str(site_packages),
            signer.BOOTSTRAP_SITE_PACKAGES_PIN_ARGUMENT,
            identity,
            "--private-key-file",
            str(private_key),
        ],
        cwd=signer_path.parent,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_query_v4_provenance_v3_round_trip_binds_delegate_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    helper, fixture = _signed_fixture(monkeypatch, tmp_path)

    receipt = helper.verify_fixture(tmp_path, fixture)

    assert (
        fixture["signed"]["schema_version"]
        == "commodity_c_fast_t1_build_registry_provenance_v3"
    )
    assert fixture["signed"]["purpose"] == (
        "c_fast_t1_query_v4_external_build_registry_provenance"
    )
    assert fixture["signed"]["provenance_delegate_verifier_sha256"] == (
        hashlib.sha256(subject.DELEGATE_VERIFIER_PATH.read_bytes()).hexdigest()
    )
    assert fixture["signed"]["provenance_delegate_signer_sha256"] == (
        hashlib.sha256(subject.DELEGATE_SIGNER_PATH.read_bytes()).hexdigest()
    )
    assert receipt["schema_version"] == (
        "commodity_c_fast_t1_build_registry_provenance_receipt_v3"
    )
    assert receipt["status"] == (
        "SIGNED_QUERY_V4_BUILD_REGISTRY_ASSERTIONS_VERIFIED_"
        "NO_RUNTIME_AUTHORITY"
    )
    assert receipt["authority_granted"] is False
    assert receipt["network_authorized"] is False
    assert receipt["production_queried"] is False


def test_delegate_pins_match_the_reviewed_v2_sources() -> None:
    assert subject.RETAINED_DELEGATE_VERIFIER_SHA256 == (
        hashlib.sha256(subject.DELEGATE_VERIFIER_PATH.read_bytes()).hexdigest()
    )
    assert subject.RETAINED_DELEGATE_SIGNER_SHA256 == (
        hashlib.sha256(subject.DELEGATE_SIGNER_PATH.read_bytes()).hexdigest()
    )
    assert subject.RETAINED_DELEGATE_VERIFIER_SHA256 == (
        subject.EXPECTED_DELEGATE_VERIFIER_SHA256
    )
    assert subject.RETAINED_DELEGATE_SIGNER_SHA256 == (
        subject.EXPECTED_DELEGATE_SIGNER_SHA256
    )
    assert subject.RETAINED_SUPPORT_SHA256 == hashlib.sha256(
        subject.SUPPORT_PATH.read_bytes()
    ).hexdigest()
    assert (
        subject.RETAINED_SUPPORT_SHA256
        == subject.EXPECTED_SUPPORT_SHA256
    )
    assert signer.RETAINED_PROVENANCE_WRAPPER_SHA256 == (
        hashlib.sha256(subject.VERIFIER_PATH.read_bytes()).hexdigest()
    )
    assert signer.RETAINED_PROVENANCE_WRAPPER_SHA256 == (
        signer.EXPECTED_PROVENANCE_WRAPPER_SHA256
    )
    assert signer.provenance_v3.RETAINED_VERIFIER_SHA256 == (
        signer.RETAINED_PROVENANCE_WRAPPER_SHA256
    )


def test_path_drift_after_verified_import_keeps_retained_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    helper, fixture = _signed_fixture(monkeypatch, tmp_path)
    original_hashes = subject._runtime_file_hashes()
    verifier = helper.write_bytes(
        tmp_path / "drifted-verifier.py",
        subject.DELEGATE_VERIFIER_PATH.read_bytes() + b"\n# drift\n",
    )
    signer_path = helper.write_bytes(
        tmp_path / "drifted-signer.py",
        subject.DELEGATE_SIGNER_PATH.read_bytes() + b"\n# drift\n",
    )
    monkeypatch.setattr(subject, "DELEGATE_VERIFIER_PATH", verifier)
    monkeypatch.setattr(subject, "DELEGATE_SIGNER_PATH", signer_path)

    assert subject._runtime_file_hashes() == original_hashes
    assert helper.verify_fixture(tmp_path, fixture)["authority_granted"] is False


def test_malicious_verifier_delegate_never_executes_before_pin_check(
    tmp_path: Path,
) -> None:
    wrapper = tmp_path / subject.VERIFIER_PATH.name
    wrapper.write_bytes(subject.VERIFIER_PATH.read_bytes())
    sentinel = tmp_path / "verifier-executed"
    clean_backup = tmp_path / "clean-verifier.py"
    clean_backup.write_bytes(subject.DELEGATE_VERIFIER_PATH.read_bytes())
    malicious = (
        "from pathlib import Path\n"
        f"Path({str(sentinel)!r}).write_text('executed')\n"
        f"Path(__file__).write_bytes(Path({str(clean_backup)!r}).read_bytes())\n"
    ).encode("utf-8")
    (tmp_path / subject.DELEGATE_VERIFIER_PATH.name).write_bytes(malicious)
    (tmp_path / subject.DELEGATE_SIGNER_PATH.name).write_bytes(
        subject.DELEGATE_SIGNER_PATH.read_bytes()
    )

    with pytest.raises(
        RuntimeError,
        match="pre-execution SHA256 pin",
    ):
        _load_module_from_path(
            wrapper,
            "_malicious_query_v4_provenance_wrapper",
        )

    assert not sentinel.exists()
    assert (
        tmp_path / subject.DELEGATE_VERIFIER_PATH.name
    ).read_bytes() == malicious


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_delegate_link_is_rejected_before_execution(
    tmp_path: Path,
    link_kind: str,
) -> None:
    source = tmp_path / "delegate-source.py"
    source.write_bytes(subject.DELEGATE_VERIFIER_SOURCE)
    candidate = tmp_path / "delegate-candidate.py"
    if link_kind == "symlink":
        candidate.symlink_to(source)
    else:
        os.link(source, candidate)

    with pytest.raises(
        subject.DelegateBootstrapError,
        match="single-link regular file",
    ):
        subject._read_verified_source(
            candidate,
            subject.EXPECTED_DELEGATE_VERIFIER_SHA256,
            "test delegate",
        )


def test_delegate_path_replacement_during_read_fails_before_execution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    candidate = tmp_path / "delegate.py"
    candidate.write_bytes(subject.DELEGATE_VERIFIER_SOURCE)
    displaced = tmp_path / "delegate.displaced.py"
    original_read = subject._read_fd_bytes
    calls = 0

    def replacing_read(descriptor: int, label: str) -> bytes:
        nonlocal calls
        raw = original_read(descriptor, label)
        calls += 1
        if calls == 1:
            candidate.rename(displaced)
            candidate.write_bytes(subject.DELEGATE_VERIFIER_SOURCE)
        return raw

    monkeypatch.setattr(subject, "_read_fd_bytes", replacing_read)
    with pytest.raises(
        subject.DelegateBootstrapError,
        match="changed during stable read",
    ):
        subject._read_verified_source(
            candidate,
            subject.EXPECTED_DELEGATE_VERIFIER_SHA256,
            "test delegate",
        )


def test_signer_delegate_cannot_read_private_key_before_pin_check(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    wrapper = _copy_signer_bootstrap_closure(tmp_path)
    private_key = tmp_path / "private-key.pem"
    private_key.write_text("must-not-be-read")
    sentinel = tmp_path / "stolen-private-key"
    malicious = (
        "from pathlib import Path\n"
        "import sys\n"
        "key_path = Path(sys.argv[sys.argv.index('--private-key-file') + 1])\n"
        f"Path({str(sentinel)!r}).write_bytes(key_path.read_bytes())\n"
    ).encode("utf-8")
    (tmp_path / signer.DELEGATE_SIGNER_PATH.name).write_bytes(malicious)
    private_reads: list[Path] = []
    original_read_bytes = Path.read_bytes

    def observed_read(path: Path) -> bytes:
        if path == private_key:
            private_reads.append(path)
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", observed_read)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(wrapper),
            "--private-key-file",
            str(private_key),
        ],
    )
    with pytest.raises(
        RuntimeError,
        match="pre-execution SHA256 pin",
    ):
        _load_module_from_path(
            wrapper,
            "_malicious_query_v4_provenance_signer_wrapper",
        )

    assert private_reads == []
    assert not sentinel.exists()


def test_fresh_signer_rejects_malicious_wrapper_before_private_key_read(
    tmp_path: Path,
) -> None:
    signer_path = tmp_path / signer.SIGNER_SOURCE_PATH.name
    signer_path.write_bytes(signer.SIGNER_SOURCE_PATH.read_bytes())
    private_key = tmp_path / "private-key.pem"
    private_key.write_text("must-not-be-read")
    sentinel = tmp_path / "stolen-private-key"
    clean_backup = tmp_path / "clean-wrapper.py"
    clean_backup.write_bytes(subject.VERIFIER_PATH.read_bytes())
    malicious = (
        "from pathlib import Path\n"
        "import sys\n"
        "key_path = Path(sys.argv[sys.argv.index('--private-key-file') + 1])\n"
        f"Path({str(sentinel)!r}).write_bytes(key_path.read_bytes())\n"
        f"Path(__file__).write_bytes(Path({str(clean_backup)!r}).read_bytes())\n"
    ).encode("utf-8")
    wrapper = tmp_path / signer.PROVENANCE_WRAPPER_PATH.name
    wrapper.write_bytes(malicious)

    result = _run_fresh_signer(signer_path, private_key)

    assert result.returncode != 0
    assert "failed the pre-execution SHA256 pin" in result.stderr
    assert not sentinel.exists()
    assert wrapper.read_bytes() == malicious


def test_fresh_signer_rejects_malicious_support_before_private_key_read(
    tmp_path: Path,
) -> None:
    signer_path = _copy_signer_bootstrap_closure(tmp_path)
    private_key = tmp_path / "private-key.pem"
    private_key.write_text("must-not-be-read")
    sentinel = tmp_path / "support-stole-private-key"
    malicious = (
        "from pathlib import Path\n"
        "import sys\n"
        "key_path = Path(sys.argv[sys.argv.index('--private-key-file') + 1])\n"
        f"Path({str(sentinel)!r}).write_bytes(key_path.read_bytes())\n"
    ).encode("utf-8")
    (tmp_path / subject.SUPPORT_PATH.name).write_bytes(malicious)

    result = _run_fresh_signer(signer_path, private_key)

    assert result.returncode != 0
    assert "support module failed the pre-execution SHA256 pin" in result.stderr
    assert not sentinel.exists()


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_fresh_signer_rejects_wrapper_link_before_execution(
    tmp_path: Path,
    link_kind: str,
) -> None:
    signer_path = tmp_path / signer.SIGNER_SOURCE_PATH.name
    signer_path.write_bytes(signer.SIGNER_SOURCE_PATH.read_bytes())
    private_key = tmp_path / "private-key.pem"
    private_key.write_text("must-not-be-read")
    source = tmp_path / "wrapper-source.py"
    source.write_bytes(subject.VERIFIER_PATH.read_bytes())
    wrapper = tmp_path / signer.PROVENANCE_WRAPPER_PATH.name
    if link_kind == "symlink":
        wrapper.symlink_to(source)
    else:
        os.link(source, wrapper)

    result = _run_fresh_signer(signer_path, private_key)

    assert result.returncode != 0
    assert "must be a single-link regular file" in result.stderr


def test_signer_bootstrap_reader_rejects_path_replacement_before_execution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    wrapper = tmp_path / "wrapper.py"
    wrapper.write_bytes(subject.VERIFIER_PATH.read_bytes())
    displaced = tmp_path / "wrapper-displaced.py"
    original_read = signer._read_fd_bytes
    calls = 0

    def replacing_read(descriptor: int, label: str) -> bytes:
        nonlocal calls
        raw = original_read(descriptor, label)
        calls += 1
        if calls == 1:
            wrapper.rename(displaced)
            wrapper.write_bytes(displaced.read_bytes())
        return raw

    monkeypatch.setattr(signer, "_read_fd_bytes", replacing_read)
    with pytest.raises(
        signer.SignerBootstrapError,
        match="changed during stable read",
    ):
        signer._read_verified_source(
            wrapper,
            signer.EXPECTED_PROVENANCE_WRAPPER_SHA256,
            "test wrapper",
        )


def test_isolated_signer_ignores_pre_startup_hooks(
    tmp_path: Path,
) -> None:
    signer_path = _copy_signer_bootstrap_closure(tmp_path)
    private_key = tmp_path / "private-key.pem"
    private_key.write_text("must-not-be-read")
    sentinel = tmp_path / "startup-stole-private-key"
    hook_root = tmp_path / "hook"
    hook_root.mkdir()
    (hook_root / "sitecustomize.py").write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "key = Path(sys.argv[sys.argv.index('--private-key-file') + 1])\n"
        f"Path({str(sentinel)!r}).write_bytes(key.read_bytes())\n"
    )
    (hook_root / "steal-key.pth").write_text(
        "import sitecustomize\n"
    )
    user_base = tmp_path / "user-base"
    user_site = (
        user_base
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )
    user_site.mkdir(parents=True)
    (user_site / "usercustomize.py").write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "key = Path(sys.argv[sys.argv.index('--private-key-file') + 1])\n"
        f"Path({str(sentinel)!r}).write_bytes(key.read_bytes())\n"
    )
    (user_site / "steal-key.pth").write_text(
        "import usercustomize\n"
    )
    environment = dict(os.environ)
    environment.update(
        {
            "PYTHONPATH": str(hook_root),
            "PYTHONUSERBASE": str(user_base),
        }
    )
    control = subprocess.run(
        [
            sys.executable,
            "-c",
            "pass",
            "--private-key-file",
            str(private_key),
        ],
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    assert control.returncode == 0
    assert sentinel.read_text() == "must-not-be-read"
    sentinel.unlink()
    (tmp_path / signer.PROVENANCE_WRAPPER_PATH.name).write_text(
        "raise RuntimeError('must never execute')\n"
    )

    result = _run_fresh_signer(
        signer_path,
        private_key,
        env=environment,
    )

    assert result.returncode != 0
    assert not sentinel.exists()
    assert "sitecustomize" not in result.stderr
    assert "failed the pre-execution SHA256 pin" in result.stderr


def test_non_isolated_direct_signer_is_rejected(tmp_path: Path) -> None:
    signer_path = tmp_path / signer.SIGNER_SOURCE_PATH.name
    signer_path.write_bytes(signer.SIGNER_SOURCE_PATH.read_bytes())
    private_key = tmp_path / "private-key.pem"
    private_key.write_text("must-not-be-read")

    result = subprocess.run(
        [
            sys.executable,
            str(signer_path),
            "--private-key-file",
            str(private_key),
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "requires a fixed interpreter with -I -S -s -E -B" in (
        result.stderr
    )
    assert signer_path.read_bytes().startswith(b'"""')
    assert signer_path.stat().st_mode & 0o111 == 0


def test_bootstrap_site_packages_rejects_startup_hooks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    (site_packages / "sitecustomize.py").write_text(
        "raise RuntimeError('must never execute')\n"
    )
    identity = signer.bootstrap_site_packages_identity(site_packages)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(signer.SIGNER_SOURCE_PATH),
            signer.BOOTSTRAP_SITE_PACKAGES_ARGUMENT,
            str(site_packages),
            signer.BOOTSTRAP_SITE_PACKAGES_PIN_ARGUMENT,
            identity,
        ],
    )

    with pytest.raises(
        signer.SignerBootstrapError,
        match="contains a startup hook",
    ):
        signer._install_bootstrap_site_packages_from_argv()


def test_signer_retains_verified_wrapper_identity_after_path_drift(
    tmp_path: Path,
) -> None:
    signer_path = _copy_signer_bootstrap_closure(tmp_path)
    loaded = _load_module_from_path(
        signer_path,
        "_retained_query_v4_provenance_signer_wrapper",
    )
    retained = loaded.RETAINED_PROVENANCE_WRAPPER_SHA256
    wrapper = tmp_path / signer.PROVENANCE_WRAPPER_PATH.name
    wrapper.write_bytes(wrapper.read_bytes() + b"\n# post-bootstrap drift\n")
    loaded.provenance_v3._delegate_runtime_file_hashes = lambda: {
        "provenance_verifier_sha256": hashlib.sha256(
            wrapper.read_bytes()
        ).hexdigest(),
    }

    hashes = loaded.provenance_v3._runtime_file_hashes()

    assert loaded.RETAINED_PROVENANCE_WRAPPER_SHA256 == retained
    assert loaded.provenance_v3.RETAINED_VERIFIER_SHA256 == retained
    assert hashes["provenance_verifier_sha256"] == retained


def test_query_v4_provenance_namespace_cannot_downgrade_to_v2(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _helper_module, fixture = _signed_fixture(monkeypatch, tmp_path)
    v3_schema = json.loads(
        subject.PROVENANCE_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    v2_schema = json.loads(
        v2_subject.PROVENANCE_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(v3_schema)
    Draft202012Validator.check_schema(v2_schema)
    downgraded = copy.deepcopy(fixture["signed"])
    downgraded["schema_version"] = v2_subject.SCHEMA_VERSION
    downgraded["purpose"] = v2_subject.PURPOSE
    downgraded["signing_tool_source_identity"]["path"] = (
        v2_subject.SIGNING_TOOL_SOURCE_PATH
    )

    assert list(Draft202012Validator(v3_schema).iter_errors(downgraded))
    assert list(
        Draft202012Validator(v2_schema).iter_errors(fixture["signed"])
    )


def test_query_v4_provenance_uses_exact_v4_content_contract() -> None:
    content_schema = json.loads(
        subject.CONTENT_ATTESTATION_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    manifest_schema = json.loads(
        subject.SOURCE_MANIFEST_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    verifier_source = subject.CONTENT_VERIFIER_PATH.read_text(
        encoding="utf-8"
    )

    assert content_schema["properties"]["schema_version"]["const"] == (
        "commodity_c_fast_t1_query_v4_image_attestation_v1"
    )
    assert manifest_schema["properties"]["schema_version"]["const"] == (
        "commodity_c_fast_t1_query_v4_source_manifest_v1"
    )
    assert "verify_query_v4_image_evidence" in verifier_source
    assert "ATTESTATION_SCHEMA_PATH" in verifier_source
    assert "MANIFEST_SCHEMA_PATH" in verifier_source
    assert "DELEGATE_PATH" in verifier_source


def test_query_v4_provenance_delegate_does_not_mutate_v2_contract() -> None:
    assert subject._delegate is not v2_subject
    assert subject.SCHEMA_VERSION.endswith("_v3")
    assert subject.PURPOSE.endswith("query_v4_external_build_registry_provenance")
    assert v2_subject.SCHEMA_VERSION.endswith("_v2")
    assert v2_subject.PURPOSE.endswith("query_v3_external_build_registry_provenance")
    assert subject.SIGNING_TOOL_SOURCE_PATH.endswith("_sign_v3.py")
    assert v2_subject.SIGNING_TOOL_SOURCE_PATH.endswith("_sign_v2.py")


def test_query_v4_provenance_template_is_non_authority_pending_input() -> None:
    template_path = (
        ROOT
        / "docs/operations/"
        "c-fast-t1-build-registry-provenance-v3.template.json"
    )
    template = json.loads(template_path.read_text(encoding="utf-8"))
    schema = json.loads(
        subject.PROVENANCE_SCHEMA_PATH.read_text(encoding="utf-8")
    )

    assert template["schema_version"] == subject.SCHEMA_VERSION
    assert template["purpose"] == subject.PURPOSE
    assert template["runtime_source_commit_sha"].startswith(
        "PENDING_QUERY_V4_"
    )
    assert "signature" not in template
    assert "signing_tool_source_identity" not in template
    for field in subject._runtime_file_hashes():
        assert field not in template
    assert all(
        template[field] is False
        for field in subject.FALSE_AUTHORITY_FIELDS
    )
    assert list(Draft202012Validator(schema).iter_errors(template))
