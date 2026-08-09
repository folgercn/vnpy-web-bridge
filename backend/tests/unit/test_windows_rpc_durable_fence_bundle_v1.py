from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from backend.tests.unit.windows_fence_public_fixture_v1 import public_keyring_raw_v1
import scripts.windows_rpc_durable_fence_v1 as durable_module
from scripts.windows_fence_foundation.bundle_v1 import (
    COMPONENT_PATHS,
    FIXED_FILE_MODE,
    FIXED_ZIP_TIMESTAMP,
    BuiltWindowsFenceBundleV1,
    WindowsFenceBundleError,
    _build_zip,
    _validate_archive_path,
    build_windows_fence_bundle_v1,
    verify_windows_fence_bundle_v1,
)
from scripts.windows_fence_foundation.contracts import canonical_json_bytes

ROOT = Path(__file__).resolve().parents[3]
CONFIG_RAW = canonical_json_bytes(
    {
        "schema_version": "windows_rpc_durable_fence_service_config_v1",
        "purpose": "launch_fixed_frozen_windows_rpc_service",
        "store_root": r"C:\ProgramData\vnpy-web-bridge\windows-fence\store",
        "store_expectation": {
            "service_name": "VnpyRpcService",
            "store_id": "windows-fence-store-" + "a" * 64,
            "store_path_sha256": hashlib.sha256(
                rb"C:\ProgramData\vnpy-web-bridge\windows-fence\store"
            ).hexdigest(),
            "store_volume_serial": "A1B2C3D4",
            "store_volume_identity_sha256": "a" * 64,
            "owner_sid_sha256": hashlib.sha256(b"test-owner").hexdigest(),
            "directory_acl_sddl_sha256": hashlib.sha256(b"test-acl").hexdigest(),
            "state_acl_sddl_sha256": "a" * 64,
        },
        "installer_store_bootstrap": {
            "root_path": r"C:\ProgramData\vnpy-web-bridge\windows-fence\store",
            "root_path_sha256": hashlib.sha256(
                rb"C:\ProgramData\vnpy-web-bridge\windows-fence\store"
            ).hexdigest(),
            "owner_sid": "test-owner",
            "directory_acl_sddl": "test-acl",
        },
        "runtime_config": {
            "gateway_name": "CTP",
            "account_scope": "account:windows",
            "environment": "simnow",
            "credential_descriptor": {
                "path": r"C:\ProgramData\vnpy-web-bridge\windows-fence\credentials\credential-descriptor-v1.json",
                "path_sha256": hashlib.sha256(
                    rb"C:\ProgramData\vnpy-web-bridge\windows-fence\credentials\credential-descriptor-v1.json"
                ).hexdigest(),
                "raw_sha256": "b" * 64,
                "owner_sid_sha256": "c" * 64,
                "acl_sddl_sha256": "d" * 64,
            },
            "pub_address": "tcp://*:4102",
            "rep_address": "tcp://*:2014",
        },
    }
)
STORE_BINDING = {
    "service_name": "VnpyRpcService",
    "store_path_sha256": hashlib.sha256(
        rb"C:\ProgramData\vnpy-web-bridge\windows-fence\store"
    ).hexdigest(),
    "store_volume_serial": "A1B2C3D4",
    "store_volume_identity_sha256": "a" * 64,
    "owner_sid_sha256": hashlib.sha256(b"test-owner").hexdigest(),
    "directory_acl_sddl_sha256": hashlib.sha256(b"test-acl").hexdigest(),
    "state_acl_sddl_sha256": "a" * 64,
}
PUBLIC_KEYRING_RAW = public_keyring_raw_v1()
KEYRING_CANONICAL_PATH = Path("/ProgramData/vnpy-web-bridge/installer-keyring.json")
EXPECTED_SOURCE_SHA256 = os.environ.get("GITHUB_SHA", "a" * 64)


def _build_bundle(source_root: Path = ROOT) -> BuiltWindowsFenceBundleV1:
    return build_windows_fence_bundle_v1(
        source_root,
        config_raw=CONFIG_RAW,
        expected_store_binding=STORE_BINDING,
        public_keyring_raw=PUBLIC_KEYRING_RAW,
        keyring_canonical_path=KEYRING_CANONICAL_PATH,
        expected_source_sha256=EXPECTED_SOURCE_SHA256,
    )


@pytest.fixture(scope="module")
def built() -> BuiltWindowsFenceBundleV1:
    return _build_bundle()


def _outer_entries(raw: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        return {info.filename: archive.read(info) for info in archive.infolist()}


def _replace_index(raw: bytes, mutate: object) -> bytes:
    value = json.loads(raw)
    assert isinstance(value, dict)
    mutate(value)  # type: ignore[operator]
    return canonical_json_bytes(value)


def _ordinary_zip(entries: dict[str, bytes], *, compression: int) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=compression) as archive:
        for path, raw in entries.items():
            archive.writestr(path, raw)
    return output.getvalue()


def test_bundle_is_byte_reproducible_and_detached_index_verifies(
    built: BuiltWindowsFenceBundleV1,
) -> None:
    rebuilt = _build_bundle()
    verified = verify_windows_fence_bundle_v1(
        built.bundle_raw, built.index_raw, expected_store_binding=STORE_BINDING
    )

    assert rebuilt == built
    assert built.index_raw not in built.bundle_raw
    assert verified.bundle_sha256 == built.bundle_sha256
    assert verified.index_raw_sha256 == built.index_raw_sha256
    assert verified.assembly_archive_raw_sha256 == (built.assembly_archive_raw_sha256)
    assert verified.assembly_source_inventory_sha256 == (
        built.assembly_source_inventory_sha256
    )
    assert set(verified.component_sha256s) == set(COMPONENT_PATHS)
    assert (
        b"gateway_setting"
        not in _outer_entries(built.bundle_raw)[COMPONENT_PATHS["config"]]
    )


def test_outer_and_assembly_zip_have_exact_fixed_metadata(
    built: BuiltWindowsFenceBundleV1,
) -> None:
    with zipfile.ZipFile(io.BytesIO(built.bundle_raw)) as outer:
        assert outer.comment == b""
        assert [item.filename for item in outer.infolist()] == sorted(
            COMPONENT_PATHS.values()
        )
        for item in outer.infolist():
            assert item.compress_type == zipfile.ZIP_STORED
            assert item.date_time == FIXED_ZIP_TIMESTAMP
            assert item.create_system == 3
            assert item.external_attr == FIXED_FILE_MODE << 16
            assert item.extra == item.comment == b""
        assembly = outer.read(COMPONENT_PATHS["assembly"])
        extension = outer.read(COMPONENT_PATHS["extension"])

    with zipfile.ZipFile(io.BytesIO(assembly)) as archive:
        assert [item.filename for item in archive.infolist()] == [
            "scripts/__init__.py",
            "scripts/windows_fence_foundation/__init__.py",
            "scripts/windows_fence_foundation/_installer_trust_anchor_generated_v1.py",
            "scripts/windows_fence_foundation/admission.py",
            "scripts/windows_fence_foundation/assembly.py",
            "scripts/windows_fence_foundation/bootstrap_v1.py",
            "scripts/windows_fence_foundation/bundle_v1.py",
            "scripts/windows_fence_foundation/contracts.py",
            "scripts/windows_fence_foundation/credential_config_v1.py",
            "scripts/windows_fence_foundation/final_admission_v1.py",
            "scripts/windows_fence_foundation/final_store_v1.py",
            "scripts/windows_fence_foundation/generate_installer_trust_anchor_v1.py",
            "scripts/windows_fence_foundation/installer_bootstrap_v1.py",
            "scripts/windows_fence_foundation/installer_entry_v1.py",
            "scripts/windows_fence_foundation/installer_trust_anchor_v1.py",
            "scripts/windows_fence_foundation/installer_windows_v1.py",
            "scripts/windows_fence_foundation/manifest_v1.py",
            "scripts/windows_fence_foundation/native_windows_installer_host_v1.py",
            "scripts/windows_fence_foundation/store.py",
            "scripts/windows_fence_foundation/target_contract_v1.py",
            "scripts/windows_fence_foundation/trust_pins_v1.py",
            "scripts/windows_fence_foundation/win32_fs.py",
            "scripts/windows_rpc_deployment_snapshot_v1.py",
        ]
        assert archive.read("scripts/__init__.py") == b""
        assert archive.read("scripts/windows_rpc_deployment_snapshot_v1.py") == (
            extension
        )


def test_generated_anchor_is_a_mandatory_indexed_assembly_source(
    built: BuiltWindowsFenceBundleV1,
) -> None:
    index = json.loads(built.index_raw)
    source = next(
        item
        for item in index["assembly_sources"]
        if item["path"]
        == "windows_fence_foundation/_installer_trust_anchor_generated_v1.py"
    )
    assert source["raw_sha256"] != "0" * 64
    assert built.expected_source_sha256 == EXPECTED_SOURCE_SHA256


def test_formal_bundle_build_without_public_material_fails_closed() -> None:
    with pytest.raises(WindowsFenceBundleError, match="PUBLIC_INPUT_REQUIRED"):
        build_windows_fence_bundle_v1(
            ROOT, config_raw=CONFIG_RAW, expected_store_binding=STORE_BINDING
        )


def test_installed_launcher_imports_archive_and_hashes_published_bytes(
    tmp_path: Path,
    built: BuiltWindowsFenceBundleV1,
) -> None:
    entries = _outer_entries(built.bundle_raw)
    for archive_path in COMPONENT_PATHS.values():
        (tmp_path / Path(archive_path).name).write_bytes(entries[archive_path])

    assembly_path = tmp_path / Path(COMPONENT_PATHS["assembly"]).name
    command = (
        "import json,runpy,sys;"
        f"sys.argv=['launcher','--assembly',{str(assembly_path)!r},"
        f"'--assembly-sha256',{built.assembly_archive_raw_sha256!r}];"
        f"m=runpy.run_path({str(tmp_path / Path(COMPONENT_PATHS['launcher']).name)!r});"
        "from scripts import windows_rpc_deployment_snapshot_v1 as extension;"
        "from scripts.windows_fence_foundation.installer_trust_anchor_v1 import load_production_installer_trust_anchor_v1;"
        "anchor=load_production_installer_trust_anchor_v1();"
        "closure=m['_runtime_closure_hashes']();"
        "closure['extension_imported_from_archive']=extension.__file__.startswith('<verified-foundation-assembly>');"
        "closure['anchor_source_sha256']=anchor.expected_source_sha256;"
        "print(json.dumps(closure,sort_keys=True))"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", command],
        check=True,
        capture_output=True,
        text=True,
    )
    closure = json.loads(result.stdout)
    verified = verify_windows_fence_bundle_v1(
        built.bundle_raw, built.index_raw, expected_store_binding=STORE_BINDING
    )

    assert closure["assembly_sha256"] == verified.component_sha256s["assembly"]
    assert closure["launcher_sha256"] == verified.component_sha256s["launcher"]
    assert closure["extension_sha256"] == verified.component_sha256s["extension"]
    assert closure["extension_imported_from_archive"] is True
    assert closure["anchor_source_sha256"] == EXPECTED_SOURCE_SHA256

    bad = command.replace(built.assembly_archive_raw_sha256, "0" * 64)
    rejected = subprocess.run(
        [sys.executable, "-I", "-c", bad],
        check=False,
        capture_output=True,
        text=True,
    )
    assert rejected.returncode != 0
    assert "FOUNDATION_ASSEMBLY_PREIMPORT_BINDING_MISMATCH" in rejected.stderr


def test_published_pythonclass_imports_from_clean_pythonpath(
    tmp_path: Path, built: BuiltWindowsFenceBundleV1
) -> None:
    wrapper = _outer_entries(built.bundle_raw)[COMPONENT_PATHS["wrapper"]]
    (tmp_path / "windows_rpc_service_wrapper_v1.py").write_bytes(wrapper)
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            (
                f"import sys;sys.path.insert(0,{str(tmp_path)!r});"
                "import windows_rpc_service_wrapper_v1 as module;"
                "assert module.SERVICE_WRAPPER_REGISTRY_V1['python_class']=="
                "'windows_rpc_service_wrapper_v1.VnpyRpcServiceWrapperV1'"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_installed_main_validates_all_components_loads_config_and_launches(
    tmp_path: Path,
    built: BuiltWindowsFenceBundleV1,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = _outer_entries(built.bundle_raw)
    paths: dict[str, Path] = {}
    for role, archive_path in COMPONENT_PATHS.items():
        path = tmp_path / Path(archive_path).name
        path.write_bytes(entries[archive_path])
        paths[role] = path
    monkeypatch.setattr(durable_module, "__file__", str(paths["launcher"]))
    captured: dict[str, object] = {}

    def fake_launch(**kwargs: object) -> None:
        captured.update(kwargs)

    monkeypatch.setattr(
        durable_module, "_launch_windows_rpc_durable_fence_bound_v1", fake_launch
    )
    monkeypatch.setattr(
        durable_module,
        "load_local_credential_descriptor_v1",
        lambda *_args, **_kwargs: type("Descriptor", (), {"gateway_name": "CTP"})(),
    )
    monkeypatch.setattr(
        durable_module,
        "load_gateway_setting_from_local_blob_v1",
        lambda *_args, **_kwargs: {"user": "unit-only"},
    )
    monkeypatch.setattr(
        durable_module, "_production_windows_filesystem", lambda: object()
    )
    verified = verify_windows_fence_bundle_v1(
        built.bundle_raw, built.index_raw, expected_store_binding=STORE_BINDING
    )
    arguments: list[str] = []
    for role in ("extension", "assembly", "config"):
        arguments.extend(
            [
                f"--{role}",
                str(paths[role]),
                f"--{role}-sha256",
                verified.component_sha256s[role],
            ]
        )

    durable_module._main(arguments)

    assert captured["store_root"] == (
        r"C:\ProgramData\vnpy-web-bridge\windows-fence\store"
    )
    assert captured["config_binding_sha256"] == verified.component_sha256s["config"]
    assert captured["store_expectation"].service_name == "VnpyRpcService"  # type: ignore[union-attr]


def test_one_byte_component_change_changes_component_assembly_and_bundle(
    tmp_path: Path,
    built: BuiltWindowsFenceBundleV1,
) -> None:
    scripts = tmp_path / "scripts"
    foundation = scripts / "windows_fence_foundation"
    foundation.mkdir(parents=True)
    for source in (ROOT / "scripts" / "windows_fence_foundation").iterdir():
        if source.name.endswith(".py"):
            (foundation / source.name).write_bytes(source.read_bytes())
    (scripts / "windows_rpc_deployment_snapshot_v1.py").write_bytes(
        (ROOT / "scripts" / "windows_rpc_deployment_snapshot_v1.py").read_bytes()
    )
    (scripts / "windows_rpc_durable_fence_v1.py").write_bytes(
        (ROOT / "scripts" / "windows_rpc_durable_fence_v1.py").read_bytes()
    )
    (scripts / "windows_rpc_service_wrapper_v1.py").write_bytes(
        (ROOT / "scripts" / "windows_rpc_service_wrapper_v1.py").read_bytes()
    )
    target = foundation / "store.py"
    target.write_bytes(target.read_bytes() + b"\n# deterministic-drift\n")

    changed = _build_bundle(tmp_path)
    assert changed.assembly_source_inventory_sha256 != (
        built.assembly_source_inventory_sha256
    )
    assert changed.assembly_archive_raw_sha256 != built.assembly_archive_raw_sha256
    assert changed.bundle_sha256 != built.bundle_sha256


@pytest.mark.parametrize(
    "path",
    [
        "../escape",
        "a/../escape",
        "/absolute",
        "//server/share",
        "C:/drive",
        "safe:stream",
        "a\\b",
        "a//b",
        "a/./b",
        "NUL.txt",
        "dir/COM1",
        "trailing.",
        "trailing ",
        "not-nfc-e\u0301",
    ],
)
def test_windows_unsafe_archive_paths_are_rejected(path: str) -> None:
    with pytest.raises(WindowsFenceBundleError, match="BUNDLE_PATH_UNSAFE"):
        _validate_archive_path(path)


def test_casefold_collision_is_rejected() -> None:
    with pytest.raises(WindowsFenceBundleError, match="CASEFOLD"):
        _build_zip({"a/File.py": b"1", "a/file.py": b"2"})


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update({"unknown": True}),
        lambda value: value.pop("bundle_sha256"),
        lambda value: value.update({"bundle_sha256": "0" * 64}),
        lambda value: value["components"][0].update({"size_bytes": 0}),
        lambda value: value["components"][0].update({"raw_sha256": "0" * 64}),
        lambda value: value["components"].reverse(),
        lambda value: value["assembly_sources"][0].update({"raw_sha256": "0" * 64}),
        lambda value: value.update({"assembly_source_inventory_sha256": "0" * 64}),
    ],
)
def test_index_unknown_missing_order_size_and_hash_drift_fail_closed(
    built: BuiltWindowsFenceBundleV1, mutation: object
) -> None:
    index = _replace_index(built.index_raw, mutation)
    with pytest.raises(WindowsFenceBundleError):
        verify_windows_fence_bundle_v1(
            built.bundle_raw, index, expected_store_binding=STORE_BINDING
        )


@pytest.mark.parametrize(
    "index_raw",
    [
        b'{"schema_version":"x","schema_version":"y"}',
        b'{"float":1.0}',
        b'{"text":"e\\u0301"}',
        b'{ "space":true}',
        b"[]",
    ],
)
def test_index_duplicate_float_non_nfc_and_noncanonical_json_rejected(
    built: BuiltWindowsFenceBundleV1, index_raw: bytes
) -> None:
    with pytest.raises(WindowsFenceBundleError):
        verify_windows_fence_bundle_v1(
            built.bundle_raw, index_raw, expected_store_binding=STORE_BINDING
        )


def test_unknown_missing_compressed_and_metadata_drift_fail_closed(
    built: BuiltWindowsFenceBundleV1,
) -> None:
    entries = _outer_entries(built.bundle_raw)
    variants = []
    missing = dict(entries)
    missing.pop(COMPONENT_PATHS["config"])
    variants.append(_build_zip(missing))
    unknown = dict(entries)
    unknown["components/unknown.py"] = b"pass\n"
    variants.append(_build_zip(unknown))
    variants.append(_ordinary_zip(entries, compression=zipfile.ZIP_DEFLATED))
    variants.append(_ordinary_zip(entries, compression=zipfile.ZIP_STORED))
    variants.append(built.bundle_raw + b"trailing-data")

    for raw in variants:
        index = _replace_index(
            built.index_raw,
            lambda value, digest=raw: value.update(
                {"bundle_sha256": __import__("hashlib").sha256(digest).hexdigest()}
            ),
        )
        with pytest.raises(WindowsFenceBundleError):
            verify_windows_fence_bundle_v1(
                raw, index, expected_store_binding=STORE_BINDING
            )


def test_assembly_unknown_missing_and_casefold_splice_fail_closed(
    built: BuiltWindowsFenceBundleV1,
) -> None:
    outer = _outer_entries(built.bundle_raw)
    assembly = _outer_entries(outer[COMPONENT_PATHS["assembly"]])
    mutations: list[dict[str, bytes]] = []
    missing = dict(assembly)
    missing.pop("scripts/windows_fence_foundation/store.py")
    mutations.append(missing)
    unknown = dict(assembly)
    unknown["scripts/windows_fence_foundation/unknown.py"] = b"pass\n"
    mutations.append(unknown)
    collision = dict(assembly)
    collision["scripts/windows_fence_foundation/STORE.py"] = b"pass\n"
    mutations.append(collision)

    for mutated in mutations:
        with pytest.raises(WindowsFenceBundleError):
            assembly_raw = _build_zip(mutated)
            changed_outer = dict(outer)
            changed_outer[COMPONENT_PATHS["assembly"]] = assembly_raw
            bundle_raw = _build_zip(changed_outer)
            bundle_digest = hashlib.sha256(bundle_raw).hexdigest()
            assembly_digest = hashlib.sha256(assembly_raw).hexdigest()
            index = _replace_index(
                built.index_raw,
                lambda value, bundle_digest=bundle_digest, assembly_digest=assembly_digest: (
                    value.update(
                        {
                            "bundle_sha256": bundle_digest,
                            "assembly_archive_raw_sha256": assembly_digest,
                        }
                    )
                ),
            )
            verify_windows_fence_bundle_v1(
                bundle_raw, index, expected_store_binding=STORE_BINDING
            )


def test_zip_bomb_style_declared_size_and_archive_bounds_rejected(
    built: BuiltWindowsFenceBundleV1,
) -> None:
    oversized_index = _replace_index(
        built.index_raw,
        lambda value: value["components"][0].update(
            {"size_bytes": 4 * 1024 * 1024 + 1}
        ),
    )
    with pytest.raises(WindowsFenceBundleError, match="VALUE|SIZE"):
        verify_windows_fence_bundle_v1(
            built.bundle_raw,
            oversized_index,
            expected_store_binding=STORE_BINDING,
        )
    with pytest.raises(WindowsFenceBundleError, match="SIZE"):
        verify_windows_fence_bundle_v1(
            b"x" * (8 * 1024 * 1024 + 1),
            built.index_raw,
            expected_store_binding=STORE_BINDING,
        )


def test_config_must_be_exact_canonical_json() -> None:
    with pytest.raises(WindowsFenceBundleError, match="CANONICAL"):
        build_windows_fence_bundle_v1(
            ROOT,
            config_raw=b'{"value": 1}',
            expected_store_binding=STORE_BINDING,
        )
    with pytest.raises(WindowsFenceBundleError, match="DUPLICATE"):
        build_windows_fence_bundle_v1(
            ROOT,
            config_raw=b'{"value":1,"value":1}',
            expected_store_binding=STORE_BINDING,
        )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update({"unexpected": True}),
        lambda value: value["runtime_config"].update({"credential_descriptor": {}}),
        lambda value: value["runtime_config"].update({"gateway_name": "bad gateway"}),
        lambda value: value["runtime_config"].update(
            {"rep_address": "tcp://0.0.0.0:2014"}
        ),
        lambda value: value["runtime_config"].update(
            {"pub_address": value["runtime_config"]["rep_address"]}
        ),
        lambda value: value["store_expectation"].update(
            {"store_path_sha256": "b" * 64}
        ),
    ],
)
def test_config_must_match_fixed_runtime_contract(mutate: object) -> None:
    value = json.loads(CONFIG_RAW)
    mutate(value)  # type: ignore[operator]
    with pytest.raises(
        WindowsFenceBundleError,
        match="BUNDLE_(RUNTIME_CONFIG_(FIELDS|VALUE)_INVALID|CREDENTIAL_DESCRIPTOR_INVALID)",
    ):
        build_windows_fence_bundle_v1(
            ROOT,
            config_raw=canonical_json_bytes(value),
            expected_store_binding=STORE_BINDING,
        )


@pytest.mark.parametrize(
    "store_root",
    [r"\\server\share\store", r"C:\different\store"],
)
def test_config_store_root_must_be_local_and_match_target_binding(
    store_root: str,
) -> None:
    value = json.loads(CONFIG_RAW)
    value["store_root"] = store_root
    value["store_expectation"]["store_path_sha256"] = hashlib.sha256(
        store_root.encode()
    ).hexdigest()
    binding = {
        **STORE_BINDING,
        "store_path_sha256": value["store_expectation"]["store_path_sha256"],
    }
    if store_root.startswith("C:"):
        binding = STORE_BINDING
    with pytest.raises(
        WindowsFenceBundleError,
        match="BUNDLE_(RUNTIME_CONFIG_VALUE_INVALID|STORE_TARGET_BINDING_MISMATCH)",
    ):
        build_windows_fence_bundle_v1(
            ROOT,
            config_raw=canonical_json_bytes(value),
            expected_store_binding=binding,
        )
