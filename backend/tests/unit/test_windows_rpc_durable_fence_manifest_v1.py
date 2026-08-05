from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.windows_fence_foundation.contracts import (
    AUTHORITY_FIELDS,
    canonical_json_bytes,
)
from scripts.windows_fence_foundation.manifest_v1 import (
    EXPECTED_BINDING_FIELDS,
    MANIFEST_ID_PREFIX,
    SIGNATURE_DOMAIN,
    FilesystemInstallAttemptNonceRegistryV1,
    ManifestVerificationError,
    derive_install_attempt_id_v1,
    verify_and_reserve_install_manifest_v1,
    verify_install_manifest_v1,
)
from scripts.windows_fence_foundation.trust_pins_v1 import (
    MANIFEST_KEY_DOMAIN,
    MANIFEST_SIGNER_ROLE,
    OBSERVER_KEY_DOMAIN,
    OBSERVER_SIGNER_ROLE,
    RESTART_KEY_DOMAIN,
    RESTART_SIGNER_ROLE,
    FoundationPublicKeyPin,
    TrustPinError,
    WindowsFoundationTrustPinsV1,
)
from scripts.windows_fence_foundation.win32_fs import PathSecurityFacts

NOW = datetime(2026, 8, 5, 0, 0, tzinfo=timezone.utc)
_REGISTRY_TEMP = tempfile.TemporaryDirectory()
REGISTRY_ROOT = Path(_REGISTRY_TEMP.name)


def _registry_facts(path: Path) -> PathSecurityFacts:
    info = path.stat()
    absolute = path.absolute()
    return PathSecurityFacts(
        path_sha256=hashlib.sha256(str(absolute).encode()).hexdigest(),
        volume_serial=f"{info.st_dev & 0xFFFFFFFF:08X}",
        volume_identity_sha256=hashlib.sha256(
            f"portable-device:{info.st_dev}".encode()
        ).hexdigest(),
        file_identity=f"{info.st_dev}:{info.st_ino}",
        owner_sid_sha256=hashlib.sha256(b"test-owner").hexdigest(),
        acl_sddl_sha256=hashlib.sha256(b"test-acl").hexdigest(),
        unsafe_write_principals=(),
        write_principal_sid_sha256s=(hashlib.sha256(b"test-writer").hexdigest(),),
        regular_file=False,
        directory=True,
        reparse_point=False,
        parent_chain_reparse_free=True,
        hardlink_count=1,
        alternate_data_streams=False,
        dacl_protected=True,
        inherited_ace_count=0,
    )


class _SecureTestFilesystem:
    def inspect(self, path: Path) -> PathSecurityFacts:
        return _registry_facts(path)


def _registry(
    pins: WindowsFoundationTrustPinsV1,
) -> FilesystemInstallAttemptNonceRegistryV1:
    return FilesystemInstallAttemptNonceRegistryV1(
        REGISTRY_ROOT,
        filesystem=_SecureTestFilesystem(),  # type: ignore[arg-type]
        expected_root_facts=pins.nonce_registry_root_facts,
    )


def _private(seed: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def _raw_public(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _pin(
    private: Ed25519PrivateKey, domain: str, role: str, suffix: str
) -> FoundationPublicKeyPin:
    raw = _raw_public(private)
    return FoundationPublicKeyPin(
        key_domain=domain,
        role=role,
        key_id=f"{role}:{suffix}",
        public_key_raw=raw,
        public_key_sha256=hashlib.sha256(raw).hexdigest(),
    )


@pytest.fixture
def keys() -> tuple[Ed25519PrivateKey, Ed25519PrivateKey, Ed25519PrivateKey]:
    return _private(1), _private(2), _private(3)


@pytest.fixture
def pins(
    keys: tuple[Ed25519PrivateKey, Ed25519PrivateKey, Ed25519PrivateKey],
) -> WindowsFoundationTrustPinsV1:
    manifest, observer, restart = keys
    return WindowsFoundationTrustPinsV1(
        manifest=_pin(manifest, MANIFEST_KEY_DOMAIN, MANIFEST_SIGNER_ROLE, "unit-key1"),
        observer=_pin(observer, OBSERVER_KEY_DOMAIN, OBSERVER_SIGNER_ROLE, "unit-key2"),
        restart=_pin(restart, RESTART_KEY_DOMAIN, RESTART_SIGNER_ROLE, "unit-key3"),
        nonce_registry_root_facts=_registry_facts(REGISTRY_ROOT),
    )


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _unsigned_manifest(pin: FoundationPublicKeyPin) -> dict[str, object]:
    sha_fields = [
        "attempt_nonce_sha256",
        "store_path_sha256",
        "store_volume_identity_sha256",
        "bundle_sha256",
        "final_version_directory_path_sha256",
        "expected_final_owner_sid_sha256",
        "expected_final_directory_acl_sddl_sha256",
        "expected_component_acl_sddl_sha256",
        "extension_sha256",
        "extension_destination_path_sha256",
        "launcher_sha256",
        "launcher_destination_path_sha256",
        "assembly_sha256",
        "assembly_destination_path_sha256",
        "config_sha256",
        "config_destination_path_sha256",
        "service_image_path_canonical_sha256",
        "service_config_canonical_sha256",
        "expected_service_config_owner_sid_sha256",
        "expected_service_config_acl_sddl_sha256",
        "preinstall_service_image_path_canonical_sha256",
        "preinstall_service_config_canonical_sha256",
        "safety_service_config_canonical_sha256",
        "service_config_transition_plan_sha256",
        "expected_installer_principal_sid_sha256",
        "expected_installer_process_image_sha256",
        "preflight_receipt_raw_sha256",
    ]
    value: dict[str, object] = {field: _sha(field) for field in sha_fields}
    value.update(
        {
            "schema_version": "windows_rpc_durable_fence_install_manifest_v1",
            "purpose": "authorize_exact_windows_fence_files_and_one_post_reservation_service_config_transition_without_restart",
            "install_attempt_id": f"windows-fence-install-{_sha('placeholder')}",
            "issued_at_utc": "2026-08-04T23:59:00Z",
            "expires_at_utc": "2026-08-05T00:01:00Z",
            "trusted_clock_id": "unit.clock.v1",
            "service_name": "VnpyRpcService",
            "store_volume_serial": "A1B2C3D4",
            "publish_mode": "atomic_content_addressed_final_directory",
            "extension_version": "windows-rpc-durable-fence-foundation-v1",
            "installer_write_access_after_publish": False,
            "service_config_mutation_before_dispatch_reservation_authorized": False,
            "service_config_transition_after_dispatch_reservation_authorized": True,
            "unbound_service_config_mutation_after_observer_seal_authorized": False,
            "target_service_start_type": "DEMAND_START",
            "target_recovery_actions_disabled": True,
            "target_failure_actions_disabled": True,
            "automatic_policy_restore_authorized": False,
            "target_state_schema_version": "windows_rpc_durable_fence_state_v1",
            "preflight_receipt_id": f"windows-fence-preflight-{_sha('receipt')}",
            "install_authorized": True,
            "restart_authorized": False,
            "automatic_restart_allowed": False,
            "authority": {field: False for field in AUTHORITY_FIELDS},
            "canonicalization_profile": "windows-foundation-canonical-json-v1",
            "signature_domain_separator": SIGNATURE_DOMAIN,
            "signature_algorithm": "Ed25519",
            "signer_role": pin.role,
            "signer_key_domain": pin.key_domain,
            "signer_key_id": pin.key_id,
            "signer_public_key_sha256": pin.public_key_sha256,
        }
    )
    value["install_attempt_id"] = derive_install_attempt_id_v1(_attempt_inputs(value))[
        0
    ]
    return value


def _attempt_inputs(value: dict[str, object]) -> dict[str, object]:
    return {
        "attempt_nonce_sha256": value["attempt_nonce_sha256"],
        "bundle_sha256": value["bundle_sha256"],
        "service_name": value["service_name"],
        "store_path_sha256": value["store_path_sha256"],
        "store_volume_serial": value["store_volume_serial"],
        "store_volume_identity_sha256": value["store_volume_identity_sha256"],
        "expected_account_sha256": _sha("expected-account"),
        "gateway_name": "CTP",
        "gateway_scope_sha256": _sha("gateway-scope"),
    }


def _sign(value: dict[str, object], private: Ed25519PrivateKey) -> bytes:
    value = copy.deepcopy(value)
    for field in ("manifest_id", "manifest_core_sha256", "signature"):
        value.pop(field, None)
    core_sha256 = hashlib.sha256(canonical_json_bytes(value)).hexdigest()
    value["manifest_core_sha256"] = core_sha256
    value["manifest_id"] = f"{MANIFEST_ID_PREFIX}{core_sha256}"
    envelope = canonical_json_bytes(value)
    signature = private.sign(SIGNATURE_DOMAIN.encode() + b"\x00" + envelope)
    value["signature"] = base64.b64encode(signature).decode()
    return canonical_json_bytes(value)


def _decoded(raw: bytes) -> dict[str, object]:
    return json.loads(raw)


def _bindings(value: dict[str, object]) -> dict[str, object]:
    return {field: value[field] for field in EXPECTED_BINDING_FIELDS}


def _verify(raw: bytes, pins: WindowsFoundationTrustPinsV1):
    value = _decoded(raw)
    return verify_install_manifest_v1(
        raw,
        trust_pins=pins,
        expected_bindings=_bindings(value),
        install_attempt_inputs=_attempt_inputs(value),
        now=NOW,
    )


def test_verifies_exact_manifest_without_granting_install_or_restart(
    keys: tuple[Ed25519PrivateKey, Ed25519PrivateKey, Ed25519PrivateKey],
    pins: WindowsFoundationTrustPinsV1,
) -> None:
    raw = _sign(_unsigned_manifest(pins.manifest), keys[0])

    verified = _verify(raw, pins)

    assert verified.signature_valid is True
    assert verified.bindings_verified is True
    assert verified.install_ready is False
    assert verified.restart_authorized is False
    assert verified["install_authorized"] is True
    assert verified.raw_sha256 == hashlib.sha256(raw).hexdigest()
    assert re.fullmatch(
        r"[0-9a-f]{64}", verified.install_attempt_immutable_inputs_sha256
    )


@pytest.mark.parametrize("mutation", ["payload", "core", "id", "signature"])
def test_rejects_tamper(
    mutation: str,
    keys: tuple[Ed25519PrivateKey, Ed25519PrivateKey, Ed25519PrivateKey],
    pins: WindowsFoundationTrustPinsV1,
) -> None:
    raw = _sign(_unsigned_manifest(pins.manifest), keys[0])
    value = _decoded(raw)
    if mutation == "payload":
        value["bundle_sha256"] = _sha("tampered")
    elif mutation == "core":
        value["manifest_core_sha256"] = _sha("bad-core")
    elif mutation == "id":
        value["manifest_id"] = f"{MANIFEST_ID_PREFIX}{_sha('bad-id')}"
    else:
        signature = bytearray(base64.b64decode(str(value["signature"])))
        signature[0] ^= 1
        value["signature"] = base64.b64encode(signature).decode()

    with pytest.raises(ManifestVerificationError):
        _verify(canonical_json_bytes(value), pins)


def test_rejects_wrong_external_key_even_when_attacker_resigns(
    keys: tuple[Ed25519PrivateKey, Ed25519PrivateKey, Ed25519PrivateKey],
    pins: WindowsFoundationTrustPinsV1,
) -> None:
    attacker = _private(9)
    attacker_pin = _pin(
        attacker, MANIFEST_KEY_DOMAIN, MANIFEST_SIGNER_ROLE, "attacker1"
    )
    raw = _sign(_unsigned_manifest(attacker_pin), attacker)

    with pytest.raises(
        ManifestVerificationError, match="MANIFEST_EXTERNAL_PIN_MISMATCH"
    ):
        _verify(raw, pins)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("signature_domain_separator", "vnpy.issue267.windows-foundation.other.v1"),
        ("signer_key_domain", OBSERVER_KEY_DOMAIN),
        ("signer_role", OBSERVER_SIGNER_ROLE),
    ],
)
def test_rejects_signature_domain_or_role_confusion(
    field: str,
    replacement: str,
    keys: tuple[Ed25519PrivateKey, Ed25519PrivateKey, Ed25519PrivateKey],
    pins: WindowsFoundationTrustPinsV1,
) -> None:
    value = _unsigned_manifest(pins.manifest)
    value[field] = replacement

    with pytest.raises(ManifestVerificationError, match="MANIFEST_CONSTANT_MISMATCH"):
        _verify(_sign(value, keys[0]), pins)


@pytest.mark.parametrize(
    ("issued", "expires"),
    [
        ("2026-08-05T00:00:01Z", "2026-08-05T00:01:00Z"),
        ("2026-08-04T23:00:00Z", "2026-08-05T00:00:00Z"),
    ],
)
def test_requires_trusted_clock_inside_half_open_window(
    issued: str,
    expires: str,
    keys: tuple[Ed25519PrivateKey, Ed25519PrivateKey, Ed25519PrivateKey],
    pins: WindowsFoundationTrustPinsV1,
) -> None:
    value = _unsigned_manifest(pins.manifest)
    value["issued_at_utc"] = issued
    value["expires_at_utc"] = expires

    with pytest.raises(
        ManifestVerificationError, match="MANIFEST_OUTSIDE_VALIDITY_WINDOW"
    ):
        _verify(_sign(value, keys[0]), pins)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("schema_version", "windows_rpc_durable_fence_install_manifest_v0"),
        ("extension_version", "windows-rpc-durable-fence-foundation-v0"),
        ("target_state_schema_version", "windows_rpc_durable_fence_state_v0"),
        ("restart_authorized", True),
        ("automatic_restart_allowed", True),
    ],
)
def test_rejects_downgrade_or_authority_expansion(
    field: str,
    replacement: object,
    keys: tuple[Ed25519PrivateKey, Ed25519PrivateKey, Ed25519PrivateKey],
    pins: WindowsFoundationTrustPinsV1,
) -> None:
    value = _unsigned_manifest(pins.manifest)
    value[field] = replacement

    with pytest.raises(ManifestVerificationError, match="MANIFEST_CONSTANT_MISMATCH"):
        _verify(_sign(value, keys[0]), pins)


def test_rejects_any_embedded_authority_true(
    keys: tuple[Ed25519PrivateKey, Ed25519PrivateKey, Ed25519PrivateKey],
    pins: WindowsFoundationTrustPinsV1,
) -> None:
    value = _unsigned_manifest(pins.manifest)
    assert isinstance(value["authority"], dict)
    value["authority"]["deployment_authorized"] = True

    with pytest.raises(
        ManifestVerificationError, match="MANIFEST_AUTHORITY_NOT_FROZEN_NONE"
    ):
        _verify(_sign(value, keys[0]), pins)


def test_expected_bindings_are_mandatory_exact_and_value_bound(
    keys: tuple[Ed25519PrivateKey, Ed25519PrivateKey, Ed25519PrivateKey],
    pins: WindowsFoundationTrustPinsV1,
) -> None:
    raw = _sign(_unsigned_manifest(pins.manifest), keys[0])
    expected = _bindings(_decoded(raw))
    expected.pop("bundle_sha256")
    with pytest.raises(
        ManifestVerificationError, match="EXPECTED_BINDINGS_FIELDS_MISMATCH"
    ):
        verify_install_manifest_v1(
            raw,
            trust_pins=pins,
            expected_bindings=expected,
            install_attempt_inputs=_attempt_inputs(_decoded(raw)),
            now=NOW,
        )

    expected = _bindings(_decoded(raw))
    expected["bundle_sha256"] = _sha("other-bundle")
    with pytest.raises(ManifestVerificationError, match="MANIFEST_BINDING_MISMATCH"):
        verify_install_manifest_v1(
            raw,
            trust_pins=pins,
            expected_bindings=expected,
            install_attempt_inputs=_attempt_inputs(_decoded(raw)),
            now=NOW,
        )


@pytest.mark.skipif(
    os.open not in os.supports_dir_fd or not getattr(os, "O_NOFOLLOW", 0),
    reason="offline nonce reservation requires handle-anchored directory I/O",
)
def test_install_attempt_id_is_derived_and_nonce_reuse_conflicts_fail_closed(
    keys: tuple[Ed25519PrivateKey, Ed25519PrivateKey, Ed25519PrivateKey],
    pins: WindowsFoundationTrustPinsV1,
) -> None:
    value = _unsigned_manifest(pins.manifest)
    inputs = _attempt_inputs(value)
    expected_id, _ = derive_install_attempt_id_v1(inputs)
    assert value["install_attempt_id"] == expected_id
    raw = _sign(value, keys[0])

    registry = _registry(pins)
    verified = verify_install_manifest_v1(
        raw,
        trust_pins=pins,
        expected_bindings=_bindings(_decoded(raw)),
        install_attempt_inputs=inputs,
        now=NOW,
    )
    reserved = verify_and_reserve_install_manifest_v1(
        raw,
        trust_pins=pins,
        expected_bindings=_bindings(_decoded(raw)),
        install_attempt_inputs=inputs,
        nonce_registry=registry,
        now=NOW,
    )
    assert reserved.raw_sha256 == verified.raw_sha256
    assert verified.install_ready is False

    conflict_value = _unsigned_manifest(pins.manifest)
    conflict_value["attempt_nonce_sha256"] = value["attempt_nonce_sha256"]
    conflict_value["bundle_sha256"] = _sha("different-bundle")
    conflict_inputs = _attempt_inputs(conflict_value)
    conflict_value["install_attempt_id"] = derive_install_attempt_id_v1(
        conflict_inputs
    )[0]
    conflict_raw = _sign(conflict_value, keys[0])
    with pytest.raises(
        ManifestVerificationError, match="INSTALL_ATTEMPT_NONCE_REUSE_CONFLICT"
    ):
        verify_and_reserve_install_manifest_v1(
            conflict_raw,
            trust_pins=pins,
            expected_bindings=_bindings(_decoded(conflict_raw)),
            install_attempt_inputs=conflict_inputs,
            nonce_registry=registry,
            now=NOW,
        )

    forged = _decoded(raw)
    forged["install_attempt_id"] = f"windows-fence-install-{'f' * 64}"
    forged_raw = _sign(forged, keys[0])
    with pytest.raises(ManifestVerificationError, match="INSTALL_ATTEMPT_ID_MISMATCH"):
        verify_install_manifest_v1(
            forged_raw,
            trust_pins=pins,
            expected_bindings=_bindings(_decoded(forged_raw)),
            install_attempt_inputs=inputs,
            now=NOW,
        )


def test_nonce_registry_root_must_match_external_security_and_identity_pin(
    keys: tuple[Ed25519PrivateKey, Ed25519PrivateKey, Ed25519PrivateKey],
    pins: WindowsFoundationTrustPinsV1,
    tmp_path: Path,
) -> None:
    raw = _sign(_unsigned_manifest(pins.manifest), keys[0])
    alternate = FilesystemInstallAttemptNonceRegistryV1(
        tmp_path,
        filesystem=_SecureTestFilesystem(),  # type: ignore[arg-type]
        expected_root_facts=_registry_facts(tmp_path),
    )
    with pytest.raises(
        ManifestVerificationError,
        match="INSTALL_ATTEMPT_NONCE_REGISTRY_PIN_MISMATCH",
    ):
        verify_and_reserve_install_manifest_v1(
            raw,
            trust_pins=pins,
            expected_bindings=_bindings(_decoded(raw)),
            install_attempt_inputs=_attempt_inputs(_decoded(raw)),
            nonce_registry=alternate,
            now=NOW,
        )


def test_nonce_registry_refuses_unanchored_windows_style_path_fallback(
    pins: WindowsFoundationTrustPinsV1,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import scripts.windows_fence_foundation.manifest_v1 as manifest_module

    monkeypatch.setattr(manifest_module.os, "supports_dir_fd", frozenset())
    registry = _registry(pins)
    with pytest.raises(
        ManifestVerificationError,
        match="NONCE_REGISTRY_HANDLE_ANCHOR_UNSUPPORTED",
    ):
        registry.compare_and_record(
            nonce_sha256=_sha("windows-fallback-nonce"),
            immutable_inputs_sha256=_sha("windows-fallback-inputs"),
        )


def test_nonce_registry_rejects_path_like_or_non_digest_bindings(
    pins: WindowsFoundationTrustPinsV1,
) -> None:
    registry = _registry(pins)
    with pytest.raises(
        ManifestVerificationError, match="NONCE_REGISTRY_BINDING_INVALID"
    ):
        registry.compare_and_record(
            nonce_sha256="../escape",
            immutable_inputs_sha256=_sha("immutable-inputs"),
        )


@pytest.mark.skipif(
    os.open not in os.supports_dir_fd or not getattr(os, "O_NOFOLLOW", 0),
    reason="open-handle identity check requires directory-relative I/O",
)
def test_nonce_registry_open_handle_must_match_pinned_directory_identity(
    tmp_path: Path,
) -> None:
    root = tmp_path / "registry"
    root.mkdir()
    expected = _registry_facts(root)
    original = tmp_path / "original"
    root.rename(original)
    root.mkdir()

    class _PinnedFactsOnly:
        def inspect(self, path: Path) -> PathSecurityFacts:
            del path
            return expected

    registry = FilesystemInstallAttemptNonceRegistryV1(
        root,
        filesystem=_PinnedFactsOnly(),  # type: ignore[arg-type]
        expected_root_facts=expected,
    )
    with pytest.raises(
        ManifestVerificationError, match="NONCE_REGISTRY_OPEN_HANDLE_MISMATCH"
    ):
        registry.compare_and_record(
            nonce_sha256=_sha("replacement-root-nonce"),
            immutable_inputs_sha256=_sha("replacement-root-inputs"),
        )


def test_rejects_noncanonical_and_invalid_signature_base64(
    keys: tuple[Ed25519PrivateKey, Ed25519PrivateKey, Ed25519PrivateKey],
    pins: WindowsFoundationTrustPinsV1,
) -> None:
    raw = _sign(_unsigned_manifest(pins.manifest), keys[0])
    with pytest.raises(ManifestVerificationError, match="MANIFEST_RAW_NOT_CANONICAL"):
        _verify(raw + b"\n", pins)

    value = _decoded(raw)
    value["signature"] = "!" + str(value["signature"])[1:]
    with pytest.raises(
        ManifestVerificationError, match="MANIFEST_SIGNATURE_ENCODING_INVALID"
    ):
        _verify(canonical_json_bytes(value), pins)


def test_rejects_oversized_manifest(pins: WindowsFoundationTrustPinsV1) -> None:
    with pytest.raises(ManifestVerificationError, match="MANIFEST_SIZE_INVALID"):
        verify_install_manifest_v1(
            b"{" + b" " * (256 * 1024),
            trust_pins=pins,
            expected_bindings={},
            install_attempt_inputs={},
            now=NOW,
        )


@pytest.mark.parametrize("reuse", ["raw", "key_id"])
def test_three_trust_domains_are_pairwise_distinct(
    reuse: str,
    keys: tuple[Ed25519PrivateKey, Ed25519PrivateKey, Ed25519PrivateKey],
    pins: WindowsFoundationTrustPinsV1,
) -> None:
    if reuse == "raw":
        observer = _pin(keys[0], OBSERVER_KEY_DOMAIN, OBSERVER_SIGNER_ROLE, "unit-key2")
        manifest = pins.manifest
    else:
        observer = pins.observer
        manifest = FoundationPublicKeyPin(
            key_domain=MANIFEST_KEY_DOMAIN,
            role=MANIFEST_SIGNER_ROLE,
            key_id=observer.key_id,
            public_key_raw=pins.manifest.public_key_raw,
            public_key_sha256=pins.manifest.public_key_sha256,
        )
    with pytest.raises(TrustPinError):
        WindowsFoundationTrustPinsV1(
            manifest=manifest,
            observer=observer,
            restart=pins.restart,
            nonce_registry_root_facts=pins.nonce_registry_root_facts,
        )


def test_production_modules_expose_no_private_key_or_signing_api() -> None:
    import scripts.windows_fence_foundation.manifest_v1 as manifest_module
    import scripts.windows_fence_foundation.trust_pins_v1 as pins_module

    public_names = set(dir(manifest_module)) | set(dir(pins_module))
    assert "Ed25519PrivateKey" not in public_names
    assert not any(name.startswith("sign_") for name in public_names)
