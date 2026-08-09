from __future__ import annotations

import base64
import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import scripts.windows_fence_foundation.offline_signing_v1 as offline_signing
from backend.tests.unit.test_issue267_windows_fence_foundation_schemas import _preflight
from backend.tests.unit.windows_fence_public_fixture_v1 import public_keyring_raw_v1
from scripts.windows_fence_foundation.contracts import (
    canonical_json_bytes,
)
from scripts.windows_fence_foundation.installer_trust_anchor_v1 import (
    canonical_public_keyring_v1,
)
from scripts.windows_fence_foundation.offline_sign_cli_v1 import run as sign_run
from scripts.windows_fence_foundation.offline_signing_v1 import (
    OfflineSigningError,
    require_fresh_zero_preflight_v1,
    sign_artifact_with_fd_v1,
    verify_public_artifact_v1,
    write_audit_create_only_v1,
    write_canonical_create_only_v1,
)
from scripts.windows_fence_foundation.trust_pins_v1 import (
    OBSERVER_KEY_DOMAIN,
    OBSERVER_SIGNER_ROLE,
    FoundationPublicKeyPin,
)


def _pin(private: Ed25519PrivateKey) -> FoundationPublicKeyPin:
    raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return FoundationPublicKeyPin(
        key_domain=OBSERVER_KEY_DOMAIN,
        role=OBSERVER_SIGNER_ROLE,
        key_id="windows-foundation-observer-evidence:unit-key-0001",
        public_key_raw=raw,
        public_key_sha256=hashlib.sha256(raw).hexdigest(),
    )


def _draft(pin: FoundationPublicKeyPin, **override: object) -> dict[str, object]:
    facts_raw = canonical_json_bytes(
        {"pending_send_outcomes": 0, "active_orders": [], "positions": []}
    )
    value: dict[str, object] = _preflight()
    value.pop("signature")
    value.pop("receipt_id")
    value.pop("receipt_core_sha256")
    value.update(
        {
            "challenge_issued_at_utc": "2026-08-09T00:00:00Z",
            "snapshot_served_at_utc": "2026-08-09T00:00:01Z",
            "observed_at_utc": "2026-08-09T00:00:02Z",
            "challenge_expires_at_utc": "2026-08-09T00:00:30Z",
            "execution_facts_canonical_sha256": hashlib.sha256(facts_raw).hexdigest(),
            "snapshot_raw_sha256": hashlib.sha256(facts_raw).hexdigest(),
            "signer_role": pin.role,
            "signer_key_domain": pin.key_domain,
            "signer_key_id": pin.key_id,
            "signer_public_key_sha256": pin.public_key_sha256,
        }
    )
    value.update(override)
    core = hashlib.sha256(canonical_json_bytes(value)).hexdigest()
    value["receipt_core_sha256"] = core
    value["receipt_id"] = "windows-fence-preflight-" + core
    return value


def _facts() -> bytes:
    return canonical_json_bytes(
        {"pending_send_outcomes": 0, "active_orders": [], "positions": []}
    )


def _key_fd(tmp_path: Path, private: Ed25519PrivateKey) -> int:
    path = tmp_path / "offline-key"
    path.write_bytes(
        base64.b64encode(
            private.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        )
    )
    path.chmod(0o400)
    return os.open(path, os.O_RDONLY)


def test_windows_fd_signing_cli_fails_closed_without_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Model the Windows branch, which cannot prove inherited FD access mode."""
    monkeypatch.setattr(offline_signing, "fcntl", None)
    keyring_raw = public_keyring_raw_v1()
    pin = canonical_public_keyring_v1(
        keyring_raw, hashlib.sha256(keyring_raw).hexdigest()
    ).observer
    facts = _facts()
    draft_path = tmp_path / "draft.json"
    keyring_path = tmp_path / "keyring.json"
    facts_path = tmp_path / "facts.json"
    snapshot_path = tmp_path / "snapshot.json"
    output_path = tmp_path / "signed.json"
    audit_path = tmp_path / "signed.audit.json"
    key_path = tmp_path / "private-key"
    ledger_path = tmp_path / "ledger"
    draft_path.write_bytes(canonical_json_bytes(_draft(pin)))
    keyring_path.write_bytes(keyring_raw)
    facts_path.write_bytes(facts)
    snapshot_path.write_bytes(facts)
    key_path.write_bytes(b"not-read-when-fcntl-is-unavailable")
    key_path.chmod(0o400)
    ledger_path.mkdir(mode=0o700)
    descriptor = os.open(key_path, os.O_RDONLY)
    try:
        assert (
            sign_run(
                "observer",
                [
                    "--draft",
                    str(draft_path),
                    "--output",
                    str(output_path),
                    "--audit-output",
                    str(audit_path),
                    "--public-keyring",
                    str(keyring_path),
                    "--private-key-fd",
                    str(descriptor),
                    "--execution-facts",
                    str(facts_path),
                    "--snapshot",
                    str(snapshot_path),
                    "--replay-ledger-dir",
                    str(ledger_path),
                ],
            )
            == 2
        )
    finally:
        os.close(descriptor)
    assert "SIGNING_PRIVATE_KEY_FD_ACCESS_UNVERIFIABLE" in capsys.readouterr().err
    assert not output_path.exists()
    assert not audit_path.exists()


@pytest.mark.skipif(
    os.name == "nt", reason="offline signing requires a provably read-only FD"
)
def test_fd_only_sign_verify_and_create_only_audit(tmp_path: Path) -> None:
    private = Ed25519PrivateKey.from_private_bytes(b"a" * 32)
    pin = _pin(private)
    descriptor = _key_fd(tmp_path, private)
    try:
        signed = sign_artifact_with_fd_v1(
            _draft(pin),
            private_key_fd=descriptor,
            pin=pin,
            execution_facts_raw=_facts(),
            snapshot_raw=_facts(),
        )
    finally:
        os.close(descriptor)
    raw = canonical_json_bytes(signed)
    verified = verify_public_artifact_v1(raw, pin=pin)
    assert verified.raw_sha256 == hashlib.sha256(raw).hexdigest()
    assert (
        require_fresh_zero_preflight_v1(
            raw, pin=pin, now=datetime(2026, 8, 9, 0, 0, 10, tzinfo=timezone.utc)
        ).value["active_orders"]
        == []
    )
    artifact = tmp_path / "artifact.json"
    audit = tmp_path / "artifact.audit.json"
    assert write_canonical_create_only_v1(artifact, signed) == raw
    assert write_audit_create_only_v1(audit, artifact_raw=raw, action="unit")
    with pytest.raises(OfflineSigningError, match="OUTPUT_EXISTS"):
        write_canonical_create_only_v1(artifact, signed)


@pytest.mark.parametrize(
    "field,value",
    [
        ("pending_send_outcomes", 1),
        ("active_orders", [{"id": "CTP.1"}]),
        ("web_trade_enabled", True),
    ],
)
@pytest.mark.skipif(
    os.name == "nt", reason="offline signing requires a provably read-only FD"
)
def test_signing_rejects_nonzero_or_live_preflight(
    field: str, value: object, tmp_path: Path
) -> None:
    private = Ed25519PrivateKey.from_private_bytes(b"b" * 32)
    pin = _pin(private)
    descriptor = _key_fd(tmp_path, private)
    try:
        with pytest.raises(
            OfflineSigningError, match="SCHEMA_INVALID|PREFLIGHT_NOT_ZERO_OR_FRESH"
        ):
            sign_artifact_with_fd_v1(
                _draft(pin, **{field: value}),
                private_key_fd=descriptor,
                pin=pin,
                execution_facts_raw=_facts(),
                snapshot_raw=_facts(),
            )
    finally:
        os.close(descriptor)


@pytest.mark.skipif(
    os.name == "nt", reason="offline signing requires a provably read-only FD"
)
def test_key_domain_reuse_and_stale_preflight_fail_closed(tmp_path: Path) -> None:
    private = Ed25519PrivateKey.from_private_bytes(b"c" * 32)
    pin = _pin(private)
    descriptor = _key_fd(tmp_path, private)
    try:
        with pytest.raises(
            OfflineSigningError, match="SCHEMA_INVALID|PUBLIC_PIN_MISMATCH"
        ):
            sign_artifact_with_fd_v1(
                _draft(
                    pin,
                    signer_key_domain="dedicated-windows-foundation-manifest-signing-v1",
                ),
                private_key_fd=descriptor,
                pin=pin,
                execution_facts_raw=_facts(),
                snapshot_raw=_facts(),
            )
        signed = sign_artifact_with_fd_v1(
            _draft(pin),
            private_key_fd=descriptor,
            pin=pin,
            execution_facts_raw=_facts(),
            snapshot_raw=_facts(),
        )
    finally:
        os.close(descriptor)
    with pytest.raises(OfflineSigningError, match="PREFLIGHT_NOT_ZERO_OR_FRESH"):
        require_fresh_zero_preflight_v1(
            canonical_json_bytes(signed),
            pin=pin,
            now=datetime(2026, 8, 9, 0, 1, tzinfo=timezone.utc),
        )


@pytest.mark.skipif(
    os.name == "nt", reason="offline signing requires a provably read-only FD"
)
def test_preflight_signing_recomputes_canonical_source_facts(tmp_path: Path) -> None:
    private = Ed25519PrivateKey.from_private_bytes(b"d" * 32)
    pin = _pin(private)
    descriptor = _key_fd(tmp_path, private)
    bad_facts = canonical_json_bytes(
        {
            "pending_send_outcomes": 0,
            "active_orders": [],
            "positions": [{"symbol": "rb"}],
        }
    )
    draft = _draft(pin)
    draft["execution_facts_canonical_sha256"] = hashlib.sha256(bad_facts).hexdigest()
    draft["snapshot_raw_sha256"] = hashlib.sha256(bad_facts).hexdigest()
    core = hashlib.sha256(
        canonical_json_bytes(
            {
                key: value
                for key, value in draft.items()
                if key not in {"receipt_id", "receipt_core_sha256"}
            }
        )
    ).hexdigest()
    draft["receipt_core_sha256"] = core
    draft["receipt_id"] = "windows-fence-preflight-" + core
    try:
        with pytest.raises(OfflineSigningError, match="PREFLIGHT_NOT_ZERO_OR_FRESH"):
            sign_artifact_with_fd_v1(
                draft,
                private_key_fd=descriptor,
                pin=pin,
                execution_facts_raw=bad_facts,
                snapshot_raw=bad_facts,
            )
    finally:
        os.close(descriptor)
