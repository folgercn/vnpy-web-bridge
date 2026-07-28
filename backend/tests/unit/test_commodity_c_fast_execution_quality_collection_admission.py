from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import commodity_c_fast_execution_quality_collection_admission as admission  # noqa: E402
import commodity_c_fast_execution_quality_sign_collection_admission as signer  # noqa: E402
from commodity_c_fast_p0_sign_acceptance_v2 import (  # noqa: E402
    write_private_json_create_only_verified,
)
from commodity_c_fast_t1_one_shot import (  # noqa: E402
    OneShotError,
    canonical_json,
    validate_json_schema,
)


def load_helper(name: str, filename: str):
    path = ROOT / "backend/tests/unit" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


acceptance_helpers = load_helper(
    "collection_admission_acceptance_helpers",
    "test_commodity_c_fast_p0_acceptance_v2.py",
)
policy_helpers = load_helper(
    "collection_admission_policy_helpers",
    "test_commodity_c_fast_execution_policy_v2.py",
)

NOW = datetime(2026, 9, 1, 0, 13, tzinfo=timezone.utc)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def public_raw(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def write_bytes(path: Path, raw: bytes, *, mode: int = 0o600) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)
    return path


def write_json(path: Path, payload, *, mode: int = 0o600) -> Path:
    raw = (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    return write_bytes(path, raw, mode=mode)


def admission_keyring(
    private_key: Ed25519PrivateKey,
    *,
    unused: Ed25519PrivateKey | None = None,
) -> dict:
    keys = [
        {
            "key_id": "collection-admission-signer-1",
            "purpose": admission.KEY_PURPOSE,
            "public_key_base64": base64.b64encode(
                public_raw(private_key)
            ).decode("ascii"),
        }
    ]
    if unused is not None:
        keys.append(
            {
                "key_id": "collection-admission-unused-key",
                "purpose": admission.KEY_PURPOSE,
                "public_key_base64": base64.b64encode(
                    public_raw(unused)
                ).decode("ascii"),
            }
        )
    return {
        "schema_version": admission.KEYRING_VERSION,
        "keys": keys,
    }


@dataclass
class Fixture:
    p0: object
    acceptance_path: Path
    policy_v1_path: Path
    policy_v2_path: Path
    policy_keyring_path: Path
    policy_pin: str
    admission_private: Ed25519PrivateKey
    admission_keyring_path: Path
    admission_pin: str
    custody: Path
    custody_identity_sha256: str

    def source_kwargs(self) -> dict:
        return {
            "policy_v1_path": self.policy_v1_path,
            "policy_v2_path": self.policy_v2_path,
            "policy_keyring_path": self.policy_keyring_path,
            "expected_policy_keyring_sha256": self.policy_pin,
            "acceptance_path": self.acceptance_path,
            "acceptance_keyring_path": self.p0.acceptance_keyring_path,
            "expected_acceptance_keyring_sha256": self.p0.acceptance_pin,
            "bundle_paths": self.p0.paths,
            "expected_upstream_keyring_sha256": self.p0.pins,
        }

    def verify_kwargs(self) -> dict:
        return {
            **self.source_kwargs(),
            "expected_admission_keyring_sha256": self.admission_pin,
            "custody_dir": self.custody,
            "pinned_custody_path": self.custody,
            "pinned_custody_identity_sha256": (
                self.custody_identity_sha256
            ),
            "require_root_owned_parent": False,
        }

    def binding_kwargs(self) -> dict:
        return {
            "custody_dir": self.custody,
            "pinned_custody_path": self.custody,
            "pinned_custody_identity_sha256": (
                self.custody_identity_sha256
            ),
            "require_root_owned_parent": False,
        }


def build_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    admission_unused: Ed25519PrivateKey | None = None,
) -> Fixture:
    p0 = acceptance_helpers.build_fixture(
        tmp_path / "p0",
        monkeypatch,
    )
    verified_bundle = acceptance_helpers.acceptance_module.verify_query_v3_bundle(
        p0.paths,
        expected_keyring_sha256=p0.pins,
    )
    acceptance_draft = acceptance_helpers.acceptance_draft(
        verified_bundle,
        p0,
    )
    signed_acceptance = acceptance_helpers.signer_module.sign_acceptance(
        acceptance_draft,
        p0.acceptance_private,
        p0.acceptance_keyring_path,
        p0.paths,
        expected_acceptance_keyring_sha256=p0.acceptance_pin,
        expected_keyring_sha256=p0.pins,
    )
    acceptance_path = write_json(
        tmp_path / "p0-acceptance.signed.json",
        signed_acceptance,
    )

    policy_private, policy_v1, policy_v2 = policy_helpers._signed_chain()
    policy_v1_path = write_bytes(
        tmp_path / "policy-v1.signed.json",
        policy_helpers._signed_model_raw(policy_v1),
    )
    policy_v2_path = write_bytes(
        tmp_path / "policy-v2.signed.json",
        policy_helpers._signed_model_raw(policy_v2),
    )
    policy_keyring = policy_helpers._trusted_keys(policy_private)
    policy_keyring_path = write_json(
        tmp_path / "policy-keyring.json",
        policy_keyring,
    )
    policy_pin = sha256(canonical_json(policy_keyring))

    admission_private = Ed25519PrivateKey.generate()
    keyring = admission_keyring(
        admission_private,
        unused=admission_unused,
    )
    admission_keyring_path = write_json(
        tmp_path / "admission-keyring.json",
        keyring,
    )
    admission_pin = sha256(canonical_json(keyring))
    custody = tmp_path / "admission-custody"
    custody.mkdir(mode=0o700)
    custody_identity = {
        "schema_version": "commodity_c_fast_t1_custody_identity_v1",
        "custody_id": "collection-admission-custody-20260901",
    }
    write_json(
        custody / "custody-identity.json",
        custody_identity,
    )
    custody_identity_sha256 = sha256(canonical_json(custody_identity))
    return Fixture(
        p0=p0,
        acceptance_path=acceptance_path,
        policy_v1_path=policy_v1_path,
        policy_v2_path=policy_v2_path,
        policy_keyring_path=policy_keyring_path,
        policy_pin=policy_pin,
        admission_private=admission_private,
        admission_keyring_path=admission_keyring_path,
        admission_pin=admission_pin,
        custody=custody,
        custody_identity_sha256=custody_identity_sha256,
    )


def draft_for(fixture: Fixture, sources=None) -> dict:
    sources = sources or admission.verify_admission_sources(
        **fixture.source_kwargs()
    )
    release_id = "c-fast-collection-admission-20260901-a01"
    payload = {
        "schema_version": admission.SCHEMA_VERSION,
        "purpose": admission.PURPOSE,
        "candidate_id": admission.CANDIDATE_ID,
        "parent_issue_number": 114,
        "issue_number": 140,
        "release_id": release_id,
        "attempt_id": admission.admission_attempt_id(release_id),
        "issued_at": (NOW - timedelta(seconds=30)).isoformat(),
        "not_before": (NOW - timedelta(seconds=5)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
        "minimum_final_revalidation_margin_seconds": 30,
        "reviewer_role": "independent collection-admission reviewer",
        "human_signature": (
            "Reviewed exact signed P0 and policy evidence for offline admission."
        ),
        "source_binding": admission.expected_source_binding(sources),
        "admission_keyring_sha256": fixture.admission_pin,
        "custody_path_sha256": admission.custody_path_sha256(
            fixture.custody
        ),
        "custody_identity_sha256": (
            fixture.custody_identity_sha256
        ),
        "verifier_sha256": sha256(admission.VERIFIER_PATH.read_bytes()),
        "release_schema_sha256": sha256(
            admission.RELEASE_SCHEMA_PATH.read_bytes()
        ),
        "trusted_keyring_schema_sha256": sha256(
            admission.KEYRING_SCHEMA_PATH.read_bytes()
        ),
        "consume_schema_sha256": sha256(
            admission.CONSUME_SCHEMA_PATH.read_bytes()
        ),
        "terminal_schema_sha256": sha256(
            admission.TERMINAL_SCHEMA_PATH.read_bytes()
        ),
        "admission_fact_frozen": True,
        "p0_accepted": True,
        "policy_rules_complete": True,
        "raw_signed_sources_required": True,
        "startup_recovery_exact_revalidation_required": True,
        "admission_scope": (
            "OFFLINE_FACT_FOR_SEPARATE_RUNTIME_RELEASE_ONLY"
        ),
        "signer_key_id": "collection-admission-signer-1",
    }
    payload.update(
        {field: False for field in admission.FALSE_AUTHORITY_FIELDS}
    )
    return payload


def sign_release(fixture: Fixture, draft: dict | None = None) -> Path:
    draft = draft or draft_for(fixture)
    candidate, public_key = signer.prepare_admission(
        draft,
        fixture.admission_keyring_path,
        expected_admission_keyring_sha256=fixture.admission_pin,
        custody_dir=fixture.custody,
        pinned_custody_path=fixture.custody,
        pinned_custody_identity_sha256=(
            fixture.custody_identity_sha256
        ),
        require_root_owned_parent=False,
        now=NOW,
        source_kwargs=fixture.source_kwargs(),
    )
    signed = signer.complete_signature(
        candidate,
        public_key,
        fixture.admission_private,
    )
    return write_json(
        fixture.custody.parent / "admission.signed.json",
        signed,
    )


def test_signed_admission_replays_policy_and_p0_then_consumes_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = build_fixture(tmp_path, monkeypatch)
    release_path = sign_release(fixture)
    verified = admission.verify_signed_admission(
        release_path,
        fixture.admission_keyring_path,
        now=NOW,
        **fixture.verify_kwargs(),
    )
    times = iter(
        [
            NOW + timedelta(seconds=1),
            NOW + timedelta(seconds=2),
            NOW + timedelta(seconds=3),
            NOW + timedelta(seconds=4),
        ]
    )

    exit_code, terminal = admission.execute_offline_admission(
        verified,
        lambda now: admission.verify_signed_admission(
            release_path,
            fixture.admission_keyring_path,
            now=now,
            **fixture.verify_kwargs(),
        ),
        custody_dir=fixture.custody,
        pinned_custody_path=fixture.custody,
        pinned_custody_identity_sha256=(
            fixture.custody_identity_sha256
        ),
        require_root_owned_parent=False,
        clock=lambda: next(times),
    )

    assert exit_code == 0
    assert terminal["terminal_state"] == admission.SUCCESS_STATE
    assert terminal["admission_fact_frozen"] is True
    assert terminal["collection_authorized"] is False
    assert terminal["runtime_activation_authorized"] is False
    consume_path = (
        fixture.custody
        / f"{verified.payload['attempt_id']}.admission-consumed.json"
    )
    terminal_path = (
        fixture.custody
        / f"{verified.payload['attempt_id']}.admission-terminal.json"
    )
    assert consume_path.stat().st_mode & 0o777 == 0o600
    assert terminal_path.stat().st_mode & 0o777 == 0o600
    consume_payload = json.loads(consume_path.read_text(encoding="utf-8"))
    terminal_payload = json.loads(terminal_path.read_text(encoding="utf-8"))
    for payload in (consume_payload, terminal_payload):
        assert (
            payload["custody_path_sha256"]
            == verified.payload["custody_path_sha256"]
        )
        assert (
            payload["custody_identity_sha256"]
            == fixture.custody_identity_sha256
        )
    terminal_path.unlink()
    with pytest.raises(
        admission.CollectionAdmissionError,
        match="already consumed",
    ):
        admission.execute_offline_admission(
            verified,
            lambda _now: verified,
            custody_dir=fixture.custody,
            pinned_custody_path=fixture.custody,
            pinned_custody_identity_sha256=(
                fixture.custody_identity_sha256
            ),
            require_root_owned_parent=False,
            clock=lambda: NOW + timedelta(seconds=4),
        )

    archived_custody = fixture.custody.with_name(
        "admission-custody-archived"
    )
    fixture.custody.rename(archived_custody)
    fixture.custody.mkdir(mode=0o700)
    write_json(
        fixture.custody / "custody-identity.json",
        {
            "schema_version": (
                "commodity_c_fast_t1_custody_identity_v1"
            ),
            "custody_id": "replacement-custody-20260901",
        },
    )
    with pytest.raises(
        OneShotError,
        match="custody identity SHA256 does not match",
    ):
        admission.verify_signed_admission(
            release_path,
            fixture.admission_keyring_path,
            now=NOW + timedelta(seconds=5),
            **fixture.verify_kwargs(),
        )


def test_raw_policy_ancestry_and_p0_bundle_splice_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = build_fixture(tmp_path, monkeypatch)
    fixture.policy_v1_path.write_bytes(
        fixture.policy_v1_path.read_bytes() + b"\n"
    )
    with pytest.raises(Exception):
        admission.verify_admission_sources(**fixture.source_kwargs())

    other = build_fixture(tmp_path / "other", monkeypatch)
    source_kwargs = fixture.source_kwargs()
    source_kwargs["bundle_paths"] = other.p0.paths
    source_kwargs["expected_upstream_keyring_sha256"] = other.p0.pins
    with pytest.raises(Exception):
        admission.verify_admission_sources(**source_kwargs)


def test_production_custody_requires_root_owned_immutable_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = build_fixture(tmp_path, monkeypatch)
    with pytest.raises(
        OneShotError,
        match="custody parent must be root-owned",
    ):
        admission._validate_custody_binding(
            {
                "custody_path_sha256": admission.custody_path_sha256(
                    fixture.custody
                ),
                "custody_identity_sha256": (
                    fixture.custody_identity_sha256
                ),
            },
            custody_dir=fixture.custody,
            pinned_custody_path=fixture.custody,
            pinned_custody_identity_sha256=(
                fixture.custody_identity_sha256
            ),
            require_root_owned_parent=True,
        )


@pytest.mark.parametrize("policy_version", ["v1", "v2"])
def test_policy_raw_replacement_during_signature_verification_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    policy_version: str,
) -> None:
    fixture = build_fixture(tmp_path, monkeypatch)
    target = (
        fixture.policy_v1_path
        if policy_version == "v1"
        else fixture.policy_v2_path
    )
    original = admission.verify_execution_policy_freeze_v2_raw_chain

    def replace_after_verification(*args, **kwargs):
        receipt = original(*args, **kwargs)
        write_bytes(target, target.read_bytes() + b"\n")
        return receipt

    monkeypatch.setattr(
        admission,
        "verify_execution_policy_freeze_v2_raw_chain",
        replace_after_verification,
    )
    with pytest.raises(
        admission.CollectionAdmissionError,
        match="policy raw chain changed during source verification",
    ):
        admission.verify_admission_sources(**fixture.source_kwargs())


@pytest.mark.parametrize("field", admission.FALSE_AUTHORITY_FIELDS)
def test_admission_cannot_enable_runtime_or_trading_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    fixture = build_fixture(tmp_path, monkeypatch)
    draft = draft_for(fixture)
    draft[field] = True
    with pytest.raises(OneShotError, match="schema validation failed"):
        validate_json_schema(
            {**draft, "signature": admission.PLACEHOLDER_SIGNATURE},
            admission.RELEASE_SCHEMA_PATH,
            "collection-admission release",
        )


def test_admission_ttl_attempt_and_source_binding_are_exact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = build_fixture(tmp_path, monkeypatch)
    sources = admission.verify_admission_sources(**fixture.source_kwargs())
    draft = draft_for(fixture, sources)
    draft["expires_at"] = (NOW + timedelta(minutes=11)).isoformat()
    with pytest.raises(
        admission.CollectionAdmissionError,
        match="TTL exceeds",
    ):
        admission.validate_admission_bindings(
            {**draft, "signature": admission.PLACEHOLDER_SIGNATURE},
            sources,
            **fixture.binding_kwargs(),
            now=NOW,
        )

    draft = draft_for(fixture, sources)
    with pytest.raises(
        admission.CollectionAdmissionError,
        match="not active",
    ):
        admission.validate_admission_bindings(
            {**draft, "signature": admission.PLACEHOLDER_SIGNATURE},
            sources,
            **fixture.binding_kwargs(),
            now=NOW + timedelta(minutes=6),
        )

    draft = draft_for(fixture, sources)
    draft["attempt_id"] = (
        "collection-admission-attempt-" + "f" * 64
    )
    with pytest.raises(
        admission.CollectionAdmissionError,
        match="identity is invalid",
    ):
        admission.validate_admission_bindings(
            {**draft, "signature": admission.PLACEHOLDER_SIGNATURE},
            sources,
            **fixture.binding_kwargs(),
            now=NOW,
        )

    draft = draft_for(fixture, sources)
    draft["source_binding"]["p0"]["bundle_index_sha256"] = "f" * 64
    with pytest.raises(
        admission.CollectionAdmissionError,
        match="source binding mismatch",
    ):
        admission.validate_admission_bindings(
            {**draft, "signature": admission.PLACEHOLDER_SIGNATURE},
            sources,
            **fixture.binding_kwargs(),
            now=NOW,
        )


def test_admission_keyring_rejects_upstream_reuse_and_private_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = build_fixture(
        tmp_path / "unused",
        monkeypatch,
    )
    reused_keyring = admission_keyring(
        fixture.admission_private,
        unused=fixture.p0.acceptance_private,
    )
    write_json(
        fixture.admission_keyring_path,
        reused_keyring,
    )
    fixture.admission_pin = sha256(canonical_json(reused_keyring))
    with pytest.raises(
        admission.CollectionAdmissionError,
        match="reuses an upstream key",
    ):
        signer.prepare_admission(
            draft_for(fixture),
            fixture.admission_keyring_path,
            expected_admission_keyring_sha256=fixture.admission_pin,
            custody_dir=fixture.custody,
            pinned_custody_path=fixture.custody,
            pinned_custody_identity_sha256=(
                fixture.custody_identity_sha256
            ),
            require_root_owned_parent=False,
            now=NOW,
            source_kwargs=fixture.source_kwargs(),
        )

    clean = build_fixture(tmp_path / "mismatch", monkeypatch)
    candidate, public_key = signer.prepare_admission(
        draft_for(clean),
        clean.admission_keyring_path,
        expected_admission_keyring_sha256=clean.admission_pin,
        custody_dir=clean.custody,
        pinned_custody_path=clean.custody,
        pinned_custody_identity_sha256=(
            clean.custody_identity_sha256
        ),
        require_root_owned_parent=False,
        now=NOW,
        source_kwargs=clean.source_kwargs(),
    )
    with pytest.raises(
        admission.CollectionAdmissionError,
        match="private key does not match",
    ):
        signer.complete_signature(
            candidate,
            public_key,
            Ed25519PrivateKey.generate(),
        )


@pytest.mark.parametrize("rotated_pin", ["policy", "custody_identity"])
def test_pin_rotation_after_consume_writes_failure_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    rotated_pin: str,
) -> None:
    fixture = build_fixture(tmp_path, monkeypatch)
    release_path = sign_release(fixture)
    verified = admission.verify_signed_admission(
        release_path,
        fixture.admission_keyring_path,
        now=NOW,
        **fixture.verify_kwargs(),
    )
    times = iter(
        [
            NOW + timedelta(seconds=1),
            NOW + timedelta(seconds=2),
            NOW + timedelta(seconds=3),
            NOW + timedelta(seconds=4),
        ]
    )
    calls = 0

    def rotated_revalidation(now: datetime):
        nonlocal calls
        calls += 1
        if calls == 2 and rotated_pin == "policy":
            keyring = json.loads(
                fixture.policy_keyring_path.read_text(encoding="utf-8")
            )
            keyring["rotated-policy-key"] = {
                "public_key_base64": base64.b64encode(
                    public_raw(Ed25519PrivateKey.generate())
                ).decode("ascii"),
                "purpose": admission.POLICY_KEY_PURPOSE,
            }
            write_json(fixture.policy_keyring_path, keyring)
        verify_kwargs = fixture.verify_kwargs()
        if calls == 2 and rotated_pin == "custody_identity":
            verify_kwargs["pinned_custody_identity_sha256"] = "f" * 64
        return admission.verify_signed_admission(
            release_path,
            fixture.admission_keyring_path,
            now=now,
            **verify_kwargs,
        )

    exit_code, terminal = admission.execute_offline_admission(
        verified,
        rotated_revalidation,
        custody_dir=fixture.custody,
        pinned_custody_path=fixture.custody,
        pinned_custody_identity_sha256=(
            fixture.custody_identity_sha256
        ),
        require_root_owned_parent=False,
        clock=lambda: next(times),
    )
    assert exit_code == 2
    assert terminal["terminal_state"] == admission.FAILURE_STATE
    assert terminal["error_code"] == "FINAL_REVALIDATION_FAILED"
    assert terminal["admission_fact_frozen"] is False
    assert terminal["collection_authorized"] is False


def test_terminal_schema_rejects_nonzero_side_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = build_fixture(tmp_path, monkeypatch)
    release_path = sign_release(fixture)
    verified = admission.verify_signed_admission(
        release_path,
        fixture.admission_keyring_path,
        now=NOW,
        **fixture.verify_kwargs(),
    )
    terminal = admission._terminal_payload(
        verified,
        consume_raw_sha256="a" * 64,
        consume_canonical_sha256="b" * 64,
        started_at=NOW,
        final_revalidation_at=NOW + timedelta(seconds=1),
        ended_at=NOW + timedelta(seconds=2),
        success=True,
        error_code=None,
    )
    terminal["orders_sent"] = 1
    with pytest.raises(OneShotError, match="schema validation failed"):
        validate_json_schema(
            terminal,
            admission.TERMINAL_SCHEMA_PATH,
            "collection-admission terminal",
        )


def test_template_is_invalid_and_signed_output_is_private_create_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    template_path = (
        ROOT
        / "docs/operations/"
        "c-fast-execution-quality-collection-admission-v1.template.json"
    )
    template = json.loads(template_path.read_text(encoding="utf-8"))
    with pytest.raises(OneShotError):
        validate_json_schema(
            template,
            admission.RELEASE_SCHEMA_PATH,
            "collection-admission template",
        )

    fixture = build_fixture(tmp_path / "signed", monkeypatch)
    release_path = sign_release(fixture)
    signed = json.loads(release_path.read_text(encoding="utf-8"))
    private_dir = tmp_path / "private-output"
    private_dir.mkdir(mode=0o700)
    output = private_dir / "admission.json"
    write_private_json_create_only_verified(output, signed)
    assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        write_private_json_create_only_verified(output, signed)


def test_verifier_has_no_runtime_network_or_database_entrypoint() -> None:
    source = admission.VERIFIER_PATH.read_text(encoding="utf-8")
    forbidden = (
        "psycopg",
        "requests.",
        "httpx.",
        "send_order",
        "cancel_order",
        "TradeService",
        "QuestDB",
        "Settings",
    )
    assert all(token not in source for token in forbidden)
