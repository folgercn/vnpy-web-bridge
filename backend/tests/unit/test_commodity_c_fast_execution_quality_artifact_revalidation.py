from __future__ import annotations

import ast
import hashlib
import json
import os
import tempfile
from collections.abc import Iterator
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.core.config import Settings
from app.schemas.commodity_c_fast_execution_quality_runtime import (
    CFastExecutionQualityArtifactVerificationDTO,
)
from app.services.commodity_c_fast_execution_quality_artifact_revalidation import (
    ARTIFACT_ROLES,
    ArtifactVerificationRequest,
    CFastExecutionQualityArtifactRevalidationError,
    CommodityCFastExecutionQualityArtifactRevalidator,
)
from app.services.commodity_c_fast_execution_quality_runtime import (
    CommodityCFastExecutionQualityRuntime,
)


NOW = datetime(2026, 9, 1, 1, 0, tzinfo=timezone.utc)
CONTRACTS = ("SHFE.ag2612", "SHFE.cu2612")
FALSE_AUTHORITY = {
    "collection_authorized": False,
    "runtime_activation_authorized": False,
    "authority_granted": False,
    "dispatch_allowed": False,
    "order_authorized": False,
    "position_mutation_authorized": False,
    "database_mutation_authorized": False,
    "deployment_mutation_authorized": False,
    "replacement_allowed": False,
    "production_allowed": False,
}
REQUIRED_BINDINGS = {
    "signed_p0_acceptance": (),
    "collection_admission": ("signed_p0_acceptance", "execution_policy"),
    "execution_policy": (),
    "signed_snapshot": ("contract_spec_set",),
    "virtual_intent_plan": (
        "execution_policy",
        "signed_snapshot",
        "contract_spec_set",
    ),
    "contract_spec_set": (),
    "custody_binding": ARTIFACT_ROLES[:-1],
}
SIGNER_DOMAINS = {
    role: (format(index + 8, "x") * 64,) for index, role in enumerate(ARTIFACT_ROLES)
}


@pytest.fixture
def secure_tmp_path() -> Iterator[Path]:
    """Exercise the real full-chain guard outside root-owned sticky /tmp."""

    with tempfile.TemporaryDirectory(
        prefix="cfast-artifact-revalidation-",
        dir=Path.home(),
    ) as directory:
        path = Path(directory)
        path.chmod(0o700)
        yield path


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def custody_pins(root: Path) -> tuple[str, str]:
    info = root.lstat()
    path_sha256 = digest(str(root).encode("utf-8"))
    identity = {
        "path_sha256": path_sha256,
        "device": info.st_dev,
        "inode": info.st_ino,
        "owner_uid": info.st_uid,
        "owner_gid": info.st_gid,
        "mode": info.st_mode & 0o7777,
    }
    return path_sha256, digest(canonical(identity))


def build_adapter(
    tmp_path: Path,
    *,
    expires_at: datetime = NOW + timedelta(minutes=5),
    mutate_role: str | None = None,
    omit_verifier: str | None = None,
    bad_binding: bool = False,
    path_collision: bool = False,
    mutate_constructor_inputs: bool = False,
) -> CommodityCFastExecutionQualityArtifactRevalidator:
    root = tmp_path / "sealed"
    root.mkdir(mode=0o700)
    paths = {}
    raw_hashes = {}
    for role in ARTIFACT_ROLES:
        path = root / f"{role}.json"
        raw = (
            canonical(
                {
                    "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
                    "role": role,
                    "signature": f"test-signature-{role}",
                }
            )
            + b"\n"
        )
        path.write_bytes(raw)
        path.chmod(0o600)
        paths[role] = path
        raw_hashes[role] = digest(raw)

    mutated = False

    def verifier(
        request: ArtifactVerificationRequest,
    ) -> CFastExecutionQualityArtifactVerificationDTO:
        nonlocal mutated
        assert request.payload["role"] == request.role
        assert request.payload["signature"] == f"test-signature-{request.role}"
        if request.role == mutate_role and not mutated:
            mutated = True
            changed = dict(request.payload)
            changed["signature"] = "changed-after-verification"
            request.path.write_bytes(canonical(changed) + b"\n")
            request.path.chmod(0o600)
        bindings = {role: raw_hashes[role] for role in REQUIRED_BINDINGS[request.role]}
        if bad_binding and request.role == "virtual_intent_plan":
            bindings["signed_snapshot"] = "f" * 64
        return CFastExecutionQualityArtifactVerificationDTO(
            schema_version=(
                "commodity_c_fast_execution_quality_artifact_verification_v1"
            ),
            artifact_role=request.role,
            candidate_id="C_FAST_CROSS_SECTION_NEUTRAL",
            raw_sha256=request.raw_sha256,
            canonical_sha256=request.canonical_sha256,
            valid_until_utc=(
                expires_at
                if request.role
                in {
                    "signed_p0_acceptance",
                    "collection_admission",
                    "signed_snapshot",
                    "custody_binding",
                }
                else None
            ),
            exact_contracts=CONTRACTS,
            bound_artifact_raw_sha256=bindings,
            verified_signer_domain_public_key_sha256=(SIGNER_DOMAINS[request.role]),
            signature_verified=True,
            semantic_contract_verified=True,
            **FALSE_AUTHORITY,
        )

    verifiers = {role: verifier for role in ARTIFACT_ROLES}
    if omit_verifier:
        verifiers.pop(omit_verifier)
    root_path_pin, root_identity_pin = custody_pins(root)
    if path_collision:
        paths["contract_spec_set"] = paths["execution_policy"]
    adapter = CommodityCFastExecutionQualityArtifactRevalidator(
        artifact_paths=paths,
        artifact_verifiers=verifiers,
        custody_root=root,
        expected_custody_root_path_sha256=root_path_pin,
        expected_custody_identity_sha256=root_identity_pin,
        expected_owner_uid=os.getuid(),
    )
    if mutate_constructor_inputs:
        paths.clear()
        verifiers.clear()
    return adapter


def test_exact_artifact_set_revalidates_without_runtime_authority(
    secure_tmp_path: Path,
) -> None:
    adapter = build_adapter(secure_tmp_path)
    runtime = CommodityCFastExecutionQualityRuntime(
        settings=Settings(commodity_c_fast_execution_quality_runtime_enabled=True),
        clock=lambda: NOW,
    )
    runtime.bind_full_revalidation_verifier(adapter)

    status = runtime.start()

    assert status["runtime_state"] == (
        "REVALIDATED_FOUNDATION_ONLY_TICK_RUNTIME_NOT_BUILT"
    )
    assert status["full_revalidation_complete"] is True
    assert status["exact_contracts"] == list(CONTRACTS)
    assert status["runtime_active"] is False
    assert status["execution_quality_implemented"] is False
    assert status["orders_sent"] == 0
    assert status["positions_modified"] == 0
    assert all(status[field] is False for field in FALSE_AUTHORITY)


@pytest.mark.parametrize(
    ("kwargs", "code"),
    [
        (
            {"omit_verifier": "contract_spec_set"},
            "ARTIFACT_VERIFIER_SET_INCOMPLETE",
        ),
        (
            {"bad_binding": True},
            "ARTIFACT_BINDING_DIGEST_MISMATCH",
        ),
        (
            {"expires_at": NOW},
            "ARTIFACT_EXPIRED_OR_MISSING_EXPIRY",
        ),
        (
            {"mutate_role": "signed_snapshot"},
            "ARTIFACT_CHANGED_DURING_REVALIDATION",
        ),
    ],
)
def test_incomplete_spliced_expired_or_mutated_set_fails_closed(
    secure_tmp_path: Path,
    kwargs: dict[str, object],
    code: str,
) -> None:
    adapter = build_adapter(secure_tmp_path, **kwargs)

    with pytest.raises(
        CFastExecutionQualityArtifactRevalidationError,
        match=code,
    ):
        adapter("startup", NOW)


def test_artifacts_must_be_distinct_canonical_files_inside_pinned_custody(
    secure_tmp_path: Path,
) -> None:
    adapter = build_adapter(secure_tmp_path, path_collision=True)
    with pytest.raises(
        CFastExecutionQualityArtifactRevalidationError,
        match="ARTIFACT_PATH_COLLISION",
    ):
        adapter("startup", NOW)


def test_constructor_takes_immutable_path_and_verifier_snapshots(
    secure_tmp_path: Path,
) -> None:
    adapter = build_adapter(
        secure_tmp_path,
        mutate_constructor_inputs=True,
    )

    receipt = adapter("startup", NOW)

    assert receipt.exact_contracts == CONTRACTS
    assert receipt.verified_signer_domains.model_dump(mode="python") == (SIGNER_DOMAINS)
    with pytest.raises(TypeError):
        adapter._artifact_paths["signed_snapshot"] = Path("/tmp/replaced")
    with pytest.raises(TypeError):
        adapter._artifact_verifiers["signed_snapshot"] = lambda _: None
    for field, replacement in (
        ("_artifact_paths", {}),
        ("_artifact_verifiers", {}),
        ("custody_root", Path("/tmp/replaced")),
        ("expected_custody_root_path_sha256", "f" * 64),
        ("expected_custody_identity_sha256", "e" * 64),
        ("expected_owner_uid", 0),
    ):
        with pytest.raises(FrozenInstanceError):
            setattr(adapter, field, replacement)


def test_exact_file_reader_handles_short_os_reads(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = build_adapter(secure_tmp_path)
    original_read = os.read

    def short_read(fd: int, size: int) -> bytes:
        return original_read(fd, min(size, 3))

    monkeypatch.setattr(os, "read", short_read)

    assert adapter("startup", NOW).exact_contracts == CONTRACTS


def test_initial_custody_revalidation_failure_closes_retained_fd(
    secure_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = build_adapter(secure_tmp_path)
    retained_fds: list[int] = []

    def fail_initial_guard(
        _adapter: CommodityCFastExecutionQualityArtifactRevalidator,
        guard: object,
    ) -> None:
        retained_fds.append(guard.fd)
        raise CFastExecutionQualityArtifactRevalidationError("CUSTODY_ROOT_CHANGED")

    monkeypatch.setattr(
        CommodityCFastExecutionQualityArtifactRevalidator,
        "_verify_open_custody_root",
        fail_initial_guard,
    )

    with pytest.raises(
        CFastExecutionQualityArtifactRevalidationError,
        match="CUSTODY_ROOT_CHANGED",
    ):
        adapter("startup", NOW)

    assert len(retained_fds) == 1
    with pytest.raises(OSError):
        os.fstat(retained_fds[0])


def test_world_writable_ancestor_is_rejected_without_relaxing_full_chain(
    secure_tmp_path: Path,
) -> None:
    unsafe_parent = secure_tmp_path / "unsafe-parent"
    unsafe_parent.mkdir(mode=0o700)
    unsafe_parent.chmod(0o777)
    try:
        adapter = build_adapter(unsafe_parent)

        with pytest.raises(
            CFastExecutionQualityArtifactRevalidationError,
            match="CUSTODY_ROOT_INVALID",
        ):
            adapter("startup", NOW)
    finally:
        unsafe_parent.chmod(0o700)


def test_adapter_has_no_tick_questdb_rpc_or_trading_dependency() -> None:
    service_path = (
        Path(__file__).resolve().parents[2]
        / "app"
        / "services"
        / "commodity_c_fast_execution_quality_artifact_revalidation.py"
    )
    tree = ast.parse(service_path.read_text(encoding="utf-8"))
    imports = {
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }
    assert imports.isdisjoint(
        {
            "app.services.commodity_simnow",
            "app.services.market_data_service",
            "app.services.tick_persistence",
            "app.services.trade_service",
            "app.services.vnpy_rpc_service",
            "psycopg",
            "questdb",
        }
    )
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    assert names.isdisjoint(
        {"send_order", "cancel_order", "rpc_service", "TradeService"}
    )
