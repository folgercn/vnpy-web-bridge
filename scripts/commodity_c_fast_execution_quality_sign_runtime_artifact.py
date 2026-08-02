#!/usr/bin/env python3
"""Sign one C_FAST execution-quality runtime envelope in its exact role domain."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import os
from pathlib import Path
import stat
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.schemas.commodity_c_fast_execution_quality_production_artifacts import (  # noqa: E402
    CFastExecutionQualityCollectionAdmissionV2DTO,
    CFastExecutionQualityP0AcceptanceV6DTO,
    CFastExecutionQualityRoleTrustedKeysDTO,
    CFastExecutionQualitySignedContractSpecSetDTO,
    CFastExecutionQualitySignedCustodyBindingDTO,
    CFastExecutionQualitySignedPlanDTO,
)
from app.services.commodity_c_fast_execution_quality_production_verifier import (  # noqa: E402
    CommodityCFastExecutionQualityProductionArtifactVerifier,
    ROLE_SIGNER_PURPOSES,
    runtime_artifact_signature_message,
)
from app.services.commodity_c_fast_execution_quality_runtime_admission import (  # noqa: E402
    _read_exact_private_canonical_json,
    canonical_json,
)
from app.services.commodity_c_fast_shadow import PRODUCTS  # noqa: E402


PLACEHOLDER_SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")
ROLE_MODELS = {
    "signed_p0_acceptance": CFastExecutionQualityP0AcceptanceV6DTO,
    "collection_admission": CFastExecutionQualityCollectionAdmissionV2DTO,
    "virtual_intent_plan": CFastExecutionQualitySignedPlanDTO,
    "contract_spec_set": CFastExecutionQualitySignedContractSpecSetDTO,
    "custody_binding": CFastExecutionQualitySignedCustodyBindingDTO,
}
class RuntimeArtifactSigningError(ValueError):
    pass


def load_private_key(path: Path) -> Ed25519PrivateKey:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
        raise RuntimeArtifactSigningError(
            "private key must be one regular, owned, single-link file"
        )
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise RuntimeArtifactSigningError(
            "private key permissions must be 0600 or stricter"
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            (opened.st_dev, opened.st_ino, opened.st_size)
            != (info.st_dev, info.st_ino, info.st_size)
            or opened.st_size > 16 * 1024
        ):
            raise RuntimeArtifactSigningError(
                "private key identity changed or exceeds 16 KiB"
            )
        raw = os.read(descriptor, opened.st_size + 1).strip()
        if os.fstat(descriptor).st_size != opened.st_size:
            raise RuntimeArtifactSigningError("private key changed while reading")
    finally:
        os.close(descriptor)
    if raw.startswith(b"-----BEGIN"):
        try:
            key = serialization.load_pem_private_key(raw, password=None)
        except (TypeError, ValueError) as exc:
            raise RuntimeArtifactSigningError(
                "private key PEM is invalid or encrypted"
            ) from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise RuntimeArtifactSigningError("private key is not Ed25519")
        return key
    try:
        decoded = base64.b64decode(raw, validate=True)
    except ValueError as exc:
        raise RuntimeArtifactSigningError(
            "private key must be unencrypted Ed25519 PEM or base64 raw bytes"
        ) from exc
    if len(decoded) != 32:
        raise RuntimeArtifactSigningError(
            "raw Ed25519 private key must contain exactly 32 bytes"
        )
    return Ed25519PrivateKey.from_private_bytes(decoded)


def sign_runtime_artifact(
    draft: dict[str, object],
    *,
    private_key: Ed25519PrivateKey,
    keyring: CFastExecutionQualityRoleTrustedKeysDTO,
) -> dict[str, object]:
    role, selected = validate_runtime_artifact_draft(draft, keyring=keyring)
    expected_public = base64.b64decode(selected.public_key_base64, validate=True)
    actual_public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    if not hmac.compare_digest(actual_public, expected_public):
        raise RuntimeArtifactSigningError(
            "private key does not match the selected role signer"
        )
    signature = private_key.sign(runtime_artifact_signature_message(role, draft))
    signed = {
        **draft,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    try:
        ROLE_MODELS[role].model_validate(signed)
    except ValidationError as exc:
        raise RuntimeArtifactSigningError(
            "signed runtime artifact schema is invalid"
        ) from exc
    return signed


def validate_runtime_artifact_draft(
    draft: dict[str, object],
    *,
    keyring: CFastExecutionQualityRoleTrustedKeysDTO,
):
    if "signature" in draft:
        raise RuntimeArtifactSigningError(
            "unsigned runtime artifact draft must omit signature"
        )
    role = draft.get("artifact_role")
    if role not in ROLE_MODELS:
        raise RuntimeArtifactSigningError("runtime artifact role is not signable")
    if keyring.artifact_role != role:
        raise RuntimeArtifactSigningError("runtime artifact keyring role mismatch")
    signer_key_id = draft.get("signer_key_id")
    selected = next(
        (item for item in keyring.trusted_keys if item.key_id == signer_key_id),
        None,
    )
    if selected is None or selected.purpose != ROLE_SIGNER_PURPOSES[role]:
        raise RuntimeArtifactSigningError(
            "runtime artifact signer is not trusted for this role"
        )
    candidate = {**draft, "signature": PLACEHOLDER_SIGNATURE}
    try:
        model = ROLE_MODELS[role].model_validate(candidate)
    except ValidationError as exc:
        raise RuntimeArtifactSigningError(
            "unsigned runtime artifact schema is invalid"
        ) from exc
    if role == "signed_p0_acceptance":
        verifier = CommodityCFastExecutionQualityProductionArtifactVerifier()
        try:
            verifier.verify_p0_semantics(model)
        except ValueError as exc:
            raise RuntimeArtifactSigningError(
                "P0 evidence semantic replay failed before signing"
            ) from exc
    return role, selected


def write_private_json_create_only(path: Path, payload: object) -> bytes:
    output = path.expanduser()
    output = output if output.is_absolute() else Path.cwd() / output
    if Path(os.path.normpath(str(output))) != output:
        raise RuntimeArtifactSigningError("output path must already be normalized")
    parent = output.parent.resolve(strict=True)
    if output.parent != parent:
        raise RuntimeArtifactSigningError("output parent must not traverse a symlink")
    parent_info = parent.stat()
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != os.getuid()
        or stat.S_IMODE(parent_info.st_mode) & 0o077
    ):
        raise RuntimeArtifactSigningError(
            "output parent must be a pre-existing private owned directory"
        )
    raw = canonical_json(payload) + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(output, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    directory_fd = os.open(parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    observed, observed_raw = _read_exact_private_canonical_json(
        output,
        label="SIGNED_RUNTIME_ARTIFACT_OUTPUT",
        expected_owner_uid=os.getuid(),
    )
    if observed != payload or observed_raw != raw:
        raise RuntimeArtifactSigningError(
            "signed runtime artifact output failed exact round-trip"
        )
    return raw


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--private-key-file", type=Path, required=True)
    parser.add_argument("--role-keyring", type=Path, required=True)
    parser.add_argument("--expected-role-keyring-raw-sha256", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        draft, _draft_raw = _read_exact_private_canonical_json(
            args.input,
            label="UNSIGNED_RUNTIME_ARTIFACT_DRAFT",
            expected_owner_uid=os.getuid(),
        )
        keyring_payload, keyring_raw = _read_exact_private_canonical_json(
            args.role_keyring,
            label="RUNTIME_ARTIFACT_ROLE_KEYRING",
            expected_owner_uid=os.getuid(),
        )
        if not hmac.compare_digest(
            hashlib.sha256(keyring_raw).hexdigest(),
            args.expected_role_keyring_raw_sha256,
        ):
            raise RuntimeArtifactSigningError("role keyring raw pin mismatch")
        keyring = CFastExecutionQualityRoleTrustedKeysDTO.model_validate(
            keyring_payload
        )
        # P0 embeds all of its evidence. Replay that evidence before private
        # key material is opened so this tool cannot sign an unusable P0.
        validate_runtime_artifact_draft(draft, keyring=keyring)
        private_key = load_private_key(args.private_key_file)
        signed = sign_runtime_artifact(
            draft,
            private_key=private_key,
            keyring=keyring,
        )
        write_private_json_create_only(args.output, signed)
    except (
        RuntimeArtifactSigningError,
        OSError,
        ValueError,
        ValidationError,
    ) as exc:
        print(f"runtime artifact signing failed: {exc}", file=sys.stderr)
        return 2
    print(f"signed runtime artifact written: {args.output}")
    print(f"artifact_role: {signed['artifact_role']}")
    print(f"products: {len(PRODUCTS)}")
    print("collection_authorized: false")
    print("runtime_activation_authorized: false")
    print("dispatch_allowed: false")
    print("order_authorized: false")
    print("position_mutation_authorized: false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
