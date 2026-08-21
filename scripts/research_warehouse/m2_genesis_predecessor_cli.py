"""Root-only publisher for the one current-root #362 Genesis artifact.

The operator can provide only fixed protected paths.  The root parent reads
root-managed runtime facts and writes the existing create-only catalog; a
forked, permanently demoted vnpyresearch child reads the private continuous
configuration and replays the signed Genesis evidence.  This command has no
Execution, Gateway, Windows, RPC, broker, or network dependency.
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import canonical_json_line, parse_json_strict, sha256
from .daily_roll_predecessor_catalog import (
    ProtectedGenesisReplayInputs,
    _close_child_inherited_descriptors,
    _drop_to_protected_replay_identity,
    _read_protected_replay_payload,
    _require_exact_service_identity,
    load_current_catalog_head,
    publish_predecessor_artifact,
)
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .m2_isolation_contracts import false_authority, load_isolation_policy
from .m2_operator_defaults import DEFAULT_OPERATOR_STATE
from .m2_operator_state import load_operator_state, operator_state_lock
from .m2_runtime_input import DEFAULT_RUNTIME_INPUT, load_runtime_input, require_sha

_CONFIG_SCHEMA = "web-bridge-simnow-continuous-run-once-config-v1"
_CONFIG_MAX_BYTES = 64 * 1024
_CONTINUOUS_CONFIG_GID = 20
_REQUEST_SCHEMA = "vnpy_research_m2_genesis_config_projection_v1"


class GenesisPublisherCliError(RegistryError):
    """The root-only Genesis publisher must fail closed."""


@dataclass(frozen=True)
class _GenesisConfigProjection:
    runtime_input_raw_sha256: str
    history_receipt_path: Path
    history_receipt_raw_sha256: str
    manifest_public_key_path: Path
    manifest_public_key_raw_sha256: str
    signed_baseline_batch_path: Path
    business_public_key_path: Path
    business_public_key_raw_sha256: str
    business_signer_key_id: str
    contract_registry_path: Path
    contract_registry_raw_sha256: str
    source_month: str
    execution_month: str


def _require_root() -> None:
    if os.getuid() != 0 or os.geteuid() != 0:
        raise GenesisPublisherCliError("Genesis publisher requires root")


def _month(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) != 7 or value[4:5] != "-":
        raise GenesisPublisherCliError(f"{label} is invalid")
    try:
        year = int(value[:4])
        month = int(value[5:])
    except ValueError as exc:
        raise GenesisPublisherCliError(f"{label} is invalid") from exc
    if not 1 <= month <= 12 or f"{year:04d}-{month:02d}" != value:
        raise GenesisPublisherCliError(f"{label} is invalid")
    return value


def _absolute(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise GenesisPublisherCliError(f"{label} is invalid")
    path = Path(value)
    if not path.is_absolute():
        raise GenesisPublisherCliError(f"{label} is invalid")
    return path


def _config_raw(path: Path, *, uid: int) -> bytes:
    if not path.is_absolute():
        raise GenesisPublisherCliError("continuous config path is invalid")
    try:
        parent = path.parent.lstat()
        info = path.lstat()
    except OSError as exc:
        raise GenesisPublisherCliError("continuous config is unavailable") from exc
    if (
        stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or parent.st_uid != uid
        or parent.st_gid != _CONTINUOUS_CONFIG_GID
        or info.st_uid != uid
        or info.st_gid != _CONTINUOUS_CONFIG_GID
        or stat.S_IMODE(parent.st_mode) != 0o700
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
    ):
        raise GenesisPublisherCliError("continuous config custody is invalid")
    return read_regular_strict(
        path,
        "Genesis publisher continuous config",
        limit=_CONFIG_MAX_BYTES,
    )


def _projection_from_config(raw: bytes) -> _GenesisConfigProjection:
    value = parse_json_strict(raw, "Genesis publisher continuous config")
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != _CONFIG_SCHEMA
        or value.get("authority") != false_authority()
        or canonical_json_line(value) != raw
    ):
        raise GenesisPublisherCliError("continuous config contract is invalid")
    required = {
        "warehouse_runtime_input_raw_sha256",
        "warehouse_history_receipt_path",
        "warehouse_history_receipt_raw_sha256",
        "warehouse_manifest_public_key_path",
        "warehouse_manifest_public_key_raw_sha256",
        "warehouse_signed_baseline_batch_path",
        "warehouse_business_public_key_path",
        "warehouse_business_public_key_raw_sha256",
        "warehouse_business_signer_key_id",
        "warehouse_contract_registry_path",
        "warehouse_contract_registry_raw_sha256",
        "bootstrap_source_month",
        "bootstrap_execution_month",
        "bootstrap_static_core_equal_sha256",
        "bootstrap_position_manager_sha256",
        "bootstrap_final_target_sha256",
    }
    if not required <= set(value):
        raise GenesisPublisherCliError("continuous config Genesis fields are missing")
    for field in (
        "warehouse_runtime_input_raw_sha256",
        "warehouse_history_receipt_raw_sha256",
        "warehouse_manifest_public_key_raw_sha256",
        "warehouse_business_public_key_raw_sha256",
        "warehouse_contract_registry_raw_sha256",
        "bootstrap_static_core_equal_sha256",
        "bootstrap_position_manager_sha256",
        "bootstrap_final_target_sha256",
    ):
        require_sha(value[field], field)
    if (
        not isinstance(value["warehouse_business_signer_key_id"], str)
        or not value["warehouse_business_signer_key_id"]
    ):
        raise GenesisPublisherCliError("continuous config signer identity is invalid")
    return _GenesisConfigProjection(
        runtime_input_raw_sha256=value["warehouse_runtime_input_raw_sha256"],
        history_receipt_path=_absolute(
            value["warehouse_history_receipt_path"], "history receipt path"
        ),
        history_receipt_raw_sha256=value["warehouse_history_receipt_raw_sha256"],
        manifest_public_key_path=_absolute(
            value["warehouse_manifest_public_key_path"], "manifest public key path"
        ),
        manifest_public_key_raw_sha256=(
            value["warehouse_manifest_public_key_raw_sha256"]
        ),
        signed_baseline_batch_path=_absolute(
            value["warehouse_signed_baseline_batch_path"], "signed baseline path"
        ),
        business_public_key_path=_absolute(
            value["warehouse_business_public_key_path"], "business public key path"
        ),
        business_public_key_raw_sha256=(
            value["warehouse_business_public_key_raw_sha256"]
        ),
        business_signer_key_id=value["warehouse_business_signer_key_id"],
        contract_registry_path=_absolute(
            value["warehouse_contract_registry_path"], "contract registry path"
        ),
        contract_registry_raw_sha256=value["warehouse_contract_registry_raw_sha256"],
        source_month=_month(value["bootstrap_source_month"], "bootstrap source month"),
        execution_month=_month(
            value["bootstrap_execution_month"], "bootstrap execution month"
        ),
    )


def _projection_payload(value: _GenesisConfigProjection) -> bytes:
    return canonical_json_line(
        {
            "schema_version": _REQUEST_SCHEMA,
            "runtime_input_raw_sha256": value.runtime_input_raw_sha256,
            "history_receipt_path": str(value.history_receipt_path),
            "history_receipt_raw_sha256": value.history_receipt_raw_sha256,
            "manifest_public_key_path": str(value.manifest_public_key_path),
            "manifest_public_key_raw_sha256": value.manifest_public_key_raw_sha256,
            "signed_baseline_batch_path": str(value.signed_baseline_batch_path),
            "business_public_key_path": str(value.business_public_key_path),
            "business_public_key_raw_sha256": value.business_public_key_raw_sha256,
            "business_signer_key_id": value.business_signer_key_id,
            "contract_registry_path": str(value.contract_registry_path),
            "contract_registry_raw_sha256": value.contract_registry_raw_sha256,
            "source_month": value.source_month,
            "execution_month": value.execution_month,
            "authority": false_authority(),
        }
    )


def _projection_from_payload(raw: bytes) -> _GenesisConfigProjection:
    value = parse_json_strict(raw, "Genesis publisher config projection")
    expected = {
        "schema_version",
        "runtime_input_raw_sha256",
        "history_receipt_path",
        "history_receipt_raw_sha256",
        "manifest_public_key_path",
        "manifest_public_key_raw_sha256",
        "signed_baseline_batch_path",
        "business_public_key_path",
        "business_public_key_raw_sha256",
        "business_signer_key_id",
        "contract_registry_path",
        "contract_registry_raw_sha256",
        "source_month",
        "execution_month",
        "authority",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value["schema_version"] != _REQUEST_SCHEMA
        or value["authority"] != false_authority()
        or canonical_json_line(value) != raw
    ):
        raise GenesisPublisherCliError("Genesis config projection is invalid")
    for field in (
        "runtime_input_raw_sha256",
        "history_receipt_raw_sha256",
        "manifest_public_key_raw_sha256",
        "business_public_key_raw_sha256",
        "contract_registry_raw_sha256",
    ):
        require_sha(value[field], field)
    if (
        not isinstance(value["business_signer_key_id"], str)
        or not value["business_signer_key_id"]
    ):
        raise GenesisPublisherCliError("Genesis config signer identity is invalid")
    return _GenesisConfigProjection(
        runtime_input_raw_sha256=value["runtime_input_raw_sha256"],
        history_receipt_path=_absolute(value["history_receipt_path"], "history receipt"),
        history_receipt_raw_sha256=value["history_receipt_raw_sha256"],
        manifest_public_key_path=_absolute(
            value["manifest_public_key_path"], "manifest public key"
        ),
        manifest_public_key_raw_sha256=value["manifest_public_key_raw_sha256"],
        signed_baseline_batch_path=_absolute(
            value["signed_baseline_batch_path"], "signed baseline"
        ),
        business_public_key_path=_absolute(
            value["business_public_key_path"], "business public key"
        ),
        business_public_key_raw_sha256=value["business_public_key_raw_sha256"],
        business_signer_key_id=value["business_signer_key_id"],
        contract_registry_path=_absolute(
            value["contract_registry_path"], "contract registry"
        ),
        contract_registry_raw_sha256=value["contract_registry_raw_sha256"],
        source_month=_month(value["source_month"], "Genesis source month"),
        execution_month=_month(value["execution_month"], "Genesis execution month"),
    )


def _load_projection_as_service(
    *,
    config_path: Path,
    service_uid: int,
    service_gid: int,
) -> _GenesisConfigProjection:
    _require_root()
    uid, gid = _require_exact_service_identity(service_uid, service_gid)
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        status = 70
        try:
            os.close(read_fd)
            result_fd = _close_child_inherited_descriptors(result_fd=write_fd)
            _drop_to_protected_replay_identity(uid=uid, gid=gid)
            raw = _projection_payload(
                _projection_from_config(_config_raw(config_path, uid=uid))
            )
            offset = 0
            while offset < len(raw):
                offset += os.write(result_fd, raw[offset:])
            status = 0
        except (OSError, RegistryError, ValueError):
            pass
        finally:
            try:
                os.close(3)
            except OSError:
                pass
        os._exit(status)
    os.close(write_fd)
    try:
        raw = _read_protected_replay_payload(descriptor=read_fd, child=child)
    finally:
        os.close(read_fd)
    if len(raw) > _CONFIG_MAX_BYTES:
        raise GenesisPublisherCliError("Genesis config projection exceeds limit")
    return _projection_from_payload(raw)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--runtime-input", type=Path, default=DEFAULT_RUNTIME_INPUT)
    result.add_argument("--operator-state", type=Path, default=DEFAULT_OPERATOR_STATE)
    result.add_argument("--continuous-config", type=Path, required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        _require_root()
        policy = load_isolation_policy(args.runtime_input.parent / "isolation-policy-v1.json")
        runtime_input = load_runtime_input(args.runtime_input, policy=policy)
        with operator_state_lock(args.operator_state, exclusive=False):
            state = load_operator_state(args.operator_state)
        projection = _load_projection_as_service(
            config_path=args.continuous_config,
            service_uid=policy.uid,
            service_gid=policy.gid,
        )
        if projection.runtime_input_raw_sha256 != runtime_input.raw_sha256:
            raise GenesisPublisherCliError("continuous config runtime input pin drifted")
        official_day = state.payload["last_trade_day"]
        if not isinstance(official_day, str) or official_day[:7] != projection.execution_month:
            raise GenesisPublisherCliError("Genesis execution month is not current root")
        entry = publish_predecessor_artifact(
            context=None,
            operator_state=state,
            history_receipt_path=None,
            pins=None,
            manifest_public_key_path=None,
            official_day=official_day,
            contract_registry_raw=None,
            expected_contract_registry_raw_sha256=None,
            protected_genesis_inputs=ProtectedGenesisReplayInputs(
                history_receipt_path=projection.history_receipt_path,
                runtime_input_path=args.runtime_input,
                runtime_input_raw_sha256=runtime_input.raw_sha256,
                service_uid=policy.uid,
                service_gid=policy.gid,
                history_receipt_raw_sha256=projection.history_receipt_raw_sha256,
                manifest_public_key_path=projection.manifest_public_key_path,
                manifest_public_key_raw_sha256=(
                    projection.manifest_public_key_raw_sha256
                ),
                signed_baseline_batch_path=projection.signed_baseline_batch_path,
                business_public_key_path=projection.business_public_key_path,
                business_public_key_raw_sha256=(
                    projection.business_public_key_raw_sha256
                ),
                business_signer_key_id=projection.business_signer_key_id,
                contract_registry_path=projection.contract_registry_path,
                contract_registry_raw_sha256=(
                    projection.contract_registry_raw_sha256
                ),
                source_month=projection.source_month,
            ),
        )
        head = load_current_catalog_head(args.operator_state)
        if head.receipt_raw != entry.receipt_raw or head.artifact_raw != entry.artifact_raw:
            raise GenesisPublisherCliError("Genesis publication readback mismatches")
        output: dict[str, Any] = {
            "schema_version": "vnpy_research_m2_genesis_publication_result_v1",
            "status": "GENESIS_PUBLISHED",
            "receipt_id": entry.receipt["receipt_id"],
            "artifact_id": entry.artifact["artifact_id"],
            "sequence": entry.receipt["sequence"],
            "official_day": entry.receipt["official_day"],
            "receipt_raw_sha256": sha256(entry.receipt_raw),
            "artifact_raw_sha256": sha256(entry.artifact_raw),
            "authority": false_authority(),
        }
    except (OSError, RegistryError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_json_line(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
