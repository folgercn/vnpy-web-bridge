from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Protocol

from pydantic import ValidationError

from app.schemas.commodity_c_fast_execution_quality_evidence_export import (
    CFastExecutionQualityEvidenceExportDTO,
)
from app.schemas.commodity_c_fast_execution_quality_production_artifacts import (
    CFastExecutionQualityP0AcceptanceV6DTO,
)
from app.schemas.commodity_c_fast_execution_quality_questdb import (
    CFastExecutionQualityQuestDBReadonlyEvidenceReceiptDTO,
)
from app.schemas.commodity_c_fast_execution_quality_runtime import (
    CFastExecutionQualityRuntimeRevalidationDTO,
)
from app.services.commodity_c_fast_execution_quality_evidence_export import (
    canonical_evidence_export_json_line,
)


_READONLY_PARAMETER_KEYS = (
    "pg.readonly.password",
    "pg.readonly.user",
    "pg.readonly.user.enabled",
    "pg.security.readonly",
    "pg.user",
    "readonly",
)
_READONLY_IDENTITY_SQL = "SELECT current_user(), build()"
_READONLY_PARAMETERS_SQL = (
    "(SHOW PARAMETERS) WHERE property_path IN "
    "('pg.readonly.password', 'pg.readonly.user', "
    "'pg.readonly.user.enabled', 'pg.security.readonly', 'pg.user', "
    "'readonly') ORDER BY property_path"
)
_MAX_DSN_BYTES = 16 * 1024
_MAX_P0_BYTES = 64 * 1024 * 1024
_FALSE_AUTHORITY = {
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


class CFastExecutionQualityQuestDBReadonlyError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ReadonlyQuestDBConnection(Protocol):
    info: Any

    def execute(self, query: str) -> Any: ...

    def close(self) -> None: ...


ReadonlyConnectionFactory = Callable[[str], ReadonlyQuestDBConnection]


@dataclass(frozen=True, slots=True)
class _ReadonlySnapshot:
    principal: str
    readonly_user: str
    admin_user: str
    questdb_build: str
    evidence: Mapping[str, Any]


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _default_connection_factory(dsn: str) -> ReadonlyQuestDBConnection:
    try:
        import psycopg

        return psycopg.connect(
            dsn,
            autocommit=True,
            connect_timeout=10,
            options="-c statement_timeout=60000",
        )
    except Exception as exc:
        raise CFastExecutionQualityQuestDBReadonlyError(
            "QUESTDB_READONLY_CONNECTION_FAILED"
        ) from exc


class CommodityCFastExecutionQualityQuestDBReadonlyEvidenceAdapter:
    """Verify one exact local evidence tip against a dedicated read-only DSN."""

    def __init__(
        self,
        *,
        dsn_path: Path,
        signed_p0_path: Path,
        expected_dsn_owner_uid: int,
        expected_p0_owner_uid: int,
        connection_factory: ReadonlyConnectionFactory | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        dsn_path = dsn_path.expanduser()
        signed_p0_path = signed_p0_path.expanduser()
        if (
            expected_dsn_owner_uid < 0
            or expected_p0_owner_uid < 0
            or not dsn_path.is_absolute()
            or not signed_p0_path.is_absolute()
        ):
            raise CFastExecutionQualityQuestDBReadonlyError(
                "QUESTDB_READONLY_CUSTODY_CONFIG_INVALID"
            )
        self._dsn_path = dsn_path
        self._signed_p0_path = signed_p0_path
        self._expected_dsn_owner_uid = expected_dsn_owner_uid
        self._expected_p0_owner_uid = expected_p0_owner_uid
        self._connection_factory = connection_factory or _default_connection_factory
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = RLock()
        self._generation = 0
        self._blocked = False
        self._last_error: str | None = None
        self._receipt: CFastExecutionQualityQuestDBReadonlyEvidenceReceiptDTO | None = (
            None
        )

    def verify(
        self,
        *,
        revalidation_receipt: CFastExecutionQualityRuntimeRevalidationDTO,
        repository_status: Mapping[str, object],
        evidence_export: CFastExecutionQualityEvidenceExportDTO,
    ) -> CFastExecutionQualityQuestDBReadonlyEvidenceReceiptDTO:
        with self._lock:
            connection: ReadonlyQuestDBConnection | None = None
            try:
                receipt = CFastExecutionQualityRuntimeRevalidationDTO.model_validate(
                    revalidation_receipt
                )
                exported = CFastExecutionQualityEvidenceExportDTO.model_validate(
                    evidence_export
                )
                now = self._utc_now()
                if not receipt.revalidated_at_utc <= now < receipt.valid_until_utc:
                    raise CFastExecutionQualityQuestDBReadonlyError(
                        "QUESTDB_READONLY_REVALIDATION_INACTIVE"
                    )
                self._verify_journal_export_join(
                    receipt=receipt,
                    repository_status=repository_status,
                    exported=exported,
                )
                p0 = self._load_exact_p0(receipt)
                reference = self._load_reference_readonly_proof(p0)
                dsn = self._read_private_text(
                    self._dsn_path,
                    "QUESTDB_READONLY_DSN",
                    _MAX_DSN_BYTES,
                )
                connection = self._connection_factory(dsn)
                endpoint_sha256 = self._endpoint_identity_sha256(connection)
                if not hmac.compare_digest(
                    endpoint_sha256,
                    str(reference["endpoint_identity_sha256"]),
                ):
                    raise CFastExecutionQualityQuestDBReadonlyError(
                        "QUESTDB_READONLY_ENDPOINT_MISMATCH"
                    )
                preflight = self._collect_snapshot(connection)
                postflight = self._collect_snapshot(connection)
                if preflight != postflight:
                    raise CFastExecutionQualityQuestDBReadonlyError(
                        "QUESTDB_READONLY_METADATA_DRIFT"
                    )
                if dict(preflight.evidence) != reference["preflight"]:
                    raise CFastExecutionQualityQuestDBReadonlyError(
                        "QUESTDB_READONLY_P0_METADATA_MISMATCH"
                    )
                connection.close()
                connection = None
                export_raw = canonical_evidence_export_json_line(
                    exported.model_dump(mode="json")
                )
                core = {
                    "schema_version": (
                        "commodity_c_fast_execution_quality_questdb_readonly_receipt_v1"
                    ),
                    "trigger": receipt.trigger,
                    "verified_at_utc": now.isoformat().replace("+00:00", "Z"),
                    "revalidation_receipt_sha256": receipt.receipt_sha256,
                    "signed_p0_acceptance_raw_sha256": (
                        receipt.signed_p0_acceptance_sha256
                    ),
                    "query_v6_terminal_raw_sha256": p0.terminal_raw_sha256,
                    "query_v6_readonly_proof_raw_sha256": (
                        p0.readonly_proof_raw_sha256
                    ),
                    "exact_contracts": list(receipt.exact_contracts),
                    "endpoint_identity_sha256": endpoint_sha256,
                    "questdb_build_sha256": _sha256(
                        preflight.questdb_build.encode("utf-8")
                    ),
                    "observable_readonly_metadata_sha256": _sha256(
                        _canonical_json(preflight.evidence)
                    ),
                    "export_generation_id": exported.generation_id,
                    "export_sha256": exported.export_sha256,
                    "export_artifact_raw_sha256": _sha256(export_raw),
                    "source_journal_record_count": (
                        exported.source_journal_record_count
                    ),
                    "source_journal_tip_record_hash": (
                        exported.source_journal_tip_record_hash
                    ),
                    "same_connection": True,
                    "readonly_principal_verified": True,
                    "endpoint_verified": True,
                    "observable_readonly_metadata_stable": True,
                    "query_v6_terminal_join_verified": True,
                    "journal_export_join_verified": True,
                    "select_statements_executed": 4,
                    "write_probe_attempted": False,
                    "database_mutations_observed": 0,
                    "orders_sent": 0,
                    "positions_modified": 0,
                    **_FALSE_AUTHORITY,
                }
                verified = CFastExecutionQualityQuestDBReadonlyEvidenceReceiptDTO.model_validate(
                    {**core, "receipt_sha256": _sha256(_canonical_json(core))}
                )
            except CFastExecutionQualityQuestDBReadonlyError as exc:
                self._block_locked(exc.code)
                raise
            except (OSError, TypeError, ValueError, ValidationError) as exc:
                self._block_locked("QUESTDB_READONLY_EVIDENCE_VERIFICATION_FAILED")
                raise CFastExecutionQualityQuestDBReadonlyError(
                    "QUESTDB_READONLY_EVIDENCE_VERIFICATION_FAILED"
                ) from exc
            finally:
                if connection is not None:
                    try:
                        connection.close()
                    except Exception:
                        pass
            self._receipt = verified
            self._generation += 1
            self._blocked = False
            self._last_error = None
            return verified

    def stop(self) -> None:
        with self._lock:
            self._receipt = None
            self._blocked = False
            self._last_error = None

    def status(self) -> dict[str, object]:
        with self._lock:
            receipt = self._receipt
            return {
                "schema_version": (
                    "commodity_c_fast_execution_quality_questdb_readonly_status_v1"
                ),
                "adapter_state": (
                    "BLOCKED_FAIL_CLOSED"
                    if self._blocked
                    else (
                        "VERIFIED_READONLY_EVIDENCE"
                        if receipt is not None
                        else "CREATED_NOT_VERIFIED"
                    )
                ),
                "blocked_fail_closed": self._blocked,
                "last_error": self._last_error,
                "verification_generation": self._generation,
                "receipt_sha256": (
                    receipt.receipt_sha256 if receipt is not None else None
                ),
                "revalidation_receipt_sha256": (
                    receipt.revalidation_receipt_sha256 if receipt is not None else None
                ),
                "source_journal_record_count": (
                    receipt.source_journal_record_count if receipt is not None else None
                ),
                "source_journal_tip_record_hash": (
                    receipt.source_journal_tip_record_hash
                    if receipt is not None
                    else None
                ),
                "export_sha256": (
                    receipt.export_sha256 if receipt is not None else None
                ),
                "query_v6_terminal_raw_sha256": (
                    receipt.query_v6_terminal_raw_sha256
                    if receipt is not None
                    else None
                ),
                "server_enforced_readonly_verified": receipt is not None,
                "dsn_secret_exposed": False,
                "write_probe_attempted": False,
                "database_mutations_observed": 0,
                "orders_sent": 0,
                "positions_modified": 0,
                **_FALSE_AUTHORITY,
            }

    def _load_exact_p0(
        self,
        receipt: CFastExecutionQualityRuntimeRevalidationDTO,
    ) -> CFastExecutionQualityP0AcceptanceV6DTO:
        raw = self._read_private_bytes(
            self._signed_p0_path,
            "SIGNED_P0_ACCEPTANCE",
            _MAX_P0_BYTES,
            self._expected_p0_owner_uid,
        )
        if not hmac.compare_digest(
            _sha256(raw),
            receipt.signed_p0_acceptance_sha256,
        ):
            raise CFastExecutionQualityQuestDBReadonlyError(
                "QUESTDB_READONLY_P0_RAW_MISMATCH"
            )
        payload = self._parse_json(raw, "SIGNED_P0_ACCEPTANCE")
        try:
            p0 = CFastExecutionQualityP0AcceptanceV6DTO.model_validate(payload)
        except ValidationError as exc:
            raise CFastExecutionQualityQuestDBReadonlyError(
                "QUESTDB_READONLY_P0_INVALID"
            ) from exc
        if p0.exact_contracts != receipt.exact_contracts:
            raise CFastExecutionQualityQuestDBReadonlyError(
                "QUESTDB_READONLY_P0_CONTRACT_MISMATCH"
            )
        return p0

    def _load_reference_readonly_proof(
        self,
        p0: CFastExecutionQualityP0AcceptanceV6DTO,
    ) -> dict[str, Any]:
        try:
            raw = base64.b64decode(
                p0.readonly_proof_exact_json_base64,
                validate=True,
            )
        except (ValueError, binascii.Error) as exc:
            raise CFastExecutionQualityQuestDBReadonlyError(
                "QUESTDB_READONLY_P0_PROOF_INVALID"
            ) from exc
        if not hmac.compare_digest(_sha256(raw), p0.readonly_proof_raw_sha256):
            raise CFastExecutionQualityQuestDBReadonlyError(
                "QUESTDB_READONLY_P0_PROOF_RAW_MISMATCH"
            )
        proof = self._parse_json(raw, "QUERY_V6_READONLY_PROOF")
        required = {
            "endpoint_identity_sha256",
            "preflight",
            "postflight",
            "write_probe_attempted",
            "database_mutations",
        }
        if (
            not required.issubset(proof)
            or proof["preflight"] != proof["postflight"]
            or proof["write_probe_attempted"] is not False
            or proof["database_mutations"] != 0
        ):
            raise CFastExecutionQualityQuestDBReadonlyError(
                "QUESTDB_READONLY_P0_PROOF_SEMANTICS_INVALID"
            )
        return proof

    @staticmethod
    def _verify_journal_export_join(
        *,
        receipt: CFastExecutionQualityRuntimeRevalidationDTO,
        repository_status: Mapping[str, object],
        exported: CFastExecutionQualityEvidenceExportDTO,
    ) -> None:
        if (
            repository_status.get("blocked_fail_closed") is not False
            or repository_status.get("source_journal_record_count")
            != exported.source_journal_record_count
            or repository_status.get("source_journal_tip_record_hash")
            != exported.source_journal_tip_record_hash
            or tuple(repository_status.get("exact_contracts") or ())
            != receipt.exact_contracts
            or exported.exact_contracts != receipt.exact_contracts
        ):
            raise CFastExecutionQualityQuestDBReadonlyError(
                "QUESTDB_READONLY_JOURNAL_EXPORT_JOIN_MISMATCH"
            )

    def _read_private_text(self, path: Path, label: str, limit: int) -> str:
        raw = self._read_private_bytes(
            path,
            label,
            limit,
            self._expected_dsn_owner_uid,
        )
        try:
            value = raw.decode("utf-8").strip()
        except UnicodeDecodeError as exc:
            raise CFastExecutionQualityQuestDBReadonlyError(f"{label}_INVALID") from exc
        if not value or "\x00" in value:
            raise CFastExecutionQualityQuestDBReadonlyError(f"{label}_INVALID")
        return value

    def _read_private_bytes(
        self,
        path: Path,
        label: str,
        limit: int,
        expected_owner_uid: int,
    ) -> bytes:
        descriptor: int | None = None
        try:
            before_path = path.lstat()
            if (
                not path.is_absolute()
                or stat.S_ISLNK(before_path.st_mode)
                or not stat.S_ISREG(before_path.st_mode)
                or before_path.st_uid != expected_owner_uid
                or stat.S_IMODE(before_path.st_mode) != 0o600
                or before_path.st_nlink != 1
                or not 0 < before_path.st_size <= limit
            ):
                raise ValueError
            descriptor = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            before_fd = os.fstat(descriptor)
            first = self._read_bounded(descriptor, limit)
            os.lseek(descriptor, 0, os.SEEK_SET)
            second = self._read_bounded(descriptor, limit)
            after_fd = os.fstat(descriptor)
            after_path = path.lstat()
        except (OSError, ValueError) as exc:
            raise CFastExecutionQualityQuestDBReadonlyError(
                f"{label}_CUSTODY_INVALID"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
        identities = tuple(
            self._file_identity(value)
            for value in (before_path, before_fd, after_fd, after_path)
        )
        if len(set(identities)) != 1 or first != second:
            raise CFastExecutionQualityQuestDBReadonlyError(
                f"{label}_CHANGED_DURING_READ"
            )
        return first

    @staticmethod
    def _read_bounded(descriptor: int, limit: int) -> bytes:
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > limit:
            raise ValueError
        return raw

    @staticmethod
    def _file_identity(value: os.stat_result) -> tuple[int, ...]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_size,
            stat.S_IFMT(value.st_mode),
            value.st_uid,
            stat.S_IMODE(value.st_mode),
            value.st_nlink,
        )

    @staticmethod
    def _parse_json(raw: bytes, label: str) -> dict[str, Any]:
        def reject_duplicates(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate key")
                result[key] = value
            return result

        try:
            value = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=reject_duplicates,
                parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise CFastExecutionQualityQuestDBReadonlyError(
                f"{label}_JSON_INVALID"
            ) from exc
        if not isinstance(value, dict):
            raise CFastExecutionQualityQuestDBReadonlyError(f"{label}_JSON_INVALID")
        return value

    @staticmethod
    def _fetch_all(cursor: Any) -> list[tuple[Any, ...]]:
        fetchall = getattr(cursor, "fetchall", None)
        if callable(fetchall):
            return list(fetchall())
        rows = []
        while True:
            batch = cursor.fetchmany(1024)
            if not batch:
                return rows
            rows.extend(batch)

    def _collect_snapshot(
        self,
        connection: ReadonlyQuestDBConnection,
    ) -> _ReadonlySnapshot:
        try:
            identity_rows = self._fetch_all(connection.execute(_READONLY_IDENTITY_SQL))
            parameter_rows = self._fetch_all(
                connection.execute(_READONLY_PARAMETERS_SQL)
            )
        except Exception as exc:
            raise CFastExecutionQualityQuestDBReadonlyError(
                "QUESTDB_READONLY_METADATA_QUERY_FAILED"
            ) from exc
        if len(identity_rows) != 1 or len(identity_rows[0]) < 2:
            raise CFastExecutionQualityQuestDBReadonlyError(
                "QUESTDB_READONLY_IDENTITY_INVALID"
            )
        principal = str(identity_rows[0][0] or "").strip()
        build = str(identity_rows[0][1] or "").strip()
        parameters: dict[str, tuple[Any, str, bool]] = {}
        for row in parameter_rows:
            if len(row) < 6:
                raise CFastExecutionQualityQuestDBReadonlyError(
                    "QUESTDB_READONLY_PARAMETER_ROW_INVALID"
                )
            key = str(row[0] or "").strip()
            if key not in _READONLY_PARAMETER_KEYS or key in parameters:
                raise CFastExecutionQualityQuestDBReadonlyError(
                    "QUESTDB_READONLY_PARAMETER_SET_INVALID"
                )
            parameters[key] = (
                row[2],
                str(row[3] or "").strip(),
                self._questdb_bool(row[4], f"{key}.sensitive"),
            )
        if set(parameters) != set(_READONLY_PARAMETER_KEYS):
            raise CFastExecutionQualityQuestDBReadonlyError(
                "QUESTDB_READONLY_PARAMETER_SET_INVALID"
            )
        readonly_user = str(parameters["pg.readonly.user"][0] or "").strip()
        admin_user = str(parameters["pg.user"][0] or "").strip()
        if (
            not principal
            or not build
            or not readonly_user
            or not admin_user
            or principal != readonly_user
            or principal == admin_user
            or not self._questdb_bool(
                parameters["pg.readonly.user.enabled"][0],
                "pg.readonly.user.enabled",
            )
            or self._questdb_bool(
                parameters["pg.security.readonly"][0],
                "pg.security.readonly",
            )
            or self._questdb_bool(parameters["readonly"][0], "readonly")
            or parameters["pg.readonly.password"][2] is not True
            or parameters["pg.readonly.password"][1] not in {"conf", "env", "file"}
            or any(not item[1] for item in parameters.values())
        ):
            raise CFastExecutionQualityQuestDBReadonlyError(
                "QUESTDB_READONLY_SERVER_ENFORCEMENT_INVALID"
            )
        evidence = {
            "questdb_build": build,
            "readonly_user_enabled": True,
            "principal_matches_readonly_user": True,
            "principal_differs_admin": True,
            "global_pgwire_readonly": False,
            "instance_readonly": False,
            "configuration_sources": {
                key: parameters[key][1] for key in _READONLY_PARAMETER_KEYS
            },
        }
        return _ReadonlySnapshot(
            principal=principal,
            readonly_user=readonly_user,
            admin_user=admin_user,
            questdb_build=build,
            evidence=evidence,
        )

    @staticmethod
    def _questdb_bool(value: Any, label: str) -> bool:
        normalized = str(value).strip().lower()
        if normalized == "true":
            return True
        if normalized == "false":
            return False
        raise CFastExecutionQualityQuestDBReadonlyError(
            f"QUESTDB_READONLY_BOOLEAN_INVALID:{label}"
        )

    @staticmethod
    def _endpoint_identity_sha256(
        connection: ReadonlyQuestDBConnection,
    ) -> str:
        try:
            host = str(connection.info.host or "").strip()
            port = int(connection.info.port)
            dbname = str(connection.info.dbname or "").strip()
        except (AttributeError, TypeError, ValueError) as exc:
            raise CFastExecutionQualityQuestDBReadonlyError(
                "QUESTDB_READONLY_ENDPOINT_INVALID"
            ) from exc
        if not host or not dbname or not 1 <= port <= 65_535:
            raise CFastExecutionQualityQuestDBReadonlyError(
                "QUESTDB_READONLY_ENDPOINT_INVALID"
            )
        return _sha256(_canonical_json({"dbname": dbname, "host": host, "port": port}))

    def _utc_now(self) -> datetime:
        value = self._clock()
        if (
            value.tzinfo is None
            or value.utcoffset() is None
            or value.utcoffset().total_seconds() != 0
        ):
            raise CFastExecutionQualityQuestDBReadonlyError(
                "QUESTDB_READONLY_CLOCK_INVALID"
            )
        return value

    def _block_locked(self, code: str) -> None:
        self._receipt = None
        self._blocked = True
        self._last_error = code


__all__ = [
    "CFastExecutionQualityQuestDBReadonlyError",
    "CommodityCFastExecutionQualityQuestDBReadonlyEvidenceAdapter",
    "ReadonlyConnectionFactory",
]
