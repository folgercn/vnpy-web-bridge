"""Offline MAP signal producer.

This module is deliberately a small batch boundary around the frozen pure
research kernel.  It accepts one explicitly approved, immutable source
envelope and emits one unsigned MAP signal candidate.  The candidate is a
content-addressed canonical JSON value; it is not a signing request and does
not grant any runtime authority.

The producer has no service lifecycle.  ``health`` and ``ready`` are CLI
probes for a batch scheduler, while ``produce`` reads an explicitly named
file and creates an explicitly named output.  There is intentionally no
directory scanning or implicit "current"/"latest" selection.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import math
import os
import stat
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:  # Repository execution has scripts/ on PYTHONPATH in existing tests.
    import commodity_c_fast_pure_producer_kernel as kernel
except ModuleNotFoundError:  # pragma: no cover - exercised by -m scripts.map
    _SCRIPTS = Path(__file__).resolve().parents[1]
    if str(_SCRIPTS) not in sys.path:
        sys.path.insert(0, str(_SCRIPTS))
    import commodity_c_fast_pure_producer_kernel as kernel


MAP_CANDIDATE_SCHEMA = "commodity_map_signal_candidate_v1"
MAP_CANDIDATE_ROLE = "unsigned_map_signal_candidate"
MAP_STATUS = "UNSIGNED_MAP_SIGNAL_CANDIDATE"
MAP_PRODUCER_IDENTITY = "map-producer"
MAP_PRODUCER_VERSION = "map-producer-v1"
MAP_STRATEGY_IDENTITY = "commodity_fast_tsmom_forward_freeze_v1"
MAP_SOURCE_ENVELOPE_SCHEMA = "commodity_approved_research_source_v1"
MAP_SOURCE_ENVELOPE_ROLE = "approved_research_source"
MAP_SOURCE_ENVELOPE_STATUS = "APPROVED_IMMUTABLE_SOURCE"
MAP_OUTPUT_CONTRACT_SCHEMA = "commodity_map_to_c_fast_projection_contract_v1"
MAX_INPUT_BYTES = 16 * 1024 * 1024

_MAP_OUTPUT_FIELDS = (
    "product",
    "sector",
    "trend_21_sign",
    "trend_63_sign",
    "trend_126_sign",
    "source_score",
    "vol60_annualized",
    "raw_risk_score",
    "source_target_weight",
)
_AUTHORITY_FIELDS = tuple(kernel.FALSE_AUTHORITY_FIELDS) + (
    "production_allowed",
    "live_allowed",
    "countable_forward",
    "authority_granted",
    "signing_requested",
    "custody_published",
)
_SOURCE_ENVELOPE_KEYS = frozenset(
    {
        "schema_version",
        "artifact_role",
        "status",
        "source_view",
        "source_view_canonical_sha256",
        "source_receipt_sha256",
        "approval",
    }
)
_APPROVAL_KEYS = frozenset(
    {"approved", "immutable", "receipt_verified", "custody_verified", "lineage_verified"}
)


class ProducerError(ValueError):
    """Fail-closed producer input, contract or file error."""


@dataclass(frozen=True)
class MapCandidateResult:
    """Canonical MAP candidate and the source hash it is bound to."""

    raw: bytes
    payload: Mapping[str, Any]
    artifact_sha256: str
    source_view_canonical_sha256: str


def canonical_json(payload: Any) -> bytes:
    """Serialize finite JSON with the one canonical representation."""

    try:
        return json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProducerError("payload is not finite canonical JSON") from exc


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reject_constant(value: str) -> None:
    raise ProducerError(f"JSON constant {value!r} is forbidden")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProducerError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _decode_json(raw: bytes, label: str) -> dict[str, Any]:
    if len(raw) > MAX_INPUT_BYTES:
        raise ProducerError(f"{label} exceeds input byte limit")
    try:
        decoded = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProducerError(f"{label} is not strict JSON") from exc
    if not isinstance(decoded, dict):
        raise ProducerError(f"{label} root must be an object")
    if canonical_json(decoded) != raw:
        raise ProducerError(f"{label} must already be canonical JSON")
    return decoded


def _exact_keys(value: Any, expected: Iterable[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProducerError(f"{label} must be an object")
    expected_set = set(expected)
    actual = set(value)
    if actual != expected_set:
        missing = sorted(expected_set - actual)
        extra = sorted(actual - expected_set)
        raise ProducerError(f"{label} field set mismatch missing={missing} extra={extra}")
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ProducerError(f"{label} must be a lowercase SHA-256")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ProducerError(f"{label} must be a lowercase SHA-256") from exc
    if value != value.lower():
        raise ProducerError(f"{label} must be lowercase")
    return value


def _finite(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProducerError(f"{label} must be a finite number")
    result = float(value)
    if not math.isfinite(result):
        raise ProducerError(f"{label} must be a finite number")
    return result


def _module_sha256(module: Any) -> str:
    path = getattr(module, "__file__", None)
    if not isinstance(path, str):
        raise ProducerError("producer kernel source identity is unavailable")
    try:
        return _sha256(Path(path).read_bytes())
    except OSError as exc:
        raise ProducerError("producer kernel source identity cannot be read") from exc


def _producer_sha256() -> str:
    try:
        return _sha256(Path(__file__).read_bytes())
    except OSError as exc:
        raise ProducerError("MAP producer source identity cannot be read") from exc


def _map_output_contract() -> dict[str, Any]:
    return {
        "schema_version": MAP_OUTPUT_CONTRACT_SCHEMA,
        "strategy_identity_field": "strategy_identity",
        "product_fields": list(_MAP_OUTPUT_FIELDS),
        "complete_product_set_required": True,
        "execution_fields_forbidden": True,
    }


def map_output_contract_sha256() -> str:
    return _sha256(canonical_json(_map_output_contract()))


def approved_source_envelope(
    source_view: Mapping[str, Any] | bytes | bytearray,
    *,
    receipt_sha256: str | None = None,
) -> dict[str, Any]:
    """Normalize a typed source view into the producer's approval envelope.

    Upstream custody is responsible for the real receipt; this helper only
    carries the already verified facts into an isolated batch.  The producer
    never treats a claim as runtime authority.
    """

    if isinstance(source_view, (bytes, bytearray)):
        raw = bytes(source_view)
        try:
            source = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProducerError("typed source is not strict JSON") from exc
    elif isinstance(source_view, Mapping):
        source = dict(source_view)
    else:
        raise ProducerError("typed source must be a mapping or JSON bytes")
    try:
        bounded = kernel._bounded_source_view_input(source)
        normalized, _bindings, _days = kernel._validate_and_normalize_source_view(bounded)
    except Exception as exc:
        if isinstance(exc, ProducerError):
            raise
        raise ProducerError("typed source failed frozen source validation") from exc
    source_raw = kernel.canonical_json(normalized)
    source_hash = _sha256(source_raw)
    claim = receipt_sha256 or str(normalized["claimed_receipt_sha256"])
    _sha(claim, "source_receipt_sha256")
    return {
        "schema_version": MAP_SOURCE_ENVELOPE_SCHEMA,
        "artifact_role": MAP_SOURCE_ENVELOPE_ROLE,
        "status": MAP_SOURCE_ENVELOPE_STATUS,
        "source_view": normalized,
        "source_view_canonical_sha256": source_hash,
        "source_receipt_sha256": claim,
        "approval": {
            "approved": True,
            "immutable": True,
            "receipt_verified": True,
            "custody_verified": True,
            "lineage_verified": True,
        },
    }


def _prepare_source(source_input: Mapping[str, Any] | bytes | bytearray) -> tuple[dict[str, Any], str, str]:
    if isinstance(source_input, (bytes, bytearray)):
        envelope = _decode_json(bytes(source_input), "source envelope")
    elif isinstance(source_input, Mapping):
        envelope = dict(source_input)
    else:
        raise ProducerError("source input must be an approved envelope")
    _exact_keys(envelope, _SOURCE_ENVELOPE_KEYS, "source envelope")
    if envelope["schema_version"] != MAP_SOURCE_ENVELOPE_SCHEMA:
        raise ProducerError("source envelope schema is not approved")
    if envelope["artifact_role"] != MAP_SOURCE_ENVELOPE_ROLE:
        raise ProducerError("source envelope role is not approved")
    if envelope["status"] != MAP_SOURCE_ENVELOPE_STATUS:
        raise ProducerError("source envelope is not approved")
    approval = _exact_keys(envelope["approval"], _APPROVAL_KEYS, "source approval")
    if any(approval[field] is not True for field in _APPROVAL_KEYS):
        raise ProducerError("source approval facts are not all true")
    if not isinstance(envelope["source_view"], Mapping):
        raise ProducerError("source envelope source_view must be an object")
    try:
        bounded = kernel._bounded_source_view_input(envelope["source_view"])
        normalized, _bindings, _days = kernel._validate_and_normalize_source_view(bounded)
    except Exception as exc:
        raise ProducerError("approved source failed frozen validation") from exc
    source_raw = kernel.canonical_json(normalized)
    source_hash = _sha256(source_raw)
    if _sha(envelope["source_view_canonical_sha256"], "source_view_canonical_sha256") != source_hash:
        raise ProducerError("source canonical hash mismatch")
    _sha(envelope["source_receipt_sha256"], "source_receipt_sha256")
    # Normalize the nested view too: accepting alternate JSON spellings would
    # permit two byte identities for one predecessor.
    if canonical_json(envelope["source_view"]) != source_raw:
        raise ProducerError("source view is not normalized canonical JSON")
    return normalized, source_hash, str(envelope["source_receipt_sha256"])


def _candidate_id(source_hash: str) -> str:
    return "map-signal-v1-" + _sha256(
        canonical_json(
            {
                "producer_identity": MAP_PRODUCER_IDENTITY,
                "producer_version": MAP_PRODUCER_VERSION,
                "strategy_identity": MAP_STRATEGY_IDENTITY,
                "source_view_canonical_sha256": source_hash,
            }
        )
    )


def _false_authority_fields(payload: dict[str, Any]) -> None:
    for field in _AUTHORITY_FIELDS:
        payload[field] = False


def _build_candidate(source: Mapping[str, Any], source_hash: str, receipt_hash: str) -> dict[str, Any]:
    products = {row["product"]: row for row in source["products"]}
    signals: dict[str, dict[str, Any]] = {}
    for product in kernel.PRODUCTS:
        signal, _roll = kernel._build_product_signal(products[product])
        signals[product] = signal
    raw_scores = {product: float(signals[product]["raw_risk_score"]) for product in kernel.PRODUCTS}
    source_weights = kernel._cap_source_weights(raw_scores)
    lineage = dict(kernel.LINEAGE)
    lineage_sha = _sha256(canonical_json(lineage))
    producer_identity = {
        "producer_id": MAP_PRODUCER_IDENTITY,
        "producer_version": MAP_PRODUCER_VERSION,
        "producer_code_sha256": _producer_sha256(),
        "kernel_id": kernel.KERNEL_ID,
        "kernel_code_sha256": _module_sha256(kernel),
    }
    rows = []
    for product in kernel.PRODUCTS:
        signal = signals[product]
        rows.append(
            {
                "product": product,
                "sector": kernel.SECTOR_MAP[product],
                "trend_21_sign": signal["trend_21_sign"],
                "trend_63_sign": signal["trend_63_sign"],
                "trend_126_sign": signal["trend_126_sign"],
                "source_score": signal["source_score"],
                "vol60_annualized": signal["vol60_annualized"],
                "raw_risk_score": signal["raw_risk_score"],
                "source_target_weight": source_weights[product],
            }
        )
    payload: dict[str, Any] = {
        "schema_version": MAP_CANDIDATE_SCHEMA,
        "artifact_role": MAP_CANDIDATE_ROLE,
        "status": MAP_STATUS,
        "candidate_id": _candidate_id(source_hash),
        "producer_identity": producer_identity,
        "strategy_identity": MAP_STRATEGY_IDENTITY,
        "strategy_model_version_sha256": kernel.FROZEN_RULE_SHA256,
        "map_output_contract": {
            **_map_output_contract(),
            "contract_sha256": map_output_contract_sha256(),
        },
        "source": {
            "schema_version": kernel.SOURCE_SCHEMA_VERSION,
            "source_view_id": source["source_view_id"],
            "source_view_canonical_sha256": source_hash,
            "source_receipt_sha256": receipt_hash,
            "research_as_of_official_day": source["research_as_of_official_day"],
            "execution_day": source["execution_day"],
        },
        "lineage": {
            "source_view_canonical_sha256": source_hash,
            "source_receipt_sha256": receipt_hash,
            "lineage_sha256": lineage_sha,
            "frozen_lineage": lineage,
        },
        "signals": rows,
        "research_evidence_only": True,
        "producer_identity_only": True,
    }
    _false_authority_fields(payload)
    return payload


def produce_map_candidate(source_input: Mapping[str, Any] | bytes | bytearray) -> MapCandidateResult:
    """Produce one deterministic unsigned MAP signal candidate."""

    source, source_hash, receipt_hash = _prepare_source(source_input)
    payload = _build_candidate(source, source_hash, receipt_hash)
    raw = canonical_json(payload)
    return MapCandidateResult(
        raw=raw,
        payload=payload,
        artifact_sha256=_sha256(raw),
        source_view_canonical_sha256=source_hash,
    )


def _validate_candidate_shape(payload: Mapping[str, Any]) -> None:
    expected = {
        "schema_version",
        "artifact_role",
        "status",
        "candidate_id",
        "producer_identity",
        "strategy_identity",
        "strategy_model_version_sha256",
        "map_output_contract",
        "source",
        "lineage",
        "signals",
        "research_evidence_only",
        "producer_identity_only",
        *_AUTHORITY_FIELDS,
    }
    _exact_keys(payload, expected, "MAP candidate")
    if payload["schema_version"] != MAP_CANDIDATE_SCHEMA or payload["artifact_role"] != MAP_CANDIDATE_ROLE:
        raise ProducerError("MAP candidate schema/role mismatch")
    if payload["status"] != MAP_STATUS:
        raise ProducerError("MAP candidate status is not unsigned")
    if payload["strategy_identity"] != MAP_STRATEGY_IDENTITY:
        raise ProducerError("MAP strategy identity mismatch")
    if payload["strategy_model_version_sha256"] != kernel.FROZEN_RULE_SHA256:
        raise ProducerError("MAP strategy model hash mismatch")
    if payload["research_evidence_only"] is not True or payload["producer_identity_only"] is not True:
        raise ProducerError("MAP candidate must remain research-only")
    if any(payload[field] is not False for field in _AUTHORITY_FIELDS):
        raise ProducerError("MAP candidate contains authority")
    identity = _exact_keys(
        payload["producer_identity"],
        {"producer_id", "producer_version", "producer_code_sha256", "kernel_id", "kernel_code_sha256"},
        "MAP producer identity",
    )
    if identity["producer_id"] != MAP_PRODUCER_IDENTITY or identity["producer_version"] != MAP_PRODUCER_VERSION:
        raise ProducerError("MAP producer identity mismatch")
    _sha(identity["producer_code_sha256"], "producer_code_sha256")
    _sha(identity["kernel_code_sha256"], "kernel_code_sha256")
    if identity["kernel_id"] != kernel.KERNEL_ID:
        raise ProducerError("MAP kernel identity mismatch")
    contract = _exact_keys(
        payload["map_output_contract"],
        {"schema_version", "strategy_identity_field", "product_fields", "complete_product_set_required", "execution_fields_forbidden", "contract_sha256"},
        "MAP output contract",
    )
    if contract["schema_version"] != MAP_OUTPUT_CONTRACT_SCHEMA or contract["contract_sha256"] != map_output_contract_sha256():
        raise ProducerError("MAP output contract identity mismatch")
    if contract["product_fields"] != list(_MAP_OUTPUT_FIELDS) or contract["complete_product_set_required"] is not True or contract["execution_fields_forbidden"] is not True:
        raise ProducerError("MAP output contract fields mismatch")
    source = _exact_keys(
        payload["source"],
        {"schema_version", "source_view_id", "source_view_canonical_sha256", "source_receipt_sha256", "research_as_of_official_day", "execution_day"},
        "MAP source binding",
    )
    if source["schema_version"] != kernel.SOURCE_SCHEMA_VERSION:
        raise ProducerError("MAP source schema mismatch")
    _sha(source["source_view_canonical_sha256"], "MAP source hash")
    _sha(source["source_receipt_sha256"], "MAP source receipt hash")
    lineage = _exact_keys(
        payload["lineage"],
        {"source_view_canonical_sha256", "source_receipt_sha256", "lineage_sha256", "frozen_lineage"},
        "MAP lineage",
    )
    if lineage["source_view_canonical_sha256"] != source["source_view_canonical_sha256"] or lineage["source_receipt_sha256"] != source["source_receipt_sha256"]:
        raise ProducerError("MAP lineage source mismatch")
    if lineage["lineage_sha256"] != _sha256(canonical_json(lineage["frozen_lineage"])):
        raise ProducerError("MAP lineage hash mismatch")
    if lineage["frozen_lineage"] != dict(kernel.LINEAGE):
        raise ProducerError("MAP frozen lineage mismatch")
    signals = payload["signals"]
    if not isinstance(signals, list) or [row.get("product") for row in signals if isinstance(row, dict)] != list(kernel.PRODUCTS):
        raise ProducerError("MAP signal product set/order mismatch")
    for index, row in enumerate(signals):
        signal = _exact_keys(row, set(_MAP_OUTPUT_FIELDS), f"MAP signal[{index}]")
        if signal["product"] != kernel.PRODUCTS[index] or signal["sector"] != kernel.SECTOR_MAP[signal["product"]]:
            raise ProducerError("MAP signal product/sector mismatch")
        for field in ("source_score", "vol60_annualized", "raw_risk_score", "source_target_weight"):
            _finite(signal[field], f"MAP signal {field}")
        if not isinstance(signal["trend_21_sign"], int) or signal["trend_21_sign"] not in {-1, 0, 1}:
            raise ProducerError("MAP trend sign is invalid")
        if not isinstance(signal["trend_63_sign"], int) or signal["trend_63_sign"] not in {-1, 0, 1}:
            raise ProducerError("MAP trend sign is invalid")
        if not isinstance(signal["trend_126_sign"], int) or signal["trend_126_sign"] not in {-1, 0, 1}:
            raise ProducerError("MAP trend sign is invalid")


def verify_map_candidate(
    candidate_input: Mapping[str, Any] | bytes | bytearray,
    *,
    source_input: Mapping[str, Any] | bytes | bytearray | None = None,
    expected_source_sha256: str | None = None,
    rejected_candidate_sha256: Iterable[str] = (),
) -> MapCandidateResult:
    """Verify canonical identity, lineage and optional source replay.

    ``rejected_candidate_sha256`` is the custody/high-water boundary supplied
    by the caller.  A pure producer cannot invent durable replay state, so it
    refuses hashes already known to be consumed instead of guessing.
    """

    if isinstance(candidate_input, (bytes, bytearray)):
        raw = bytes(candidate_input)
        payload = _decode_json(raw, "MAP candidate")
    elif isinstance(candidate_input, Mapping):
        payload = dict(candidate_input)
        raw = canonical_json(payload)
    else:
        raise ProducerError("MAP candidate must be canonical JSON")
    _validate_candidate_shape(payload)
    artifact_hash = _sha256(raw)
    rejected = {_sha(value, "rejected candidate hash") for value in rejected_candidate_sha256}
    if artifact_hash in rejected or payload["candidate_id"] in rejected:
        raise ProducerError("MAP candidate replay is rejected by high-water input")
    source = payload["source"]
    if expected_source_sha256 is not None and source["source_view_canonical_sha256"] != _sha(expected_source_sha256, "expected source hash"):
        raise ProducerError("MAP source predecessor mismatch")
    if source_input is not None:
        normalized, source_hash, receipt_hash = _prepare_source(source_input)
        expected = _build_candidate(normalized, source_hash, receipt_hash)
        expected_raw = canonical_json(expected)
        if expected_raw != raw:
            raise ProducerError("MAP candidate failed source replay or was tampered")
    return MapCandidateResult(
        raw=raw,
        payload=payload,
        artifact_sha256=artifact_hash,
        source_view_canonical_sha256=source["source_view_canonical_sha256"],
    )


def _reject_path_latest(path: Path) -> None:
    if any(part.casefold() == "latest" for part in path.parts):
        raise ProducerError("implicit latest paths are forbidden")


def _read_pinned_file(path: Path) -> bytes:
    _reject_path_latest(path)
    try:
        before = path.lstat()
    except OSError as exc:
        raise ProducerError("input file cannot be stat-ed") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ProducerError("input must be a regular non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ProducerError("input file cannot be opened safely") from exc
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise ProducerError("input changed before read")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, MAX_INPUT_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_INPUT_BYTES:
                raise ProducerError("input exceeds byte limit")
        after = os.fstat(fd)
        current = path.lstat()
        if (after.st_dev, after.st_ino, after.st_size) != (opened.st_dev, opened.st_ino, opened.st_size) or (current.st_dev, current.st_ino, current.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise ProducerError("input changed during read")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _create_only_atomic(path: Path, raw: bytes) -> None:
    _reject_path_latest(path)
    parent = path.parent
    try:
        parent_stat = parent.lstat()
    except OSError as exc:
        raise ProducerError("output parent cannot be stat-ed") from exc
    if stat.S_ISLNK(parent_stat.st_mode) or not stat.S_ISDIR(parent_stat.st_mode):
        raise ProducerError("output parent must be a real directory")
    if path.exists() or path.is_symlink():
        raise ProducerError("output already exists; overwrite is forbidden")
    temporary = parent / f".{path.name}.{os.getpid()}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = -1
    try:
        fd = os.open(temporary, flags, 0o600)
        written = 0
        while written < len(raw):
            written += os.write(fd, raw[written:])
        os.fsync(fd)
        os.close(fd)
        fd = -1
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise ProducerError("output already exists; overwrite is forbidden") from exc
        directory_fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        if exc.errno == errno.EEXIST:
            raise ProducerError("output already exists; overwrite is forbidden") from exc
        raise ProducerError("atomic candidate publish failed") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _cli_json(payload: Mapping[str, Any]) -> None:
    sys.stdout.buffer.write(canonical_json(dict(payload)) + b"\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="offline MAP signal producer")
    parser.add_argument("--version", action="version", version=f"{MAP_PRODUCER_IDENTITY} {MAP_PRODUCER_VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("health", help="print liveness for the batch image")
    sub.add_parser("ready", help="print readiness for the batch image")
    produce = sub.add_parser("produce", help="create one unsigned MAP candidate")
    produce.add_argument("--source", required=True, type=Path)
    produce.add_argument("--output", required=True, type=Path)
    produce.add_argument("--expected-source-sha256")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "health":
            _cli_json({"status": "ok", "producer_identity": MAP_PRODUCER_IDENTITY, "version": MAP_PRODUCER_VERSION})
            return 0
        if args.command == "ready":
            _module_sha256(kernel)
            _producer_sha256()
            _cli_json({"status": "ready", "producer_identity": MAP_PRODUCER_IDENTITY, "version": MAP_PRODUCER_VERSION})
            return 0
        source_raw = _read_pinned_file(args.source)
        result = produce_map_candidate(source_raw)
        if args.expected_source_sha256 is not None and result.source_view_canonical_sha256 != _sha(args.expected_source_sha256, "expected source hash"):
            raise ProducerError("source predecessor mismatch")
        _create_only_atomic(args.output, result.raw)
        _cli_json({"status": "created", "producer_identity": MAP_PRODUCER_IDENTITY, "version": MAP_PRODUCER_VERSION, "candidate_id": result.payload["candidate_id"], "artifact_sha256": result.artifact_sha256, "source_view_canonical_sha256": result.source_view_canonical_sha256})
        return 0
    except ProducerError as exc:
        _cli_json({"status": "not_ready", "producer_identity": MAP_PRODUCER_IDENTITY, "error": str(exc)})
        return 2


if __name__ == "__main__":  # pragma: no cover - exercised by image smoke
    raise SystemExit(main())
