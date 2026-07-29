"""Idempotent exact-byte official-data acquisition orchestration."""

from __future__ import annotations

import os
from datetime import date, datetime, timezone

from .absence_receipts import create_absence_receipt
from .acquisition_models import AcquiredObject, AuthoritativeAbsence
from .calendar_models import OfficialCalendar
from .clock_quality import TrustedClockSample, validate_observation_clock
from .errors import RegistryError
from .file_integrity import fsync_dir
from .filesystem import (
    WarehousePaths,
    create_download_temp,
    custody_lock,
    publish_temp_create_only,
    read_regular_strict,
    recover_atomic_publishes,
    stream_to_fd,
)
from .observations import create_observation
from .policy import render_endpoint, validate_redirect
from .registry import SourceRegistry
from .source_availability import classify_http_status
from .timeutil import parse_utc, require_utc
from .transport import Transport, UrllibTransport
from .validation import validate_source_bytes

CAPTURED_HTTP_HEADERS = (
    "content-length",
    "content-type",
    "etag",
    "last-modified",
)


def acquire_daily(
    *,
    paths: WarehousePaths,
    registry: SourceRegistry,
    source_id: str,
    trade_day: str,
    collector_version: str,
    observed_at: datetime | None = None,
    transport: Transport | None = None,
    timeout_seconds: float = 30.0,
    calendar: OfficialCalendar | None = None,
    clock_sample: TrustedClockSample | None = None,
) -> AcquiredObject | AuthoritativeAbsence:
    try:
        source = registry.source(source_id)
    except KeyError as exc:
        raise RegistryError(f"source is not in audited registry: {source_id}") from exc
    try:
        parsed_day = date.fromisoformat(trade_day)
    except ValueError as exc:
        raise RegistryError("trade_day must be canonical YYYY-MM-DD") from exc
    if parsed_day.isoformat() != trade_day:
        raise RegistryError("trade_day must be canonical YYYY-MM-DD")
    compact_day = trade_day.replace("-", "")
    endpoint = render_endpoint(source.endpoint_template, compact_day)
    observed = require_utc(
        observed_at or datetime.now(timezone.utc), "observed_at"
    )
    if calendar is not None:
        if clock_sample is None:
            raise RegistryError(
                "calendar-aware acquisition requires trusted NTP clock evidence"
            )
        validate_observation_clock(observed, sample=clock_sample)
    client = transport or UrllibTransport()
    descriptor, temp_path = create_download_temp(paths)
    try:
        with client.open(
            endpoint,
            allowed_hosts=source.allowed_hosts,
            accept=source.media_type,
            user_agent=f"vnpy-research-warehouse/{collector_version}",
            timeout_seconds=timeout_seconds,
        ) as response:
            validate_redirect(response.final_url, source.allowed_hosts)
            if calendar is None and response.status != 200:
                raise RegistryError(
                    f"official source returned unexpected HTTP {response.status}"
                )
            if calendar is not None:
                availability = classify_http_status(
                    calendar=calendar,
                    exchange=source.exchange,
                    requested_day=parsed_day,
                    status=response.status,
                )
                if response.status == 404:
                    os.close(descriptor)
                    descriptor = -1
                    temp_path.unlink()
                    fsync_dir(paths.temporary)
                    absence_id, receipt_path = create_absence_receipt(
                        paths=paths,
                        source_id=source.source_id,
                        exchange=source.exchange,
                        trade_day=trade_day,
                        source_url=response.final_url,
                        observed_at=observed,
                        calendar_raw_sha256=calendar.raw_sha256,
                        collector_version=collector_version,
                    )
                    return AuthoritativeAbsence(
                        absence_id=absence_id,
                        receipt_path=receipt_path,
                        source_id=source.source_id,
                        exchange=source.exchange,
                        trade_day=trade_day,
                        observed_at=observed,
                        http_status=404,
                        calendar_raw_sha256=calendar.raw_sha256,
                        status=availability,
                    )
            expected_length = response.headers.get("content-length")
            if expected_length is not None:
                try:
                    parsed_length = int(expected_length)
                except ValueError as exc:
                    raise RegistryError("invalid HTTP content-length") from exc
                if parsed_length < 0:
                    raise RegistryError("invalid HTTP content-length")
            else:
                parsed_length = None
            raw_bytes, raw_sha256 = stream_to_fd(descriptor, response.chunks)
            if parsed_length is not None and raw_bytes != parsed_length:
                raise RegistryError("partial download: content-length mismatch")
            os.close(descriptor)
            descriptor = -1
            raw = read_regular_strict(temp_path, "completed temporary raw object")
            validate_source_bytes(raw, source, trade_day)
            raw_parent = paths.private_subdir(
                paths.raw,
                source.exchange.lower(),
                trade_day,
                source.source_id,
            )
            raw_path = raw_parent / f"{raw_sha256}.raw"
            lock_key = f"{source.exchange.lower()}-{trade_day}-{source.source_id}"
            with custody_lock(paths, lock_key):
                with custody_lock(paths, "raw-publish"):
                    recover_atomic_publishes(
                        temporary_dir=paths.temporary,
                        final_root=paths.raw,
                        temporary_name_prefix=".download-",
                        final_name_glob="*.raw",
                        remove_unlinked=False,
                        verify_sha256_filename=True,
                    )
                    raw_path, idempotent_raw = publish_temp_create_only(
                        temp_path,
                        raw_path,
                        expected_sha256=raw_sha256,
                    )
                metadata = {
                    name: response.headers.get(name)
                    for name in CAPTURED_HTTP_HEADERS
                }
                observation = create_observation(
                    paths,
                    source=source,
                    trade_day=trade_day,
                    source_url=response.final_url,
                    http_status=response.status,
                    http_metadata=metadata,
                    observed_at=observed,
                    raw_sha256=raw_sha256,
                    raw_bytes=raw_bytes,
                    raw_path=raw_path,
                    collector_version=collector_version,
                    registry=registry,
                )
        return AcquiredObject(
            object_id=observation["object_id"],
            observation_id=observation["observation_id"],
            revision_id=observation["revision_id"],
            raw_sha256=raw_sha256,
            raw_bytes=raw_bytes,
            raw_path=raw_path,
            first_seen_at=parse_utc(observation["first_seen_at"], "first_seen_at"),
            last_seen_at=parse_utc(observation["last_seen_at"], "last_seen_at"),
            supersedes_object_id=observation["supersedes_object_id"],
            supersedes_revision_id=observation["supersedes_revision_id"],
            idempotent_raw=idempotent_raw,
        )
    except BaseException as exc:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temp_info = temp_path.lstat()
            if temp_info.st_nlink == 1:
                temp_path.unlink()
        except FileNotFoundError:
            pass
        if isinstance(exc, OSError):
            raise RegistryError(f"raw acquisition filesystem failure: {exc}") from exc
        raise
