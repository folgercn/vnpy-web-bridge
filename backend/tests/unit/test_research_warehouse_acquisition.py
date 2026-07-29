from __future__ import annotations

import base64
import errno
import json
import stat
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

from research_warehouse import filesystem
from research_warehouse.acquisition import acquire_daily
from research_warehouse.acquisition_models import HttpResponse
from research_warehouse.errors import RegistryError
from research_warehouse.filesystem import (
    WarehousePaths,
    read_regular_strict,
)
from research_warehouse.manifests import (
    seal_daily_batch,
    verify_manifest_chain,
)
from research_warehouse.observations import (
    load_observations,
    revision_state,
)
from research_warehouse.pit import select_pit_revision
from research_warehouse.registry import load_registry

REGISTRY_PATH = (
    ROOT / "deployments/research-warehouse/source-registry-v1.json"
)
SOURCE_ID = "shfe-daily-market-data-v1"
TRADE_DAY = "2026-07-28"
T1 = datetime(2026, 7, 28, 8, 0, tzinfo=timezone.utc)
T2 = datetime(2026, 7, 28, 8, 5, tzinfo=timezone.utc)
T3 = datetime(2026, 7, 28, 8, 10, tzinfo=timezone.utc)
T4 = datetime(2026, 7, 28, 8, 15, tzinfo=timezone.utc)


def official_raw(marker: str = "first") -> bytes:
    row = {
        "DELIVERYMONTH": "2608",
        "PRODUCTID": "cu_f",
        "OPENPRICE": "80000",
        "HIGHESTPRICE": "80100",
        "LOWESTPRICE": "79900",
        "CLOSEPRICE": "80050",
        "SETTLEMENTPRICE": "80020",
        "VOLUME": "100",
        "OPENINTEREST": "200",
        "TEST_MARKER": marker,
    }
    return json.dumps(
        {"o_curinstrument": [row], "report_date": "20260728"},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


class FakeTransport:
    def __init__(
        self,
        raw: bytes,
        *,
        status: int = 200,
        content_length: int | None = None,
        chunks: list[bytes] | None = None,
        final_url: str = (
            "https://www.shfe.com.cn/data/tradedata/future/"
            "dailydata/kx20260728.dat"
        ),
    ) -> None:
        self.raw = raw
        self.status = status
        self.content_length = (
            len(raw) if content_length is None else content_length
        )
        self._chunks = chunks
        self.final_url = final_url

    @contextmanager
    def open(self, url: str, **_kwargs):
        body = self._chunks if self._chunks is not None else [self.raw]
        yield HttpResponse(
            final_url=self.final_url,
            status=self.status,
            headers={
                "content-length": str(self.content_length),
                "content-type": "application/json",
                "etag": '"v1"',
                "last-modified": "Tue, 28 Jul 2026 08:00:00 GMT",
            },
            chunks=iter(body),
        )


class TimeoutTransport:
    @contextmanager
    def open(self, _url: str, **_kwargs):
        raise RegistryError("official source body download failed")
        yield  # pragma: no cover


def warehouse(tmp_path: Path) -> WarehousePaths:
    return WarehousePaths.initialize(tmp_path / "warehouse")


def registry():
    return load_registry(REGISTRY_PATH)


def acquire(
    paths: WarehousePaths,
    raw: bytes,
    observed_at: datetime,
    **transport_kwargs,
):
    return acquire_daily(
        paths=paths,
        registry=registry(),
        source_id=SOURCE_ID,
        trade_day=TRADE_DAY,
        collector_version="issue-169-test-v1",
        observed_at=observed_at,
        transport=FakeTransport(raw, **transport_kwargs),
    )


def signing_keys(tmp_path: Path) -> tuple[Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    private = Ed25519PrivateKey.generate()
    private_raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    private_path = tmp_path / "manifest-private.key"
    public_path = tmp_path / "manifest-public.key"
    private_path.write_bytes(private_raw)
    private_path.chmod(0o600)
    public_path.write_bytes(base64.b64encode(public_raw) + b"\n")
    public_path.chmod(0o600)
    return private_path, public_path


def assert_no_ready(paths: WarehousePaths) -> None:
    assert list(paths.manifests.rglob("*.json")) == []


def test_exact_bytes_publish_create_only_and_remain_not_ready(
    tmp_path: Path,
) -> None:
    paths = warehouse(tmp_path)
    raw = official_raw()

    acquired = acquire(paths, raw, T1)

    assert acquired.raw_path.read_bytes() == raw
    assert acquired.raw_sha256 in acquired.raw_path.name
    assert acquired.idempotent_raw is False
    info = acquired.raw_path.lstat()
    assert stat.S_IMODE(info.st_mode) == 0o600
    assert info.st_nlink == 1
    observations = load_observations(paths)
    assert len(observations) == 1
    assert observations[0]["http_metadata"]["etag"] == '"v1"'
    assert observations[0]["authority"] == "RESEARCH_EVIDENCE_ONLY"
    assert_no_ready(paths)
    assert list(paths.temporary.iterdir()) == []


def test_same_bytes_are_raw_idempotent_with_append_only_last_seen(
    tmp_path: Path,
) -> None:
    paths = warehouse(tmp_path)
    raw = official_raw()

    first = acquire(paths, raw, T1)
    second = acquire(paths, raw, T2)

    assert second.idempotent_raw is True
    assert second.object_id == first.object_id
    assert second.first_seen_at == T1
    assert second.last_seen_at == T2
    assert len(list(paths.raw.rglob("*.raw"))) == 1
    observations = load_observations(paths)
    assert len(observations) == 2
    state = revision_state(observations)
    assert state[0]["first_seen_at"].startswith("2026-07-28T08:00:00")
    assert state[0]["last_seen_at"].startswith("2026-07-28T08:05:00")


def test_revision_is_append_only_and_pit_cutoff_never_uses_future_revision(
    tmp_path: Path,
) -> None:
    paths = warehouse(tmp_path)
    private_key, public_key = signing_keys(tmp_path)
    first = acquire(paths, official_raw("first"), T1)
    first_manifest = seal_daily_batch(
        paths=paths,
        registry=registry(),
        trade_day=TRADE_DAY,
        private_key_path=private_key,
        signer_key_id="research-key-v1",
        sealed_at=T2,
    )
    second = acquire(paths, official_raw("revision"), T3)
    second_manifest = seal_daily_batch(
        paths=paths,
        registry=registry(),
        trade_day=TRADE_DAY,
        private_key_path=private_key,
        signer_key_id="research-key-v1",
        sealed_at=T4,
    )

    assert first.raw_path.exists() and second.raw_path.exists()
    assert second.supersedes_object_id == first.object_id
    chain = verify_manifest_chain(paths=paths, public_key_path=public_key)
    assert len(chain) == 2
    assert chain[1]["parent_batch_seal_sha256"] == chain[0]["batch_seal_sha256"]
    before_revision = select_pit_revision(
        paths=paths,
        public_key_path=public_key,
        source_id=SOURCE_ID,
        trade_day=TRADE_DAY,
        cutoff_at=datetime(2026, 7, 28, 8, 7, tzinfo=timezone.utc),
    )
    after_revision = select_pit_revision(
        paths=paths,
        public_key_path=public_key,
        source_id=SOURCE_ID,
        trade_day=TRADE_DAY,
        cutoff_at=datetime(2026, 7, 28, 8, 20, tzinfo=timezone.utc),
    )
    assert before_revision.object_id == first.object_id
    assert before_revision.batch_id in first_manifest.name
    assert after_revision.object_id == second.object_id
    assert after_revision.batch_id in second_manifest.name


def test_seal_is_idempotent_when_observations_are_unchanged(
    tmp_path: Path,
) -> None:
    paths = warehouse(tmp_path)
    private_key, public_key = signing_keys(tmp_path)
    acquire(paths, official_raw(), T1)

    first = seal_daily_batch(
        paths=paths,
        registry=registry(),
        trade_day=TRADE_DAY,
        private_key_path=private_key,
        signer_key_id="research-key-v1",
        sealed_at=T2,
    )
    repeated = seal_daily_batch(
        paths=paths,
        registry=registry(),
        trade_day=TRADE_DAY,
        private_key_path=private_key,
        signer_key_id="research-key-v1",
        sealed_at=T3,
    )

    assert repeated == first
    assert len(verify_manifest_chain(paths=paths, public_key_path=public_key)) == 1


@pytest.mark.parametrize(
    ("transport_kwargs", "match"),
    [
        ({"content_length": len(official_raw()) + 1}, "partial download"),
        ({"status": 404}, "unexpected HTTP 404"),
        (
            {
                "final_url": (
                    "https://evil.invalid/data/tradedata/future/"
                    "dailydata/kx20260728.dat"
                )
            },
            "not allowlisted",
        ),
    ],
)
def test_http_failures_leave_no_raw_observation_or_ready(
    tmp_path: Path,
    transport_kwargs: dict,
    match: str,
) -> None:
    paths = warehouse(tmp_path)

    with pytest.raises(RegistryError, match=match):
        acquire(paths, official_raw(), T1, **transport_kwargs)

    assert list(paths.raw.rglob("*.raw")) == []
    assert load_observations(paths) == []
    assert_no_ready(paths)
    assert list(paths.temporary.iterdir()) == []


def test_timeout_leaves_no_raw_observation_or_ready(tmp_path: Path) -> None:
    paths = warehouse(tmp_path)

    with pytest.raises(RegistryError, match="body download failed"):
        acquire_daily(
            paths=paths,
            registry=registry(),
            source_id=SOURCE_ID,
            trade_day=TRADE_DAY,
            collector_version="issue-169-test-v1",
            observed_at=T1,
            transport=TimeoutTransport(),
        )

    assert list(paths.raw.rglob("*.raw")) == []
    assert load_observations(paths) == []
    assert_no_ready(paths)
    assert list(paths.temporary.iterdir()) == []


def test_schema_drift_leaves_only_no_evidence(tmp_path: Path) -> None:
    paths = warehouse(tmp_path)
    drifted = json.dumps(
        {"o_curinstrument": [{"PRODUCTID": "cu_f"}]}
    ).encode()

    with pytest.raises(RegistryError, match="schema drift"):
        acquire(paths, drifted, T1)

    assert list(paths.raw.rglob("*.raw")) == []
    assert load_observations(paths) == []
    assert_no_ready(paths)


def test_disk_full_cleans_partial_and_never_publishes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = warehouse(tmp_path)

    def disk_full(_descriptor: int, _raw: bytes) -> None:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(filesystem, "_write_all", disk_full)

    with pytest.raises(RegistryError, match="filesystem failure"):
        acquire(paths, official_raw(), T1)

    assert list(paths.temporary.iterdir()) == []
    assert list(paths.raw.rglob("*.raw")) == []
    assert_no_ready(paths)


def test_interruption_after_raw_publish_leaves_no_ready(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = warehouse(tmp_path)

    def interrupted(*_args, **_kwargs):
        raise RuntimeError("process interrupted")

    monkeypatch.setattr(
        "research_warehouse.acquisition.create_observation",
        interrupted,
    )

    with pytest.raises(RuntimeError, match="interrupted"):
        acquire(paths, official_raw(), T1)

    assert len(list(paths.raw.rglob("*.raw"))) == 1
    assert load_observations(paths) == []
    assert_no_ready(paths)
    assert list(paths.temporary.iterdir()) == []


def test_raw_tamper_and_hardlink_are_detected(tmp_path: Path) -> None:
    paths = warehouse(tmp_path)
    acquired = acquire(paths, official_raw(), T1)

    acquired.raw_path.write_bytes(b"tampered")
    with pytest.raises(RegistryError, match="exact-byte binding"):
        load_observations(paths)

    acquired.raw_path.write_bytes(official_raw())
    hardlink = tmp_path / "raw-hardlink"
    hardlink.hardlink_to(acquired.raw_path)
    with pytest.raises(RegistryError, match="exactly one hard link"):
        read_regular_strict(acquired.raw_path, "raw")


def test_manifest_tamper_wrong_key_and_missing_parent_fail_closed(
    tmp_path: Path,
) -> None:
    paths = warehouse(tmp_path)
    private_key, public_key = signing_keys(tmp_path)
    acquire(paths, official_raw("first"), T1)
    first = seal_daily_batch(
        paths=paths,
        registry=registry(),
        trade_day=TRADE_DAY,
        private_key_path=private_key,
        signer_key_id="research-key-v1",
        sealed_at=T2,
    )
    acquire(paths, official_raw("second"), T3)
    seal_daily_batch(
        paths=paths,
        registry=registry(),
        trade_day=TRADE_DAY,
        private_key_path=private_key,
        signer_key_id="research-key-v1",
        sealed_at=T4,
    )

    _other_private, other_public = signing_keys(tmp_path / "other")
    with pytest.raises(RegistryError, match="public-key binding|signature"):
        verify_manifest_chain(paths=paths, public_key_path=other_public)

    first.unlink()
    with pytest.raises(RegistryError, match="parent seal|exactly one root"):
        verify_manifest_chain(paths=paths, public_key_path=public_key)


def test_manifest_signature_tamper_fails_closed(tmp_path: Path) -> None:
    paths = warehouse(tmp_path)
    private_key, public_key = signing_keys(tmp_path)
    acquire(paths, official_raw(), T1)
    manifest = seal_daily_batch(
        paths=paths,
        registry=registry(),
        trade_day=TRADE_DAY,
        private_key_path=private_key,
        signer_key_id="research-key-v1",
        sealed_at=T2,
    )
    payload = json.loads(manifest.read_bytes())
    payload["ready"] = False
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(RegistryError, match="authority/READY|signature"):
        verify_manifest_chain(paths=paths, public_key_path=public_key)


def test_clock_regression_and_invalid_day_fail_before_new_evidence(
    tmp_path: Path,
) -> None:
    paths = warehouse(tmp_path)
    acquire(paths, official_raw(), T2)

    with pytest.raises(RegistryError, match="clock moved backwards"):
        acquire(paths, official_raw(), T1)
    with pytest.raises(RegistryError, match="trade_day"):
        acquire_daily(
            paths=paths,
            registry=registry(),
            source_id=SOURCE_ID,
            trade_day="2026-99-99",
            collector_version="test",
            observed_at=T3,
            transport=FakeTransport(official_raw()),
        )

    assert len(load_observations(paths)) == 1


def test_symlink_warehouse_component_is_rejected(tmp_path: Path) -> None:
    paths = warehouse(tmp_path)
    paths.temporary.rmdir()
    paths.temporary.symlink_to(paths.raw, target_is_directory=True)

    with pytest.raises(RegistryError, match="non-symlink"):
        WarehousePaths.open(paths.root)


def test_symlink_custody_lock_is_rejected(tmp_path: Path) -> None:
    paths = warehouse(tmp_path)
    target = tmp_path / "target.lock"
    target.write_bytes(b"")
    target.chmod(0o600)
    (paths.locks / f"{SOURCE_ID}.lock").symlink_to(target)

    with (
        pytest.raises(RegistryError, match="lock file"),
        filesystem.custody_lock(paths, SOURCE_ID),
    ):
        pass
