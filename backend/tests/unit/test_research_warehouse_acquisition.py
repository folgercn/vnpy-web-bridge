from __future__ import annotations

import base64
import errno
import json
import multiprocessing
import os
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
from research_warehouse.canonical import canonical_json_line, sha256
from research_warehouse.errors import RegistryError
from research_warehouse.filesystem import (
    WarehousePaths,
    create_only_bytes,
    read_regular_strict,
)
from research_warehouse.manifests import (
    seal_daily_batch,
    verify_manifest_chain,
)
from research_warehouse.observations import (
    load_observations,
    observation_id,
    raw_object_id,
    revision_occurrence_id,
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
T5 = datetime(2026, 7, 28, 8, 20, tzinfo=timezone.utc)
T6 = datetime(2026, 7, 28, 8, 25, tzinfo=timezone.utc)
T7 = datetime(2026, 7, 28, 8, 30, tzinfo=timezone.utc)
T8 = datetime(2026, 7, 28, 8, 35, tzinfo=timezone.utc)


def _crash_during_metadata_write(
    warehouse_root: str,
    target: str,
) -> None:
    paths = WarehousePaths.open(Path(warehouse_root))

    def partial_then_exit(descriptor: int, raw: bytes) -> None:
        os.write(descriptor, raw[:4])
        os._exit(91)

    filesystem._write_all = partial_then_exit
    create_only_bytes(
        Path(target),
        b'{"complete":true}\n',
        "crash-test metadata",
        temporary_dir=paths.temporary,
    )


def _crash_after_metadata_link(
    warehouse_root: str,
    target: str,
) -> None:
    paths = WarehousePaths.open(Path(warehouse_root))
    original_link = filesystem.os.link

    def link_then_exit(source, destination, **kwargs) -> None:
        original_link(source, destination, **kwargs)
        os._exit(92)

    filesystem.os.link = link_then_exit
    create_only_bytes(
        Path(target),
        b'{"complete":true}\n',
        "crash-test metadata",
        temporary_dir=paths.temporary,
    )


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


def observations(paths: WarehousePaths):
    return load_observations(paths, registry())


def manifest_payload(path: Path) -> dict:
    return json.loads(path.read_bytes())


def seal(
    paths: WarehousePaths,
    private_key: Path,
    sealed_at: datetime,
    parent_seal: str | None,
) -> tuple[Path, dict]:
    output = seal_daily_batch(
        paths=paths,
        registry=registry(),
        trade_day=TRADE_DAY,
        private_key_path=private_key,
        signer_key_id="research-key-v1",
        expected_parent_batch_seal_sha256=parent_seal,
        sealed_at=sealed_at,
    )
    return output, manifest_payload(output)


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
    receipts = observations(paths)
    assert len(receipts) == 1
    assert receipts[0]["http_metadata"]["etag"] == '"v1"'
    assert receipts[0]["authority"] == "RESEARCH_EVIDENCE_ONLY"
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
    receipts = observations(paths)
    assert len(receipts) == 2
    state = revision_state(receipts)
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
        expected_parent_batch_seal_sha256=None,
        sealed_at=T2,
    )
    first_seal = manifest_payload(first_manifest)["batch_seal_sha256"]
    second = acquire(paths, official_raw("revision"), T3)
    second_manifest = seal_daily_batch(
        paths=paths,
        registry=registry(),
        trade_day=TRADE_DAY,
        private_key_path=private_key,
        signer_key_id="research-key-v1",
        expected_parent_batch_seal_sha256=first_seal,
        sealed_at=T4,
    )
    second_seal = manifest_payload(second_manifest)["batch_seal_sha256"]

    assert first.raw_path.exists() and second.raw_path.exists()
    assert second.supersedes_object_id == first.object_id
    chain = verify_manifest_chain(
        paths=paths,
        public_key_path=public_key,
        registry=registry(),
        expected_genesis_seal_sha256=first_seal,
        expected_head_seal_sha256=second_seal,
    )
    assert len(chain) == 2
    assert chain[1]["parent_batch_seal_sha256"] == chain[0]["batch_seal_sha256"]
    before_revision = select_pit_revision(
        paths=paths,
        public_key_path=public_key,
        registry=registry(),
        expected_genesis_seal_sha256=first_seal,
        expected_head_seal_sha256=second_seal,
        source_id=SOURCE_ID,
        trade_day=TRADE_DAY,
        cutoff_at=datetime(2026, 7, 28, 8, 7, tzinfo=timezone.utc),
    )
    after_revision = select_pit_revision(
        paths=paths,
        public_key_path=public_key,
        registry=registry(),
        expected_genesis_seal_sha256=first_seal,
        expected_head_seal_sha256=second_seal,
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
        expected_parent_batch_seal_sha256=None,
        sealed_at=T2,
    )
    first_seal = manifest_payload(first)["batch_seal_sha256"]
    repeated = seal_daily_batch(
        paths=paths,
        registry=registry(),
        trade_day=TRADE_DAY,
        private_key_path=private_key,
        signer_key_id="research-key-v1",
        expected_parent_batch_seal_sha256=first_seal,
        sealed_at=T3,
    )

    assert repeated == first
    assert len(
        verify_manifest_chain(
            paths=paths,
            public_key_path=public_key,
            registry=registry(),
            expected_genesis_seal_sha256=first_seal,
            expected_head_seal_sha256=first_seal,
        )
    ) == 1


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
    assert observations(paths) == []
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
    assert observations(paths) == []
    assert_no_ready(paths)
    assert list(paths.temporary.iterdir()) == []


def test_schema_drift_leaves_only_no_evidence(tmp_path: Path) -> None:
    paths = warehouse(tmp_path)
    drifted = json.dumps(
        {
            "o_curinstrument": [{"PRODUCTID": "cu_f"}],
            "report_date": "20260728",
        }
    ).encode()

    with pytest.raises(RegistryError, match="schema drift"):
        acquire(paths, drifted, T1)

    assert list(paths.raw.rglob("*.raw")) == []
    assert observations(paths) == []
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
    assert observations(paths) == []
    assert_no_ready(paths)
    assert list(paths.temporary.iterdir()) == []


def test_raw_tamper_and_hardlink_are_detected(tmp_path: Path) -> None:
    paths = warehouse(tmp_path)
    acquired = acquire(paths, official_raw(), T1)

    acquired.raw_path.write_bytes(b"tampered")
    with pytest.raises(RegistryError, match="exact-byte binding"):
        observations(paths)

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
        expected_parent_batch_seal_sha256=None,
        sealed_at=T2,
    )
    first_seal = manifest_payload(first)["batch_seal_sha256"]
    acquire(paths, official_raw("second"), T3)
    second_manifest = seal_daily_batch(
        paths=paths,
        registry=registry(),
        trade_day=TRADE_DAY,
        private_key_path=private_key,
        signer_key_id="research-key-v1",
        expected_parent_batch_seal_sha256=first_seal,
        sealed_at=T4,
    )
    second_seal = manifest_payload(second_manifest)["batch_seal_sha256"]

    _other_private, other_public = signing_keys(tmp_path / "other")
    with pytest.raises(RegistryError, match="public-key binding|signature"):
        verify_manifest_chain(
            paths=paths,
            public_key_path=other_public,
            registry=registry(),
            expected_genesis_seal_sha256=first_seal,
            expected_head_seal_sha256=second_seal,
        )

    first.unlink()
    with pytest.raises(RegistryError, match="parent seal|exactly one root"):
        verify_manifest_chain(
            paths=paths,
            public_key_path=public_key,
            registry=registry(),
            expected_genesis_seal_sha256=first_seal,
            expected_head_seal_sha256=second_seal,
        )


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
        expected_parent_batch_seal_sha256=None,
        sealed_at=T2,
    )
    seal = manifest_payload(manifest)["batch_seal_sha256"]
    payload = json.loads(manifest.read_bytes())
    payload["ready"] = False
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(RegistryError, match="authority/READY|signature"):
        verify_manifest_chain(
            paths=paths,
            public_key_path=public_key,
            registry=registry(),
            expected_genesis_seal_sha256=seal,
            expected_head_seal_sha256=seal,
        )


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

    assert len(observations(paths)) == 1


def test_response_day_must_match_requested_trade_day(tmp_path: Path) -> None:
    paths = warehouse(tmp_path)
    payload = json.loads(official_raw())
    payload["report_date"] = "20260729"
    wrong_day = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()

    with pytest.raises(RegistryError, match="does not match requested"):
        acquire(paths, wrong_day, T1)

    assert observations(paths) == []
    assert_no_ready(paths)


def test_signer_revalidates_trusted_registry_and_raw_schema(
    tmp_path: Path,
) -> None:
    paths = warehouse(tmp_path)
    private_key, _public_key = signing_keys(tmp_path)
    acquired = acquire(paths, official_raw(), T1)
    receipt = next(paths.observations.rglob("obs-*.json"))
    payload = json.loads(receipt.read_bytes())
    payload["registry_raw_sha256"] = "0" * 64
    payload["observation_id"] = ""
    payload["observation_id"] = observation_id(payload)
    forged_receipt = receipt.parent / f"{payload['observation_id']}.json"
    receipt.unlink()
    forged_receipt.write_bytes(canonical_json_line(payload))
    forged_receipt.chmod(0o600)

    with pytest.raises(RegistryError, match="trusted source contract"):
        seal(paths, private_key, T2, None)

    payload["registry_raw_sha256"] = registry().raw_sha256
    invalid_raw = json.dumps(
        {"o_curinstrument": [], "report_date": "20260728"},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    digest = sha256(invalid_raw)
    invalid_path = (
        paths.raw
        / "shfe"
        / TRADE_DAY
        / SOURCE_ID
        / f"{digest}.raw"
    )
    acquired.raw_path.unlink()
    invalid_path.write_bytes(invalid_raw)
    invalid_path.chmod(0o600)
    source = registry().source(SOURCE_ID)
    payload["raw_sha256"] = digest
    payload["raw_bytes"] = len(invalid_raw)
    payload["http_metadata"]["content-length"] = str(len(invalid_raw))
    payload["raw_relative_path"] = str(invalid_path.relative_to(paths.root))
    payload["object_id"] = raw_object_id(source, TRADE_DAY, digest)
    payload["revision_id"] = revision_occurrence_id(
        source_id=SOURCE_ID,
        trade_day=TRADE_DAY,
        observation_sequence=1,
        object_id=payload["object_id"],
        supersedes_revision_id=None,
    )
    payload["observation_id"] = ""
    payload["observation_id"] = observation_id(payload)
    forged_receipt.unlink()
    forged_receipt = receipt.parent / f"{payload['observation_id']}.json"
    forged_receipt.write_bytes(canonical_json_line(payload))
    forged_receipt.chmod(0o600)

    with pytest.raises(RegistryError, match="non-empty rows"):
        seal(paths, private_key, T2, None)


def test_signer_replays_supersedes_lineage(tmp_path: Path) -> None:
    paths = warehouse(tmp_path)
    private_key, _public_key = signing_keys(tmp_path)
    acquire(paths, official_raw("A"), T1)
    acquire(paths, official_raw("B"), T2)
    receipts = sorted(
        paths.observations.rglob("obs-*.json"),
        key=lambda path: json.loads(path.read_bytes())["observation_sequence"],
    )
    second = json.loads(receipts[1].read_bytes())
    second["supersedes_revision_id"] = None
    second["observation_id"] = ""
    second["observation_id"] = observation_id(second)
    receipts[1].unlink()
    forged = receipts[1].parent / f"{second['observation_id']}.json"
    forged.write_bytes(canonical_json_line(second))
    forged.chmod(0o600)

    with pytest.raises(RegistryError, match="revision lineage"):
        seal(paths, private_key, T3, None)


def test_metadata_publish_survives_forced_process_death(
    tmp_path: Path,
) -> None:
    paths = warehouse(tmp_path)
    parent = paths.private_subdir(paths.observations, "crash")
    target = parent / "obs-crash-test.json"
    context = multiprocessing.get_context("fork")

    writer = context.Process(
        target=_crash_during_metadata_write,
        args=(str(paths.root), str(target)),
    )
    writer.start()
    writer.join(timeout=10)
    assert writer.exitcode == 91
    assert not target.exists()

    linker = context.Process(
        target=_crash_after_metadata_link,
        args=(str(paths.root), str(target)),
    )
    linker.start()
    linker.join(timeout=10)
    assert linker.exitcode == 92
    with pytest.raises(RegistryError, match="exactly one hard link"):
        read_regular_strict(target, "crash-test metadata")

    create_only_bytes(
        target,
        b'{"complete":true}\n',
        "crash-test metadata",
        temporary_dir=paths.temporary,
    )
    assert read_regular_strict(target, "crash-test metadata") == (
        b'{"complete":true}\n'
    )
    assert list(paths.temporary.iterdir()) == []


def test_external_anchors_detect_leaf_and_full_chain_rollback(
    tmp_path: Path,
) -> None:
    paths = warehouse(tmp_path)
    private_key, public_key = signing_keys(tmp_path)
    acquire(paths, official_raw("first"), T1)
    first_path, first_manifest = seal(paths, private_key, T2, None)
    first_seal = first_manifest["batch_seal_sha256"]
    acquire(paths, official_raw("second"), T3)
    second_path, second_manifest = seal(paths, private_key, T4, first_seal)
    second_seal = second_manifest["batch_seal_sha256"]

    second_path.unlink()
    with pytest.raises(RegistryError, match="trusted anchor"):
        verify_manifest_chain(
            paths=paths,
            public_key_path=public_key,
            registry=registry(),
            expected_genesis_seal_sha256=first_seal,
            expected_head_seal_sha256=second_seal,
        )
    with pytest.raises(RegistryError, match="expected parent anchor"):
        seal(paths, private_key, T5, second_seal)

    first_path.unlink()
    with pytest.raises(RegistryError, match="empty"):
        verify_manifest_chain(
            paths=paths,
            public_key_path=public_key,
            registry=registry(),
            expected_genesis_seal_sha256=first_seal,
            expected_head_seal_sha256=second_seal,
        )
    with pytest.raises(RegistryError, match="expected parent anchor"):
        seal(paths, private_key, T5, second_seal)


def test_revision_occurrences_preserve_a_b_a_and_following_c(
    tmp_path: Path,
) -> None:
    paths = warehouse(tmp_path)
    private_key, public_key = signing_keys(tmp_path)
    first_a = acquire(paths, official_raw("A"), T1)
    _first_path, first_manifest = seal(paths, private_key, T2, None)
    first_seal = first_manifest["batch_seal_sha256"]
    second_b = acquire(paths, official_raw("B"), T3)
    _second_path, second_manifest = seal(paths, private_key, T4, first_seal)
    second_seal = second_manifest["batch_seal_sha256"]
    third_a = acquire(paths, official_raw("A"), T5)
    _third_path, third_manifest = seal(paths, private_key, T6, second_seal)
    third_seal = third_manifest["batch_seal_sha256"]

    assert third_a.object_id == first_a.object_id
    assert third_a.revision_id != first_a.revision_id
    assert third_a.supersedes_revision_id == second_b.revision_id
    selected_a = select_pit_revision(
        paths=paths,
        public_key_path=public_key,
        registry=registry(),
        expected_genesis_seal_sha256=first_seal,
        expected_head_seal_sha256=third_seal,
        source_id=SOURCE_ID,
        trade_day=TRADE_DAY,
        cutoff_at=T7,
    )
    assert selected_a.object_id == first_a.object_id
    assert selected_a.revision_id == third_a.revision_id

    fourth_c = acquire(paths, official_raw("C"), T7)
    _fourth_path, fourth_manifest = seal(paths, private_key, T8, third_seal)
    fourth_seal = fourth_manifest["batch_seal_sha256"]
    assert fourth_c.supersedes_revision_id == third_a.revision_id
    selected_c = select_pit_revision(
        paths=paths,
        public_key_path=public_key,
        registry=registry(),
        expected_genesis_seal_sha256=first_seal,
        expected_head_seal_sha256=fourth_seal,
        source_id=SOURCE_ID,
        trade_day=TRADE_DAY,
        cutoff_at=datetime(2026, 7, 28, 8, 40, tzinfo=timezone.utc),
    )
    assert selected_c.revision_id == fourth_c.revision_id


def test_seal_rejects_future_observation_timestamp(tmp_path: Path) -> None:
    paths = warehouse(tmp_path)
    private_key, _public_key = signing_keys(tmp_path)
    acquire(paths, official_raw(), T3)

    with pytest.raises(RegistryError, match="predate"):
        seal(paths, private_key, T2, None)


def test_pit_rechecks_raw_after_chain_verification(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = warehouse(tmp_path)
    private_key, public_key = signing_keys(tmp_path)
    acquired = acquire(paths, official_raw(), T1)
    _manifest_path, manifest = seal(paths, private_key, T2, None)
    seal_hash = manifest["batch_seal_sha256"]
    real_verify = verify_manifest_chain

    def verify_then_tamper(**kwargs):
        chain = real_verify(**kwargs)
        acquired.raw_path.write_bytes(b"tampered after verify")
        return chain

    monkeypatch.setattr(
        "research_warehouse.pit.verify_manifest_chain",
        verify_then_tamper,
    )
    with pytest.raises(RegistryError, match="changed after verification|exact-byte"):
        select_pit_revision(
            paths=paths,
            public_key_path=public_key,
            registry=registry(),
            expected_genesis_seal_sha256=seal_hash,
            expected_head_seal_sha256=seal_hash,
            source_id=SOURCE_ID,
            trade_day=TRADE_DAY,
            cutoff_at=T3,
        )


def test_pit_uses_signed_revision_fields_after_receipt_verification(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = warehouse(tmp_path)
    private_key, public_key = signing_keys(tmp_path)
    acquired = acquire(paths, official_raw(), T1)
    receipt = next(paths.observations.rglob("obs-*.json"))
    _manifest_path, manifest = seal(paths, private_key, T2, None)
    seal_hash = manifest["batch_seal_sha256"]
    real_verify = verify_manifest_chain

    def verify_then_corrupt_receipt(**kwargs):
        chain = real_verify(**kwargs)
        receipt.write_bytes(b'{"source_id":"forged-after-verification"}')
        return chain

    monkeypatch.setattr(
        "research_warehouse.pit.verify_manifest_chain",
        verify_then_corrupt_receipt,
    )
    selected = select_pit_revision(
        paths=paths,
        public_key_path=public_key,
        registry=registry(),
        expected_genesis_seal_sha256=seal_hash,
        expected_head_seal_sha256=seal_hash,
        source_id=SOURCE_ID,
        trade_day=TRADE_DAY,
        cutoff_at=T3,
    )
    assert selected.object_id == acquired.object_id
    assert selected.raw_content == official_raw()


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
