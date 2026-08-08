#!/usr/bin/env bash
# Fresh-volume final-runtime smoke.  It is entirely offline: no Windows RPC,
# gateway proxy, signer, private key, order send, or cancellation is started.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
compose_file="deployments/final/docker-compose.runtime-smoke.yml"
project="issue291-final-smoke-${RANDOM}${RANDOM}"
workdir="$(mktemp -d "${TMPDIR:-/tmp}/issue291-final-runtime.XXXXXX")"
python_bin="${PYTHON:-python3}"
if ! "$python_bin" -c 'import cryptography' >/dev/null 2>&1; then
  local_venv_python="$root/.venv/bin/python"
  if [ -x "$local_venv_python" ] && "$local_venv_python" -c 'import cryptography' >/dev/null 2>&1; then
    python_bin="$local_venv_python"
  else
    echo "final runtime smoke requires host Python cryptography" >&2
    exit 2
  fi
fi

if docker compose version >/dev/null 2>&1; then
  compose_command=(docker compose)
else
  # Local Colima images may lack the desktop plugin.  Compose-bin still talks
  # only to the local Docker socket and is not a reason to skip the runtime
  # test; CI normally takes the native branch above.
  compose_command=(
    docker run --rm --entrypoint /docker-compose
    -v /var/run/docker.sock:/var/run/docker.sock
    -v "$root":/work -w /work docker/compose-bin:latest
  )
fi
compose() { "${compose_command[@]}" --project-name "$project" -f "$compose_file" "$@"; }

diagnose() {
  compose ps >&2 || true
  compose logs --no-color --tail=100 2>&1 \
    | sed -E '/secret|password|token|dsn|keyring/ s/.*/[redacted sensitive log line]/' >&2 \
    || true
}
cleanup() {
  compose --profile bootstrap down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$workdir"
}
on_exit() {
  status=$?
  if (( status != 0 )); then diagnose; fi
  cleanup
  exit "$status"
}
trap on_exit EXIT

compose config --quiet
"$python_bin" - "$workdir" <<'PY'
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from shared.artifact_contracts.v1 import new_artifact_envelope
from shared.commodity_execution import build_target_plan
from shared.trust_contracts.v1 import (
    build_signed_artifact,
    build_signing_request,
    canonical_json_line,
    sha256_bytes,
    signing_bytes,
)

root = Path(sys.argv[1])
private = Ed25519PrivateKey.generate()
public = private.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)
keyring = {
    "schema_version": "web-bridge-trust-keyring-v1",
    "domain": "runtime_authorization",
    "key_version": "v1",
    "keys": [{
        "key_id": "smoke-target-plan-key",
        "domain": "runtime_authorization",
        "purpose": "phase-c-runtime-authorization",
        "public_key_base64": base64.b64encode(public).decode(),
        "status": "active",
    }],
}
keyring_raw = canonical_json_line(keyring)
(root / "keyring.json").write_bytes(keyring_raw)
target = build_target_plan(
    plan_id="smoke-target-plan-0001",
    account_scope="account:smoke-final",
    environment="SIMNOW",
    authority_artifact_id="artifact-smoke-authority-0001",
    authority_artifact_sha256="a" * 64,
    authority_receipt_id="custody-smoke-authority-0001",
    authority_receipt_sha256="b" * 64,
    signer_key_id="smoke-target-plan-key",
    signer_key_version="v1",
    keyring_raw_sha256=sha256_bytes(keyring_raw),
    scope={"account_scope": "account:smoke-final", "environment": "SIMNOW"},
    expires_at="2099-01-01T00:00:00Z",
    phase="OPEN",
    expected_before_position_hash="0" * 64,
    expected_after_position_hash="0" * 64,
    orders=[{
        "symbol": "RB",
        "exchange": "SHFE",
        "direction": "LONG",
        "type": "LIMIT",
        "volume": 1,
        "price": 1.0,
        "offset": "OPEN",
        "reference": "smoke-order-ref-0001",
        "gateway_name": "smoke-gateway",
    }],
)
artifact = new_artifact_envelope(
    artifact_type="simnow-target-plan",
    trust_domain="runtime_authorization",
    producer_id="final-runtime-smoke",
    producer_version="v1",
    schema_ref="web-bridge-simnow-target-plan-v1",
    generated_at="2026-08-08T00:00:00Z",
    scope={"environment": "SIMNOW"},
    predecessor_refs=[],
    lineage=[],
    payload=target,
)
request = build_signing_request(
    artifact,
    domain="runtime_authorization",
    key_id="smoke-target-plan-key",
    key_version="v1",
    request_id="smoke-target-plan-request-0001",
    requested_at="2026-08-08T00:00:00Z",
    expires_at="2099-01-01T00:00:00Z",
)
unsigned = {
    "schema_version": "web-bridge-signed-artifact-v1",
    "request_id": request["request_id"],
    "domain": request["domain"],
    "signer_key_id": request["key_id"],
    "signer_key_version": request["key_version"],
    "requested_at": request["requested_at"],
    "expires_at": request["expires_at"],
    "artifact": request["artifact"],
}
signed = build_signed_artifact(
    request,
    signature_base64=base64.b64encode(private.sign(signing_bytes(unsigned))).decode(),
)
(root / "signed.json").write_text(json.dumps(signed, separators=(",", ":")), encoding="utf-8")
(root / "expect.json").write_text(json.dumps({
    "artifact_id": artifact["artifact_id"],
    "artifact_raw_sha256": hashlib.sha256(canonical_json_line(artifact)).hexdigest(),
}), encoding="utf-8")
PY

# Bootstrap is the only pre-HTTP custody writer.  It is a one-shot,
# networkless container; the host copies only a public keyring and signed
# wrapper into its fresh volume, never the ephemeral private key.
compose build artifact-bootstrap >/dev/null
compose --profile bootstrap create artifact-bootstrap >/dev/null
bootstrap_container="$(compose --profile bootstrap ps --all -q artifact-bootstrap)"
docker cp "$workdir/keyring.json" "$bootstrap_container:/handoff/keyring.json"
docker cp "$workdir/signed.json" "$bootstrap_container:/handoff/signed.json"
test "$(docker start "$bootstrap_container" >/dev/null && docker wait "$bootstrap_container")" = "0"

# Keep normal CI output compact; failure diagnostics below remain redacted.
compose up --build --detach >/dev/null

container_id() {
  compose ps -q "$1"
}
market_container="$(container_id market-data-worker)"
custody_container="$(container_id artifact-custody)"
eq_container="$(container_id execution-quality-worker)"
monitor_container="$(container_id monitor-worker)"
read -r artifact_id artifact_raw_sha256 < <("$python_bin" - "$workdir/expect.json" <<'PY'
import json
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
print(value["artifact_id"], value["artifact_raw_sha256"])
PY
)

docker exec -e "SMOKE_ARTIFACT_ID=$artifact_id" \
  -e "SMOKE_ARTIFACT_RAW_SHA256=$artifact_raw_sha256" \
  -i "$custody_container" python - <<'PY'
import json
import os
from hashlib import sha256
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from shared.trust_contracts.v1 import canonical_json_line

assert urlopen("http://127.0.0.1:8091/health/ready", timeout=3).status == 200
artifact_id = os.environ["SMOKE_ARTIFACT_ID"]
expected_hash = os.environ["SMOKE_ARTIFACT_RAW_SHA256"]
execution = Request(
    f"http://127.0.0.1:8091/internal/v1/artifacts/{artifact_id}",
    headers={
        "X-Phase-C-Principal": "execution-orchestrator",
        "X-Phase-C-Custody-Secret": "smoke-execution-read-secret",
    },
)
artifact = json.load(urlopen(execution, timeout=3))
assert artifact["artifact_id"] == artifact_id
assert artifact["artifact_raw_sha256"] == expected_hash
assert sha256(canonical_json_line(artifact["artifact"])).hexdigest() == expected_hash
assert artifact["artifact"]["payload"]["plan_id"] == "smoke-target-plan-0001"
assert all(artifact["artifact"]["payload"][flag] is False for flag in (
    "production_allowed", "live_trading_authorized", "countable_forward"
))
control = Request(
    f"http://127.0.0.1:8091/internal/v1/artifacts/{artifact_id}",
    headers={
        "X-Phase-C-Principal": "control-api",
        "X-Phase-C-Custody-Secret": "smoke-control-secret",
    },
)
try:
    urlopen(control, timeout=3)
except HTTPError as exc:
    assert exc.code == 401
else:
    raise AssertionError("control read unexpectedly authorised")
legacy = Request(
    f"http://127.0.0.1:8091/internal/v1/artifacts/{artifact_id}",
    headers={
        "X-Phase-C-Principal": "phase-c-execution",
        "X-Phase-C-Custody-Secret": "smoke-control-secret",
    },
)
try:
    urlopen(legacy, timeout=3)
except HTTPError as exc:
    assert exc.code == 401
else:
    raise AssertionError("legacy execution read unexpectedly authorised")
PY

# Validate exactly the projection file through the monitor's read-only mount
# before entering any worker readiness loop.  This prevents a missing Custody
# projection from looking like an unrelated timeout.
docker exec -i "$monitor_container" python - <<'PY'
import json
from pathlib import Path

from phase_b_workers.projections import validate_projection

path = Path("/var/lib/phase-b/projections/artifact-custody/artifact-custody.json")
try:
    projection = json.loads(path.read_text(encoding="utf-8"))
    validate_projection(projection, expected_service_id="artifact-custody")
except Exception as exc:  # noqa: BLE001 - print the exact smoke contract error
    raise SystemExit(
        f"artifact-custody projection invalid at {path}: {type(exc).__name__}: {exc}"
    ) from exc
PY

docker exec -i "$market_container" python - <<'PY'
import json
import os
from pathlib import Path

import psycopg

fence = json.loads(Path("/var/lib/phase-b/market-data/publish_proxy_cursor.json").read_text())
# This assertion intentionally happens before the database query: count==1
# only proves replay dedup after the worker has accepted at least two frames.
assert int(fence["last_source_seq"]) >= 2, fence
with psycopg.connect(os.environ["PHASE_B_QUESTDB_PG_DSN"], connect_timeout=3) as db:
    with db.cursor() as cur:
        cur.execute("SELECT count(*), min(vt_symbol), min(last_price), min(ts), min(ingest_id), min(ingest_seq) FROM market_ticks")
        count, symbol, price, event_time, ingest_id, ingest_seq = cur.fetchone()
        assert (count, symbol, float(price)) == (1, "RB2601.SHFE", 3500.0)
        assert event_time.isoformat() == "2026-08-08T01:02:03+00:00"
        assert isinstance(ingest_id, str) and len(ingest_id) == 32
        assert ingest_seq == 1
        cur.execute("SELECT \"column\", upsertKey, designated FROM table_columns('market_ticks')")
        metadata = {name: (key, designated) for name, key, designated in cur.fetchall()}
        assert metadata["ts"] == (True, True)
        assert metadata["ingest_id"] == (True, False)
PY

for _attempt in $(seq 1 30); do
  if docker exec "$eq_container" python -m phase_b_workers.execution_quality_worker \
    --state-dir /var/lib/phase-b/execution-quality --ready >/dev/null 2>&1 \
    && docker exec "$monitor_container" python -m phase_b_workers.monitor_worker \
      --state-dir /var/lib/phase-b/monitor --ready >/dev/null 2>&1; then
    exit 0
  fi
  sleep 1
done
echo "EQ/monitor did not reach ready state" >&2
exit 1
