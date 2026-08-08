#!/usr/bin/env bash
# Offline-only canonical Phase C flow.  It creates a throwaway signer/keyring,
# proves Control -> Custody -> Execution, then restarts and reads durable state.
set -euo pipefail

source_sha="${1:?source commit SHA required}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
compose_file=deployments/phase-c/docker-compose.offline-e2e.yml
project="phase-c-offline-e2e-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}"
workdir=$(mktemp -d /tmp/issue291-phase-c-e2e.XXXXXX)

if docker compose version >/dev/null 2>&1; then
  compose_command=(docker compose)
else
  echo "Docker Compose v2 is required for Phase C offline E2E" >&2
  exit 2
fi
compose() { "${compose_command[@]}" --project-name "$project" -f "$compose_file" "$@"; }
cleanup() { compose down --volumes --remove-orphans >/dev/null 2>&1 || true; rm -rf "$workdir"; }
diagnose_failure() {
  echo "phase-c-e2e: failure diagnostics (sensitive lines redacted)" >&2
  compose ps >&2 || true
  while read -r container; do
    [[ -z "$container" ]] && continue
    docker inspect --format '{{.Name}} oom={{.State.OOMKilled}} exit={{.State.ExitCode}} status={{.State.Status}}' "$container" >&2 || true
  done < <(compose ps -aq 2>/dev/null || true)
  compose logs --no-color --tail=80 2>&1 \
    | sed -E '/upload|keyring|authorization|secret|token|password/ s/.*/[redacted sensitive log line]/I' >&2 || true
}
on_exit() {
  local status=$?
  if ((status != 0)); then diagnose_failure; fi
  cleanup
  exit "$status"
}
trap on_exit EXIT

release_buildx_builder() {
  local builder
  builder="$(docker buildx inspect --format '{{.Name}}' 2>/dev/null || true)"
  if [[ -n "$builder" ]]; then
    echo "phase-c-e2e: releasing Buildx builder"
    docker buildx rm "$builder" >/dev/null 2>&1 || true
  fi
}

wait_for_control() {
  local attempt
  for attempt in {1..30}; do
    if compose exec -T control-api python -c \
      "import socket; socket.create_connection(('127.0.0.1', 8081), 2).close()" \
      >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "control-api did not become ready; canonical offline E2E cannot continue" >&2
  compose ps >&2 || true
  return 1
}

python3 - "$workdir" <<'PY'
import base64, json, sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from shared.artifact_contracts.v1 import new_artifact_envelope
from shared.phase_c_workflow.v1 import build_signing_request
from shared.trust_contracts.v1 import build_signed_artifact, canonical_json_line, sha256_bytes, signing_bytes

root = Path(sys.argv[1])
private = Ed25519PrivateKey.generate()
public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
keyring = {"schema_version":"web-bridge-trust-keyring-v1","domain":"runtime_authorization","key_version":"v1","keys":[{"key_id":"phase-c-e2e-key","domain":"runtime_authorization","purpose":"phase-c-runtime-authorization","public_key_base64":base64.b64encode(public).decode(),"status":"active"}]}
raw = canonical_json_line(keyring)
(root / "keyring.json").write_bytes(raw)
artifact = new_artifact_envelope(artifact_type="runtime-authorization", trust_domain="runtime_authorization", producer_id="phase-c-e2e", producer_version="v1", schema_ref="phase-c-runtime-authorization-v1", generated_at="2026-08-08T00:00:00Z", scope={}, predecessor_refs=[], lineage=[], payload={"production_allowed":False,"live_trading_authorized":False,"countable_forward":False})
request = build_signing_request(artifact=artifact, domain="runtime_authorization", key_id="phase-c-e2e-key", key_version="v1", request_id="phase-c-e2e-request-0001", requested_at="2026-08-08T00:00:00Z", expires_at="2099-01-01T00:00:00Z")
unsigned = {"schema_version":"web-bridge-signed-artifact-v1","request_id":request["request_id"],"domain":request["domain"],"signer_key_id":request["key_id"],"signer_key_version":request["key_version"],"requested_at":request["requested_at"],"expires_at":request["expires_at"],"artifact":request["artifact"]}
signed = build_signed_artifact(request, signature_base64=base64.b64encode(private.sign(signing_bytes(unsigned))).decode())
upload = {"idempotency_key":"phase-c-e2e-upload-0001","expected_custody_version":0,"signing_request_id":request["request_id"],"correlation_id":"phase-c-e2e-correlation-0001","signed_artifact":signed}
policies = {domain:{"keyring_path":"/tmp/phase-c-e2e-keyring.json","keyring_raw_sha256":sha256_bytes(raw) if domain == "runtime_authorization" else "0" * 64,"key_purpose":"phase-c-runtime-authorization" if domain == "runtime_authorization" else "unused"} for domain in ("map_acceptance","c_fast_acceptance","runtime_authorization")}
(root / "upload.json").write_text(json.dumps(upload, separators=(",", ":")), encoding="utf-8")
(root / "policies.json").write_text(json.dumps(policies, separators=(",", ":")), encoding="utf-8")
PY

export PHASE_C_CUSTODY_SHARED_SECRET=phase-c-e2e-custody-secret
export PHASE_C_CUSTODY_EXECUTION_READ_SECRET=phase-c-e2e-execution-read-secret
export PHASE_C_EXECUTION_SHARED_SECRET=phase-c-e2e-execution-secret
export CONTROL_EXECUTION_SHARED_SECRET=phase-c-e2e-control-execution-secret
# APP_ENV=phase-c-offline exercises the same non-test Control startup guard as
# a deployed process. Keep this token ephemeral: it is neither logged nor
# written to the temporary handoff/receipt artifacts.
export JWT_SECRET_KEY
JWT_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
if [ "${#JWT_SECRET_KEY}" -lt 32 ] || [ "$JWT_SECRET_KEY" = "change-me-in-production" ]; then
  echo "failed to generate a compliant ephemeral Control JWT secret" >&2
  exit 2
fi
export AUTH_USERS_JSON='[{"username":"ci","password_sha256":"ci"}]'
export PHASE_C_CUSTODY_POLICIES_JSON
PHASE_C_CUSTODY_POLICIES_JSON=$(<"$workdir/policies.json")

echo "phase-c-e2e: build control-api"
scripts/ci/phase_c_build_and_smoke.sh A control-api deployments/phase-a/Containerfile.control-api vnpy-web-bridge-control-api "issue-291-phase-c-${source_sha}-control-api" control-api "$source_sha" artifacts/issue-291-phase-c-e2e-control-api-receipt.json
echo "phase-c-e2e: build artifact-custody"
scripts/ci/phase_c_build_and_smoke.sh B artifact-custody deployments/phase-b/Containerfile.artifact-custody vnpy-web-bridge-artifact-custody "issue-291-phase-c-${source_sha}-artifact-custody" artifact-custody "$source_sha" artifacts/issue-291-phase-c-e2e-artifact-custody-receipt.json
echo "phase-c-e2e: build execution-orchestrator"
scripts/ci/phase_c_build_and_smoke.sh A execution-orchestrator deployments/phase-a/Containerfile.execution-orchestrator vnpy-web-bridge-execution "issue-291-phase-c-${source_sha}-execution-orchestrator" execution-orchestrator "$source_sha" artifacts/issue-291-phase-c-e2e-execution-orchestrator-receipt.json
release_buildx_builder

receipt_image_tag() {
  python3 - "$1" <<'PY'
import json
import sys

receipt = json.load(open(sys.argv[1], encoding="utf-8"))
print(f"{receipt['image_repository']}:{receipt['image_tag']}")
PY
}

# The E2E images were loaded into this runner, so Compose must use their local
# tags.  The receipts retain image_digest/immutable_image_ref for release
# evidence; those digest refs require a registry and are not local image names.
export CONTROL_API_IMAGE="$(receipt_image_tag artifacts/issue-291-phase-c-e2e-control-api-receipt.json)"
export ARTIFACT_CUSTODY_IMAGE="$(receipt_image_tag artifacts/issue-291-phase-c-e2e-artifact-custody-receipt.json)"
export EXECUTION_IMAGE="$(receipt_image_tag artifacts/issue-291-phase-c-e2e-execution-orchestrator-receipt.json)"
echo "phase-c-e2e: compose up"
compose up --no-build --detach
echo "phase-c-e2e: inject public keyring"
compose exec -T artifact-custody python -c \
  'import sys; open("/tmp/phase-c-e2e-keyring.json", "wb").write(sys.stdin.buffer.read())' \
  < "$workdir/keyring.json"
echo "phase-c-e2e: wait for control"
wait_for_control

upload_b64=$(base64 < "$workdir/upload.json" | tr -d '\n')
compose exec -T -e "PHASE_C_E2E_UPLOAD_B64=$upload_b64" control-api python - <<'PY'
import base64, json, os, urllib.request
from app.core.security import CurrentUser, create_access_token

token = create_access_token(CurrentUser("phase-c-e2e", "admin"))
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
upload = json.loads(base64.b64decode(os.environ["PHASE_C_E2E_UPLOAD_B64"]))
request = urllib.request.Request("http://127.0.0.1:8081/api/phase-c/artifacts/upload-install", data=json.dumps(upload).encode(), headers=headers, method="POST")
receipt = json.load(urllib.request.urlopen(request, timeout=15))["data"]
command = {"command_id":"phase-c-e2e-command-0001","idempotency_key":"phase-c-e2e-enable-0001","expected_version":0,"action":"enable","authorization_artifact_id":receipt["artifact_id"],"custody_receipt_id":receipt["receipt_id"],"reason":"offline canonical e2e"}
request = urllib.request.Request("http://127.0.0.1:8081/api/phase-c/authorization/commands", data=json.dumps(command).encode(), headers=headers, method="POST")
status = json.load(urllib.request.urlopen(request, timeout=15))["data"]
assert status["requested_state"] == "ENABLE_REQUESTED" and status["runtime_mutation_allowed"] is False
open("/tmp/phase-c-e2e-handoff.json", "w", encoding="utf-8").write(json.dumps({"receipt_id":receipt["receipt_id"], "artifact_id":receipt["artifact_id"]}))
PY
handoff_b64=$(compose exec -T control-api cat /tmp/phase-c-e2e-handoff.json | base64 | tr -d '\n')
compose restart control-api artifact-custody execution-orchestrator
wait_for_control
compose exec -T -e "PHASE_C_E2E_HANDOFF_B64=$handoff_b64" control-api python - <<'PY'
import base64, json, os, urllib.request
from app.core.security import CurrentUser, create_access_token
token = create_access_token(CurrentUser("phase-c-e2e", "admin")); headers = {"Authorization": f"Bearer {token}"}
handoff = json.loads(base64.b64decode(os.environ["PHASE_C_E2E_HANDOFF_B64"]))
for path in ("/api/phase-c/authorization/status", f"/api/phase-c/custody/receipts/{handoff['receipt_id']}"):
    request = urllib.request.Request("http://127.0.0.1:8081" + path, headers=headers)
    body = json.load(urllib.request.urlopen(request, timeout=15))["data"]
    assert body["production_allowed"] is False and body["live_trading_authorized"] is False and body["countable_forward"] is False
    if path.endswith("/status"):
        assert body["requested_state"] == "ENABLE_REQUESTED" and body["receipt_id"] == handoff["receipt_id"] and body["artifact_id"] == handoff["artifact_id"]
    else:
        assert body["receipt_id"] == handoff["receipt_id"] and body["artifact_id"] == handoff["artifact_id"]
PY
