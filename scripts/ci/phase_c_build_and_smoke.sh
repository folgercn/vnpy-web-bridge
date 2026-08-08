#!/usr/bin/env bash
# Build exactly one matrix unit, assert its offline smoke contract, and emit a
# digest-bound receipt.  This script has no push, deploy, SSH, RPC or trading
# action; Buildx metadata is the required OCI digest evidence.
set -euo pipefail

phase="${1:?phase required}"
unit="${2:?unit required}"
containerfile="${3:?containerfile required}"
repository="${4:?image repository required}"
tag="${5:?image tag required}"
smoke_profile="${6:?smoke profile required}"
source_sha="${7:?source commit sha required}"
receipt="${8:?receipt output required}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

image="${repository}:${tag}"
metadata="artifacts/issue-291-phase-c-${phase}-${unit}-build-metadata.json"
mkdir -p artifacts
docker buildx build --load --file "$containerfile" --tag "$image" --metadata-file "$metadata" .
digest="$(python - "$metadata" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding="utf-8")).get("containerimage.digest")
if not isinstance(value, str) or not value.startswith("sha256:"):
    raise SystemExit("Buildx did not provide containerimage.digest")
print(value)
PY
)"

safe=(--rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges)
case "$smoke_profile" in
  frontend)
    docker run "${safe[@]}" --tmpfs /tmp:rw,noexec,nosuid,size=16m --add-host control-api:127.0.0.1 --entrypoint nginx "$image" -t -c /etc/nginx/nginx.conf
    ;;
  control-api)
    docker run "${safe[@]}" --tmpfs /tmp:rw,noexec,nosuid,size=16m --entrypoint python "$image" -c "from app.control_api import app; paths={getattr(r, 'path', '') for r in app.routes}; assert {'/health/live','/health/ready','/version'} <= paths"
    ;;
  execution-orchestrator)
    docker run "${safe[@]}" --tmpfs /tmp:rw,noexec,nosuid,size=16m --entrypoint python "$image" -c "from app.execution_orchestrator import app; paths={getattr(r, 'path', '') for r in app.routes}; assert {'/health/live','/health/ready','/version'} <= paths"
    ;;
  gateway-request-proxy|gateway-publish-proxy)
    docker image inspect "$image" | python -c "import json,sys; c=json.load(sys.stdin)[0]['Config']; assert c['Entrypoint'] == ['python','/usr/local/bin/gateway_proxy.py']; assert c['User'] == '65532:65532'"
    docker run "${safe[@]}" --tmpfs /tmp:rw,noexec,nosuid,size=16m "$image" version | python -c "import json,sys; value=json.load(sys.stdin); assert value['service'] == 'gateway-rpc-proxy'; assert value['version']"
    ;;
  artifact-custody)
    volume="phase-c-${unit}-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}"
    projection="${volume}-projection"
    trap 'docker volume rm -f "$volume" "$projection" >/dev/null || true' EXIT
    docker volume create "$volume" >/dev/null; docker volume create "$projection" >/dev/null
    for command in version health ready; do docker run "${safe[@]}" -v "$volume:/var/lib/phase-b-custody" -v "$projection:/var/lib/phase-b/projection" "$image" --root /var/lib/phase-b-custody --schema-dir /app/docs/schemas "$command"; done
    ;;
  market-data-worker)
    volume="phase-c-${unit}-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}"; trap 'docker volume rm -f "$volume" >/dev/null || true' EXIT; docker volume create "$volume" >/dev/null
    for command in --health --ready --version; do docker run "${safe[@]}" -v "$volume:/var/lib/phase-b/market-data" "$image" --state-dir /var/lib/phase-b/market-data "$command"; done
    ;;
  execution-quality-worker|monitor-worker)
    state=/var/lib/phase-b/execution-quality; [[ "$smoke_profile" = monitor-worker ]] && state=/var/lib/phase-b/monitor
    volume="phase-c-${unit}-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}"; trap 'docker volume rm -f "$volume" >/dev/null || true' EXIT; docker volume create "$volume" >/dev/null
    for command in --health --version; do docker run "${safe[@]}" -v "$volume:$state" "$image" --state-dir "$state" "$command"; done
    ;;
  batch-producer)
    for command in health ready --version; do docker run "${safe[@]}" --tmpfs /tmp:rw,noexec,nosuid,size=16m "$image" "$command"; done
    ;;
  signing-authority)
    for command in --health --ready --version; do docker run "${safe[@]}" --tmpfs /tmp:rw,noexec,nosuid,size=16m "$image" "$command"; done
    ;;
  *) echo "unknown smoke profile: $smoke_profile" >&2; exit 2 ;;
esac

python scripts/ci/phase_c_build_receipt.py \
  --phase "$phase" --unit "$unit" --source-commit-sha "$source_sha" \
  --image-repository "$repository" --image-tag "$tag" --image-digest "$digest" \
  --containerfile "$containerfile" --metadata "$metadata" --output "$receipt"
