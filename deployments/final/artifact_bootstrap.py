"""One-shot, networkless final-smoke target-plan custody bootstrap."""

from __future__ import annotations

import json
from pathlib import Path

from shared.artifact_custody.v1 import ArtifactCustody
from shared.commodity_execution import TARGET_PLAN_SCHEMA_VERSION, TargetPlan
from shared.trust_contracts.v1 import sha256_bytes

ROOT = Path("/var/lib/phase-c-custody")
HANDOFF = Path("/handoff")
DOMAIN = "runtime_authorization"
PURPOSE = "phase-c-runtime-authorization"


def _validate_target_plan(payload: object) -> None:
    if not isinstance(payload, dict):
        raise TypeError("target plan payload must be an object")
    TargetPlan.from_mapping(payload)


def main() -> None:
    signed = json.loads((HANDOFF / "signed.json").read_text(encoding="utf-8"))
    if (
        not isinstance(signed, dict)
        or not isinstance(signed.get("artifact"), dict)
        or signed["artifact"].get("artifact_type") != "simnow-target-plan"
        or signed["artifact"].get("trust_domain") != DOMAIN
        or signed["artifact"].get("schema_ref") != TARGET_PLAN_SCHEMA_VERSION
    ):
        raise ValueError("smoke bootstrap requires one target-plan wrapper")
    keyring = HANDOFF / "keyring.json"
    keyring_raw_sha256 = sha256_bytes(keyring.read_bytes())
    with ArtifactCustody(
        ROOT,
        writer_id="artifact-custody",
        writer_epoch=1,
        schema_registry={TARGET_PLAN_SCHEMA_VERSION: _validate_target_plan},
    ) as custody:
        published = custody.publish_signed(
            signed,
            keyring_path=keyring,
            expected_domain=DOMAIN,
            expected_key_purpose=PURPOSE,
            expected_keyring_raw_sha256=keyring_raw_sha256,
            actor_id="smoke-bootstrap",
            idempotency_key="smoke-target-plan-publish-0001",
            correlation_id="smoke-target-plan-bootstrap-0001",
            expected_version=0,
        )
        custody.record(
            "install",
            str(published["artifact_id"]),
            actor_id="smoke-bootstrap",
            idempotency_key="smoke-target-plan-install-0001",
            correlation_id="smoke-target-plan-bootstrap-0001",
            expected_version=int(published["resulting_version"]),
        )


if __name__ == "__main__":
    main()
