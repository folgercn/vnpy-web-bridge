"""Capture canonical live-host evidence for the final M2 isolation verifier."""

from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

from .canonical import canonical_json_line
from .errors import RegistryError
from .m2_evidence_capture import publish_evidence
from .m2_evidence_probe import capture_host_probes
from .m2_monitor import evaluate_monitor
from .m2_monitor_facts import derive_monitor_facts
from .m2_ntp import query_trusted_clock
from .m2_release_lock import hold_release_verification_lock
from .m2_runtime_input import DEFAULT_RUNTIME_INPUT
from .m2_runtime_loader import load_runtime_context
from .timeutil import parse_utc


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "--runtime-input",
        type=Path,
        default=DEFAULT_RUNTIME_INPUT,
    )
    result.add_argument("--deployment-dir", type=Path, required=True)
    result.add_argument("--policy-activated-at", required=True)
    result.add_argument("--pf-loaded-at", required=True)
    result.add_argument("--launchd-loaded-at", required=True)
    result.add_argument("--release-tree-manifest", type=Path, required=True)
    result.add_argument(
        "--expected-release-tree-manifest-sha256",
        required=True,
    )
    result.add_argument("--success-output", type=Path, required=True)
    result.add_argument("--evidence-output", type=Path, required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        activation = {
            "policy_activated_at": args.policy_activated_at,
            "pf_loaded_at": args.pf_loaded_at,
            "launchd_loaded_at": args.launchd_loaded_at,
        }
        for label, value in activation.items():
            parse_utc(value, f"M2 {label}")
        context = load_runtime_context(args.runtime_input)
        clock = query_trusted_clock()
        facts = derive_monitor_facts(
            paths=context.paths,
            runtime=context.runtime,
            registry=context.registry,
            calendar=context.calendar,
            calendar_availability_raw_sha256=context.availability.raw_sha256,
            monitor_from_day=date.fromisoformat(
                context.runtime_input.payload["monitor_from_day"]
            ),
            backup_root=Path(context.policy.payload["backup_root"]),
            backup_public_key_path=Path(
                context.runtime_input.payload["backup_public_key_path"]
            ),
            expected_backup_public_key_sha256=context.runtime_input.payload[
                "expected_backup_public_key_sha256"
            ],
            expected_backup_head_anchor_raw_sha256=context.runtime_input.payload[
                "expected_backup_head_anchor_raw_sha256"
            ],
            now=clock.trusted_now,
        )
        probes = capture_host_probes(
            policy=context.policy,
            deployment_directory=args.deployment_dir,
            observed_at=clock.trusted_now.isoformat(timespec="microseconds").replace(
                "+00:00", "Z"
            ),
        )
        captured_clock = query_trusted_clock()
        monitor = evaluate_monitor(
            facts,
            policy=context.policy,
            now=captured_clock.trusted_now,
        )
        if monitor["status"] != "HEALTHY":
            raise RegistryError(
                "M2 evidence monitor is degraded: " + ",".join(monitor["incidents"])
            )
        with hold_release_verification_lock(
            Path(context.policy.payload["release_lock_path"])
        ) as held:
            if held.identity is None:
                raise RegistryError("M2 release lock identity is missing")
            result = publish_evidence(
                args.evidence_output,
                policy=context.policy,
                probes=probes,
                activation=activation,
                monitor_input=facts,
                release_tree_manifest_path=args.release_tree_manifest,
                expected_release_tree_manifest_sha256=(
                    args.expected_release_tree_manifest_sha256
                ),
                release_lock_identity=held.identity.as_dict(),
                success_output_path=args.success_output,
                captured_at=captured_clock.trusted_now,
            )
            held.revalidate()
    except (OSError, RegistryError, ValueError) as exc:
        print(f"M2 evidence capture failed closed: {exc}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(
        canonical_json_line(
            {
                "schema_version": "vnpy_research_m2_evidence_capture_result_v1",
                "status": "M2_RESEARCH_ISOLATION_EVIDENCE_CAPTURED",
                **result,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
