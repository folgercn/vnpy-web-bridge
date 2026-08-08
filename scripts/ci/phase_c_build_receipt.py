#!/usr/bin/env python3
"""Record immutable, build-only OCI evidence for one Phase C matrix unit."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "docs/schemas/issue-291-phase-c-image-receipt-v1.schema.json"


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def create_receipt(
    *,
    phase: str,
    unit: str,
    source_commit_sha: str,
    image_repository: str,
    image_tag: str,
    image_digest: str,
    containerfile: str,
    metadata_sha256: str,
) -> dict[str, Any]:
    """Create a receipt bound to a manifest digest, never a mutable tag."""

    if phase not in {"A", "B"}:
        raise ValueError("phase must be A or B")
    if not image_digest.startswith("sha256:") or len(image_digest) != 71:
        raise ValueError("image_digest must be a sha256 OCI digest")
    if not all(char in "0123456789abcdef" for char in image_digest[7:]):
        raise ValueError("image_digest must be lowercase hexadecimal")
    containerfile_path = ROOT / containerfile
    if not containerfile_path.is_file():
        raise ValueError(f"missing containerfile: {containerfile}")
    body = {
        "schema_version": "web_bridge_issue_291_phase_c_image_receipt_v1",
        "issue_number": 291,
        "phase": phase,
        "unit": unit,
        "source_commit_sha": source_commit_sha,
        "containerfile": containerfile,
        "containerfile_sha256": _sha256_bytes(containerfile_path.read_bytes()),
        "image_repository": image_repository,
        "image_tag": image_tag,
        "image_digest": image_digest,
        "immutable_image_ref": f"{image_repository}@{image_digest}",
        "build_metadata_sha256": metadata_sha256,
        "rollback_identity": f"{image_repository}@{image_digest}",
        "rollback_receipt": {
            "status": "build_only_hold",
            "target_identity": f"{image_repository}@{image_digest}",
            "automatic_rollback_allowed": False,
            "production_allowed": False,
            "live_trading_authorized": False,
            "countable_forward": False,
        },
        "automatic_deploy_allowed": False,
        "manual_deploy_allowed": False,
        "production_allowed": False,
        "live_trading_authorized": False,
        "countable_forward": False,
    }
    core = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {"receipt_id": f"phase-c-build-{_sha256_bytes(core)}", **body}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", required=True)
    parser.add_argument("--unit", required=True)
    parser.add_argument("--source-commit-sha", required=True)
    parser.add_argument("--image-repository", required=True)
    parser.add_argument("--image-tag", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--containerfile", required=True)
    parser.add_argument("--metadata", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    metadata_path = Path(args.metadata)
    receipt = create_receipt(
        phase=args.phase,
        unit=args.unit,
        source_commit_sha=args.source_commit_sha,
        image_repository=args.image_repository,
        image_tag=args.image_tag,
        image_digest=args.image_digest,
        containerfile=args.containerfile,
        metadata_sha256=_sha256_bytes(metadata_path.read_bytes()),
    )
    Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))).validate(receipt)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
