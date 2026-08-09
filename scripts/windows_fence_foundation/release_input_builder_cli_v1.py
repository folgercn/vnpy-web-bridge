"""Offline-only release-input builder; never contacts Windows, M2, or SCM."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from datetime import datetime
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from .contracts import canonical_json_bytes
from .installer_trust_anchor_v1 import canonical_public_keyring_v1
from .offline_signing_v1 import (
    OfflineSigningError,
    write_binary_create_only_v1,
    write_canonical_create_only_v1,
)
from .release_input_builder_v1 import build_release_input_manifest_v1

_RELEASE_BUILD_AUDIT_SCHEMA = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "schemas"
    / "windows-fence-release-build-audit-v1.schema.json"
)


def verify_release_build_audit_v1(
    audit_raw: bytes, *, artifacts: dict[str, bytes]
) -> dict[str, object]:
    """Validate one release-build receipt against the exact emitted bytes."""
    if set(artifacts) != {"bundle", "index", "manifest"} or any(
        type(raw) is not bytes for raw in artifacts.values()
    ):
        raise OfflineSigningError("RELEASE_BUILD_AUDIT_ARTIFACT_SET_INVALID")
    try:
        audit = json.loads(audit_raw)
        if not isinstance(audit, dict) or canonical_json_bytes(audit) != audit_raw:
            raise OfflineSigningError("RELEASE_BUILD_AUDIT_NOT_CANONICAL")
        schema = json.loads(_RELEASE_BUILD_AUDIT_SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(audit)
    except OfflineSigningError:
        raise
    except (OSError, json.JSONDecodeError, ValidationError, ValueError) as exc:
        raise OfflineSigningError("RELEASE_BUILD_AUDIT_SCHEMA_INVALID") from exc
    expected_aggregate = hashlib.sha256(
        canonical_json_bytes(audit["artifacts"])
    ).hexdigest()
    if audit["aggregate_raw_sha256"] != expected_aggregate:
        raise OfflineSigningError("RELEASE_BUILD_AUDIT_AGGREGATE_MISMATCH")
    for name, raw in artifacts.items():
        record = audit["artifacts"][name]
        if record["raw_sha256"] != hashlib.sha256(raw).hexdigest() or record[
            "size_bytes"
        ] != len(raw):
            raise OfflineSigningError("RELEASE_BUILD_AUDIT_ARTIFACT_MISMATCH")
    return audit


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-input", type=Path, required=True)
    parser.add_argument("--bundle-output", type=Path, required=True)
    parser.add_argument("--index-output", type=Path, required=True)
    parser.add_argument("--manifest-output", type=Path, required=True)
    parser.add_argument("--audit-output", type=Path, required=True)
    parser.add_argument("--now-utc", required=True)
    options = parser.parse_args(argv)
    try:
        value = json.loads(options.release_input.read_text(encoding="utf-8"))
        schema = json.loads(
            (
                Path(__file__).resolve().parents[2]
                / "docs"
                / "schemas"
                / "windows-fence-release-input-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)
        inputs = dict(value["inputs"])
        for field in ("config_raw", "keyring_raw", "preflight_raw"):
            inputs[field] = base64.b64decode(inputs[field], validate=True)
        pins = canonical_public_keyring_v1(
            inputs["keyring_raw"], hashlib.sha256(inputs["keyring_raw"]).hexdigest()
        )
        bundle, index, manifest = build_release_input_manifest_v1(
            Path(value["source_root"]),
            release_input=inputs,
            pins=pins,
            now=datetime.fromisoformat(options.now_utc.replace("Z", "+00:00")),
        )
        write_binary_create_only_v1(options.bundle_output, bundle)
        index_raw = write_canonical_create_only_v1(
            options.index_output, json.loads(index)
        )
        manifest_raw = write_canonical_create_only_v1(
            options.manifest_output, json.loads(manifest)
        )
        audit = {
            "schema_version": "windows_fence_release_build_audit_v1",
            "purpose": "record_create_only_release_build_outputs",
            "artifacts": {
                name: {
                    "raw_sha256": hashlib.sha256(raw).hexdigest(),
                    "size_bytes": len(raw),
                }
                for name, raw in {
                    "bundle": bundle,
                    "index": index_raw,
                    "manifest": manifest_raw,
                }.items()
            },
        }
        audit["aggregate_raw_sha256"] = hashlib.sha256(
            canonical_json_bytes(audit["artifacts"])
        ).hexdigest()
        audit_raw = canonical_json_bytes(audit)
        verify_release_build_audit_v1(
            audit_raw,
            artifacts={"bundle": bundle, "index": index_raw, "manifest": manifest_raw},
        )
        write_canonical_create_only_v1(options.audit_output, audit)
    except (
        OfflineSigningError,
        OSError,
        ValueError,
        json.JSONDecodeError,
        ValidationError,
    ) as exc:
        parser.error(f"release-input build failed: {exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
