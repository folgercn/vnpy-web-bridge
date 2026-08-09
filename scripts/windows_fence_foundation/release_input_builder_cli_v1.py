"""Offline-only release-input builder; never contacts Windows, M2, or SCM."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from datetime import datetime
from pathlib import Path

from .installer_trust_anchor_v1 import canonical_public_keyring_v1
from .offline_signing_v1 import OfflineSigningError, write_audit_create_only_v1, write_binary_create_only_v1, write_canonical_create_only_v1
from .release_input_builder_v1 import build_release_input_manifest_v1


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
        if not isinstance(value, dict) or set(value) != {"source_root", "inputs"} or not isinstance(value["inputs"], dict):
            raise OfflineSigningError("RELEASE_INPUT_SCHEMA_INVALID")
        inputs = dict(value["inputs"])
        for field in ("config_raw", "keyring_raw", "preflight_raw"):
            inputs[field] = base64.b64decode(inputs[field], validate=True)
        pins = canonical_public_keyring_v1(inputs["keyring_raw"], hashlib.sha256(inputs["keyring_raw"]).hexdigest())
        bundle, index, manifest = build_release_input_manifest_v1(Path(value["source_root"]), release_input=inputs, pins=pins, now=datetime.fromisoformat(options.now_utc.replace("Z", "+00:00")))
        bundle_sha256 = write_binary_create_only_v1(options.bundle_output, bundle)
        index_raw = write_canonical_create_only_v1(options.index_output, json.loads(index))
        manifest_raw = write_canonical_create_only_v1(options.manifest_output, json.loads(manifest))
        write_audit_create_only_v1(options.audit_output, artifact_raw=hashlib.sha256(bundle_sha256.encode() + index_raw + manifest_raw).digest(), action="build-release-input")
    except (OfflineSigningError, OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(f"release-input build failed: {exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
