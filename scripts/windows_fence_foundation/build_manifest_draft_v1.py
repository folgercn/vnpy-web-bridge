"""Deterministically validate and publish one unsigned Windows manifest draft.

No private-key input exists in this command.  It is intentionally an offline
release-bundle preparation step, not an installer or runtime operation.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from .offline_signing_v1 import (
    OfflineSigningError,
    _verify_identity_and_frozen_facts,
    read_canonical_artifact_v1,
    write_audit_create_only_v1,
    write_canonical_create_only_v1,
)


def build_manifest_draft_v1(raw: bytes) -> dict[str, object]:
    """Accept only a complete canonical, schema-valid unsigned manifest draft."""
    value = dict(_verify_unsigned_manifest(raw))
    return value


def _verify_unsigned_manifest(raw: bytes) -> dict[str, object]:
    # The standard reader rejects only noncanonical/duplicate JSON.  Drafts
    # deliberately omit signature, then the same strict schema path is used.
    from .offline_signing_v1 import _strict_object

    value = _strict_object(raw)
    if "signature" in value or value.get("schema_version") != "windows_rpc_durable_fence_install_manifest_v1":
        raise OfflineSigningError("SIGNING_UNSIGNED_MANIFEST_DRAFT_REQUIRED")
    _verify_identity_and_frozen_facts(value)
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--audit-output", type=Path, required=True)
    options = parser.parse_args(argv)
    try:
        raw, _value = read_canonical_artifact_v1(options.input)
        draft = build_manifest_draft_v1(raw)
        output = write_canonical_create_only_v1(options.output, draft)
        write_audit_create_only_v1(options.audit_output, artifact_raw=output, action="build-manifest-draft")
    except (OfflineSigningError, OSError, ValueError) as exc:
        parser.error(f"offline manifest draft build failed: {exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
