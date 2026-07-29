#!/usr/bin/env python3
"""Sign one pre-reviewed C_FAST non-countable SimNow research bundle."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
from pathlib import Path
import sys

from commodity_c_fast_simnow_research_bundle import (
    OneShotError,
    ResearchBundleError,
    add_artifact_arguments,
    artifact_paths_from_args,
    complete_signature,
    prepare_unsigned_bundle,
    verify_signed_bundle,
    write_json_create_only_verified,
)
from commodity_c_fast_t1_one_shot import (
    load_json_strict,
    read_regular_file_strict,
)
from commodity_c_fast_t1_sign_release import load_private_key


SIGNER_PATH = Path(__file__).resolve()


def verified_signer_source_sha256(expected_sha256: str) -> str:
    raw = read_regular_file_strict(
        SIGNER_PATH,
        "C_FAST SimNow research-bundle signer source",
    )
    actual = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(actual, expected_sha256):
        raise ResearchBundleError(
            "research-bundle signer source pin mismatch"
        )
    return actual


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="private unsigned bundle JSON; INVALID template is not accepted",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--private-key-file", type=Path, required=True)
    parser.add_argument("--trusted-keyring", type=Path, required=True)
    parser.add_argument(
        "--expected-trusted-keyring-raw-sha256",
        required=True,
        help="out-of-band raw SHA256 pin for the trusted keyring",
    )
    parser.add_argument(
        "--expected-signer-sha256",
        required=True,
        help="out-of-band raw SHA256 pin for this signer source file",
    )
    parser.add_argument(
        "--expected-custody-root-path-sha256",
        required=True,
        help="out-of-band pin for the normalized production custody root path",
    )
    parser.add_argument(
        "--expected-custody-identity-sha256",
        required=True,
        help="out-of-band pin for custody dev/inode/uid/mode identity",
    )
    add_artifact_arguments(parser)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    now = datetime.now(timezone.utc)
    artifact_paths = artifact_paths_from_args(args)
    try:
        signer_sha256 = verified_signer_source_sha256(
            args.expected_signer_sha256
        )
        draft = load_json_strict(
            args.input,
            "unsigned C_FAST SimNow research bundle",
            private=True,
        )

        # Public evidence, schemas, raw pins, formulae and validity are checked
        # before this process is allowed to read private-key material.
        candidate, public_key, _artifact_raw = prepare_unsigned_bundle(
            draft,
            args.trusted_keyring,
            artifact_paths,
            expected_keyring_raw_sha256=(
                args.expected_trusted_keyring_raw_sha256
            ),
            expected_signer_sha256=signer_sha256,
            expected_custody_root_path_sha256=(
                args.expected_custody_root_path_sha256
            ),
            expected_custody_identity_sha256=(
                args.expected_custody_identity_sha256
            ),
            now=now,
        )
        private_key = load_private_key(args.private_key_file)
        signed = complete_signature(candidate, public_key, private_key)
        output = write_json_create_only_verified(
            args.output,
            signed,
            label="signed C_FAST SimNow research bundle",
        )
        verified = verify_signed_bundle(
            output,
            args.trusted_keyring,
            artifact_paths,
            expected_keyring_raw_sha256=(
                args.expected_trusted_keyring_raw_sha256
            ),
            expected_signer_sha256=signer_sha256,
            now=now,
        )
    except (
        ResearchBundleError,
        OneShotError,
        OSError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        print(
            f"C_FAST research-bundle signing failed: {exc}",
            file=sys.stderr,
        )
        return 2
    print(f"signed research bundle written: {output}")
    print(f"bundle_id: {verified.payload['bundle_id']}")
    print("countable_forward: false")
    print("simnow_execution_authorized: false")
    print("runtime_activation_authorized: false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
