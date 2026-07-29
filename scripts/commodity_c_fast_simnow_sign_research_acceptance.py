#!/usr/bin/env python3
"""Sign one pre-reviewed C_FAST SimNow Research Acceptance v1."""

from __future__ import annotations

import argparse
import hashlib
import hmac
from pathlib import Path
import sys

from commodity_c_fast_simnow_research_acceptance import (
    OneShotError,
    ResearchAcceptanceError,
    add_artifact_arguments,
    artifact_paths_from_args,
    complete_signature,
    prepare_unsigned_acceptance,
    utc_now,
    verify_signed_acceptance,
)
from commodity_c_fast_simnow_research_bundle import (
    ResearchBundleError,
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
        "C_FAST SimNow Research Acceptance signer source",
    )
    actual = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(actual, expected_sha256):
        raise ResearchAcceptanceError(
            "Control acceptance signer source pin mismatch"
        )
    return actual


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="private unsigned acceptance JSON; PENDING template is invalid",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--private-key-file", type=Path, required=True)
    parser.add_argument("--custody-root", type=Path, required=True)
    parser.add_argument(
        "--research-trusted-keyring",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--expected-research-keyring-raw-sha256",
        required=True,
    )
    parser.add_argument(
        "--expected-research-signer-sha256",
        required=True,
    )
    parser.add_argument(
        "--acceptance-trusted-keyring",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--expected-acceptance-keyring-raw-sha256",
        required=True,
    )
    parser.add_argument(
        "--expected-acceptance-signer-sha256",
        required=True,
        help="out-of-band raw SHA256 pin for this signer source",
    )
    parser.add_argument(
        "--expected-simnow-account-sha256",
        required=True,
    )
    add_artifact_arguments(parser)
    return parser.parse_args()


def _prepare_from_args(
    args: argparse.Namespace,
    draft: dict,
    signer_sha256: str,
) -> tuple[dict, object, object]:
    return prepare_unsigned_acceptance(
        draft,
        custody_root=args.custody_root,
        research_keyring_path=args.research_trusted_keyring,
        acceptance_keyring_path=args.acceptance_trusted_keyring,
        artifact_paths=artifact_paths_from_args(args),
        expected_research_keyring_raw_sha256=(
            args.expected_research_keyring_raw_sha256
        ),
        expected_research_signer_sha256=(
            args.expected_research_signer_sha256
        ),
        expected_acceptance_keyring_raw_sha256=(
            args.expected_acceptance_keyring_raw_sha256
        ),
        expected_acceptance_signer_sha256=signer_sha256,
        expected_simnow_account_sha256=(
            args.expected_simnow_account_sha256
        ),
        now=utc_now(),
    )


def _require_same_public_snapshot(
    expected_candidate: dict,
    expected_installed: object,
    actual_candidate: dict,
    actual_installed: object,
    *,
    stage: str,
) -> None:
    if (
        actual_candidate != expected_candidate
        or actual_installed != expected_installed
    ):
        raise ResearchAcceptanceError(
            f"public Research Acceptance inputs changed {stage}"
        )


def main() -> int:
    args = parse_args()
    try:
        signer_sha256 = verified_signer_source_sha256(
            args.expected_acceptance_signer_sha256
        )
        draft = load_json_strict(
            args.input,
            "unsigned C_FAST SimNow Research Acceptance",
            private=True,
        )

        # All public evidence, custody, key-domain, target and time checks
        # finish before this process is allowed to read private-key material.
        candidate, public_key, installed = _prepare_from_args(
            args,
            draft,
            signer_sha256,
        )
        final_candidate, final_public_key, final_installed = (
            _prepare_from_args(
                args,
                draft,
                signer_sha256,
            )
        )
        _require_same_public_snapshot(
            candidate,
            installed,
            final_candidate,
            final_installed,
            stage="before private-key read",
        )
        candidate = final_candidate
        public_key = final_public_key
        installed = final_installed
        private_key = load_private_key(args.private_key_file)
        signing_candidate, signing_public_key, signing_installed = (
            _prepare_from_args(
                args,
                draft,
                signer_sha256,
            )
        )
        _require_same_public_snapshot(
            candidate,
            installed,
            signing_candidate,
            signing_installed,
            stage="before signature",
        )
        candidate = signing_candidate
        public_key = signing_public_key
        signed = complete_signature(candidate, public_key, private_key)
        output = write_json_create_only_verified(
            args.output,
            signed,
            label="signed C_FAST SimNow Research Acceptance",
        )
        verified = verify_signed_acceptance(
            output,
            custody_root=args.custody_root,
            research_keyring_path=args.research_trusted_keyring,
            acceptance_keyring_path=args.acceptance_trusted_keyring,
            artifact_paths=artifact_paths_from_args(args),
            expected_research_keyring_raw_sha256=(
                args.expected_research_keyring_raw_sha256
            ),
            expected_research_signer_sha256=(
                args.expected_research_signer_sha256
            ),
            expected_acceptance_keyring_raw_sha256=(
                args.expected_acceptance_keyring_raw_sha256
            ),
            expected_acceptance_signer_sha256=signer_sha256,
            expected_simnow_account_sha256=(
                args.expected_simnow_account_sha256
            ),
            now=utc_now(),
        )
    except (
        ResearchAcceptanceError,
        ResearchBundleError,
        OneShotError,
        OSError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        print(
            f"C_FAST Research Acceptance signing failed: {exc}",
            file=sys.stderr,
        )
        return 2
    print(f"signed Research Acceptance written: {output}")
    print(f"acceptance_id: {verified.payload['acceptance_id']}")
    print(f"acceptance_state: {verified.payload['acceptance_state']}")
    print("simnow_execution_authorized: false")
    print("trading_authorized: false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
