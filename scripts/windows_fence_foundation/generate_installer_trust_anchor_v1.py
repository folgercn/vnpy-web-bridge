"""Generate the sealed installer trust-anchor module from public keyring bytes only."""

from __future__ import annotations

import argparse
from pathlib import Path

from .installer_trust_anchor_v1 import (
    render_installer_trust_anchor_generated_module_v1,
)


def generate_installer_trust_anchor_v1(
    *,
    public_keyring_path: Path,
    keyring_canonical_path: Path,
    expected_source_sha256: str,
    output: Path,
) -> None:
    output.write_bytes(
        render_installer_trust_anchor_generated_module_v1(
            public_keyring_raw=public_keyring_path.read_bytes(),
            keyring_canonical_path=keyring_canonical_path,
            expected_source_sha256=expected_source_sha256,
        )
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-keyring", type=Path, required=True)
    parser.add_argument("--keyring-canonical-path", type=Path, required=True)
    parser.add_argument("--expected-source-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args(argv)
    generate_installer_trust_anchor_v1(
        public_keyring_path=options.public_keyring,
        keyring_canonical_path=options.keyring_canonical_path,
        expected_source_sha256=options.expected_source_sha256,
        output=options.output,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
