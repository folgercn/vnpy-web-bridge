"""Generate the sealed installer trust-anchor module from public keyring bytes only."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from .installer_bootstrap_v1 import _canonical_keyring


def generate_installer_trust_anchor_v1(
    *,
    public_keyring_path: Path,
    keyring_canonical_path: Path,
    expected_source_sha256: str,
    output: Path,
) -> None:
    raw = public_keyring_path.read_bytes()
    keyring_sha256 = hashlib.sha256(raw).hexdigest()
    pins = _canonical_keyring(raw, keyring_sha256)
    if not keyring_canonical_path.is_absolute() or expected_source_sha256 == "0" * 64:
        raise ValueError("INSTALLER_TRUST_ANCHOR_GENERATION_INPUT_INVALID")

    def pin(name: str) -> str:
        value = getattr(pins, name)
        return (
            f"    {name}=FoundationPublicKeyPin(key_domain={value.key_domain!r}, "
            f"role={value.role!r}, key_id={value.key_id!r}, public_key_raw={value.public_key_raw!r}, "
            f"public_key_sha256={value.public_key_sha256!r}),\n"
        )

    source = (
        "# generated from public keyring bytes; never contains a private key\n"
        "from pathlib import Path\n"
        "from .installer_trust_anchor_v1 import InstallerBootstrapTrustAnchorV1\n"
        "from .trust_pins_v1 import FoundationPublicKeyPin\n\n"
        "PRODUCTION_INSTALLER_TRUST_ANCHOR_V1 = InstallerBootstrapTrustAnchorV1(\n"
        f"    keyring_path=Path({str(keyring_canonical_path)!r}),\n"
        f"    keyring_raw_sha256={keyring_sha256!r},\n"
        f"    expected_source_sha256={expected_source_sha256!r},\n"
        f"{pin('manifest')}{pin('observer')}{pin('restart')})\n"
    )
    output.write_text(source, encoding="utf-8")


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
