"""Offline manifest signer; private key is accepted only via --private-key-fd."""

from .offline_sign_cli_v1 import run

if __name__ == "__main__":
    raise SystemExit(run("manifest"))
