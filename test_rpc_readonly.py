from __future__ import annotations

import os
import sys
from pathlib import Path
from pprint import pprint

import zmq

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None

if load_dotenv:
    load_dotenv(Path(__file__).resolve().parent / "backend" / ".env")
    load_dotenv(Path(__file__).resolve().parent / ".env")

REQ_ADDRESS = os.getenv("VNPY_RPC_REQ_ADDRESS", "tcp://127.0.0.1:2014")
TIMEOUT_MS = int(os.getenv("VNPY_RPC_TIMEOUT_MS", "10000"))


def rpc_call(socket: zmq.Socket, name: str, *args, **kwargs):
    socket.send_pyobj([name, args, kwargs])
    if not socket.poll(TIMEOUT_MS):
        raise TimeoutError(f"{name} timeout after {TIMEOUT_MS}ms")

    ok, payload = socket.recv_pyobj()
    if not ok:
        raise RuntimeError(f"{name} failed: {payload}")
    return payload


def sample(items, size: int = 3):
    return list(items[:size]) if items else []


def main() -> int:
    context = zmq.Context()
    socket = context.socket(zmq.REQ)
    socket.setsockopt(zmq.LINGER, 0)
    socket.connect(REQ_ADDRESS)

    try:
        contracts = rpc_call(socket, "get_all_contracts")
        accounts = rpc_call(socket, "get_all_accounts")
        positions = rpc_call(socket, "get_all_positions")

        print(f"contracts: {len(contracts)}")
        for contract in sample(contracts):
            print("contract:", contract.vt_symbol, contract.name, contract.gateway_name)

        print(f"accounts: {len(accounts)}")
        for account in accounts:
            print("account:")
            pprint(account)

        print(f"positions: {len(positions)}")
        for position in sample(positions, 10):
            print("position:")
            pprint(position)

        return 0
    finally:
        socket.close()
        context.term()


if __name__ == "__main__":
    sys.exit(main())
