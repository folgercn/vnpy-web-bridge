from __future__ import annotations

import os
import sys
import time
from dataclasses import asdict, is_dataclass
from queue import Empty, Queue

from vnpy.rpc import RpcClient
from vnpy.trader.constant import Direction, Exchange, Offset, OrderType, Status
from vnpy.trader.event import EVENT_ORDER, EVENT_TICK, EVENT_TRADE
from vnpy.trader.object import CancelRequest, OrderData, OrderRequest, SubscribeRequest, TickData


REQ_ADDRESS = os.getenv("VNPY_RPC_REQ_ADDRESS", "tcp://127.0.0.1:2014")
PUB_ADDRESS = os.getenv("VNPY_RPC_PUB_ADDRESS", "tcp://127.0.0.1:4102")
GATEWAY_NAME = os.getenv("VNPY_GATEWAY_NAME", "CTP")
SYMBOL = os.getenv("VNPY_TEST_SYMBOL", "rb2610")
EXCHANGE = Exchange(os.getenv("VNPY_TEST_EXCHANGE", "SHFE"))


class TestClient(RpcClient):
    def __init__(self) -> None:
        super().__init__()
        self.events: Queue = Queue()

    def callback(self, topic: str, data) -> None:
        self.events.put((topic, data))


def brief(obj) -> dict:
    if is_dataclass(obj):
        data = asdict(obj)
    else:
        data = getattr(obj, "__dict__", {"value": obj})

    return {
        k: v
        for k, v in data.items()
        if k
        in {
            "gateway_name",
            "symbol",
            "exchange",
            "orderid",
            "direction",
            "offset",
            "price",
            "volume",
            "traded",
            "status",
            "datetime",
            "last_price",
            "bid_price_1",
            "ask_price_1",
            "limit_up",
            "limit_down",
        }
    }


def wait_for_tick(client: TestClient, vt_symbol: str, timeout: int = 20) -> TickData | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        remaining = max(0.1, deadline - time.time())
        try:
            topic, event = client.events.get(timeout=min(1, remaining))
        except Empty:
            continue

        event_type = getattr(event, "type", topic)
        if event_type.startswith(EVENT_TICK):
            tick = event.data
            if getattr(tick, "vt_symbol", "") == vt_symbol:
                return tick

    return None


def wait_for_order(client: TestClient, vt_orderid: str, timeout: int = 10) -> OrderData | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        order = client.get_order(vt_orderid, timeout=3_000)
        if order:
            return order
        time.sleep(0.5)
    return None


def drain_order_events(client: TestClient, seconds: int = 5) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            topic, event = client.events.get(timeout=0.5)
        except Empty:
            continue

        event_type = getattr(event, "type", topic)
        if event_type.startswith((EVENT_ORDER, EVENT_TRADE)):
            print(topic, brief(event.data))


def main() -> int:
    vt_symbol = f"{SYMBOL}.{EXCHANGE.value}"
    client = TestClient()
    client.subscribe_topic("")
    client.start(REQ_ADDRESS, PUB_ADDRESS)

    try:
        print(f"subscribe: {vt_symbol}")
        client.subscribe(SubscribeRequest(SYMBOL, EXCHANGE), GATEWAY_NAME, timeout=10_000)

        tick = wait_for_tick(client, vt_symbol)
        if not tick:
            print("tick: timeout")
            print("行情订阅请求已发出，但 20 秒内没收到 tick；可能当前合约无行情或非交易时段。")
            return 2

        print("tick:", brief(tick))

        price = tick.limit_down if tick.limit_down else max(tick.bid_price_1 - 100, tick.bid_price_1 * 0.9)
        req = OrderRequest(
            symbol=SYMBOL,
            exchange=EXCHANGE,
            direction=Direction.LONG,
            type=OrderType.LIMIT,
            volume=1,
            price=price,
            offset=Offset.OPEN,
            reference="mac_rpc_test",
        )

        print("send_order:", brief(req))
        vt_orderid = client.send_order(req, GATEWAY_NAME, timeout=10_000)
        print("vt_orderid:", vt_orderid)

        order = wait_for_order(client, vt_orderid)
        if not order:
            print("order: not found")
            drain_order_events(client)
            return 3

        print("order:", brief(order))

        if order.status in {Status.SUBMITTING, Status.NOTTRADED, Status.PARTTRADED}:
            cancel_req: CancelRequest = order.create_cancel_request()
            print("cancel_order:", brief(cancel_req))
            client.cancel_order(cancel_req, GATEWAY_NAME, timeout=10_000)
            drain_order_events(client, 8)

            final_order = client.get_order(vt_orderid, timeout=5_000)
            print("final_order:", brief(final_order) if final_order else None)
        else:
            print(f"skip cancel: order status is {order.status}")

        return 0
    finally:
        client.stop()
        client.join()


if __name__ == "__main__":
    sys.exit(main())
