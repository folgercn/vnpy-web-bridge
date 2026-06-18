from __future__ import annotations

import logging
from typing import Any

from app.core.config import Settings, get_settings
from app.core.errors import DatabaseUnavailableError

logger = logging.getLogger(__name__)

DEFAULT_WATCHLIST_ITEMS = [
    {"watch_type": "product", "watch_key": "product:rubber", "display_name": "天然橡胶", "product_codes": ["ru"], "exchange_codes": ["SHFE"]},
    {"watch_type": "product", "watch_key": "product:bitumen", "display_name": "沥青", "product_codes": ["bu"], "exchange_codes": ["SHFE"]},
    {"watch_type": "product", "watch_key": "product:methanol", "display_name": "甲醇", "product_codes": ["ma"], "exchange_codes": ["CZCE"]},
    {"watch_type": "product", "watch_key": "product:soda", "display_name": "纯碱", "product_codes": ["sa"], "exchange_codes": ["CZCE"]},
    {"watch_type": "product", "watch_key": "product:polysilicon", "display_name": "多晶硅", "product_codes": ["ps"], "exchange_codes": ["GFEX"]},
]


class WatchlistService:
    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings
        self._schema_ready = False

    @property
    def settings(self) -> Settings:
        return self._settings or get_settings()

    def list_items(self, username: str) -> list[dict[str, Any]]:
        self._ensure_user_defaults(username)
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT watch_type, watch_key, vt_symbol, symbol, exchange, display_name, product_codes, exchange_codes, created_at
                    FROM user_market_watchlists
                    WHERE username = %s
                    ORDER BY created_at ASC, id ASC
                    """,
                    (username,),
                )
                return [self._normalize(row) for row in cur.fetchall()]

    def add_contract(self, username: str, item: dict[str, str]) -> dict[str, Any]:
        self._ensure_schema()
        vt_symbol = item["vt_symbol"]
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO user_market_watchlists
                        (username, watch_type, watch_key, vt_symbol, symbol, exchange, display_name, product_codes, exchange_codes)
                    VALUES (%s, 'contract', %s, %s, %s, %s, %s, ARRAY[]::text[], ARRAY[]::text[])
                    ON CONFLICT (username, watch_key) DO UPDATE SET
                        vt_symbol = EXCLUDED.vt_symbol,
                        symbol = EXCLUDED.symbol,
                        exchange = EXCLUDED.exchange,
                        display_name = EXCLUDED.display_name
                    RETURNING watch_type, watch_key, vt_symbol, symbol, exchange, display_name, product_codes, exchange_codes, created_at
                    """,
                    (username, f"contract:{vt_symbol}", vt_symbol, item["symbol"], item["exchange"], item["display_name"]),
                )
                row = cur.fetchone()
            conn.commit()
        return self._normalize(row)

    def remove_item(self, username: str, watch_key: str) -> dict[str, Any]:
        self._ensure_schema()
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM user_market_watchlists WHERE username = %s AND watch_key = %s RETURNING watch_key",
                    (username, watch_key),
                )
                deleted = cur.fetchone()
            conn.commit()
        return {"removed": bool(deleted), "watch_key": watch_key}

    def _ensure_user_defaults(self, username: str) -> None:
        self._ensure_schema()
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM user_market_watchlists WHERE username = %s LIMIT 1", (username,))
                if cur.fetchone():
                    return
                cur.executemany(
                    """
                    INSERT INTO user_market_watchlists
                        (username, watch_type, watch_key, display_name, product_codes, exchange_codes)
                    VALUES (%(username)s, %(watch_type)s, %(watch_key)s, %(display_name)s, %(product_codes)s, %(exchange_codes)s)
                    ON CONFLICT (username, watch_key) DO NOTHING
                    """,
                    [{"username": username, **item} for item in DEFAULT_WATCHLIST_ITEMS],
                )
            conn.commit()

    def _ensure_schema(self) -> None:
        if self._schema_ready:
            return
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS user_market_watchlists (
                        id BIGSERIAL PRIMARY KEY,
                        username TEXT NOT NULL,
                        watch_type TEXT NOT NULL CHECK (watch_type IN ('product', 'contract')),
                        watch_key TEXT NOT NULL,
                        vt_symbol TEXT,
                        symbol TEXT,
                        exchange TEXT,
                        display_name TEXT NOT NULL,
                        product_codes TEXT[] NOT NULL DEFAULT ARRAY[]::text[],
                        exchange_codes TEXT[] NOT NULL DEFAULT ARRAY[]::text[],
                        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                        UNIQUE (username, watch_key)
                    )
                    """
                )
                cur.execute("CREATE INDEX IF NOT EXISTS idx_user_market_watchlists_username ON user_market_watchlists(username)")
            conn.commit()
        self._schema_ready = True

    def _connect(self):
        database_url = self.settings.database_url
        if not database_url:
            raise DatabaseUnavailableError("DATABASE_URL 未配置")
        try:
            import psycopg
            from psycopg.rows import dict_row

            return psycopg.connect(database_url, row_factory=dict_row)
        except DatabaseUnavailableError:
            raise
        except Exception as exc:
            logger.exception("PostgreSQL connection failed")
            raise DatabaseUnavailableError(detail={"type": exc.__class__.__name__}) from exc

    @staticmethod
    def _normalize(row: dict[str, Any] | None) -> dict[str, Any]:
        if not row:
            return {}
        data = dict(row)
        data["product_codes"] = list(data.get("product_codes") or [])
        data["exchange_codes"] = list(data.get("exchange_codes") or [])
        if data.get("created_at") is not None:
            data["created_at"] = data["created_at"].isoformat()
        return data


watchlist_service = WatchlistService()
