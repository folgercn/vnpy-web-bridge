"""Short-lived, one-time WebSocket handshake tickets.

Bearer tokens are intentionally never placed in a WebSocket URL.  Tickets are
random, hashed before storage, bound to the authenticated user/role, and
consumed exactly once during the handshake.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import RLock


class WebSocketTicketError(ValueError):
    """The ticket is missing, expired, replayed, or malformed."""


@dataclass(frozen=True, slots=True)
class WebSocketTicketClaim:
    principal: str
    role: str
    expires_at: datetime


class OneTimeWebSocketTicketStore:
    def __init__(self, *, ttl_seconds: int = 60) -> None:
        if ttl_seconds < 10 or ttl_seconds > 300:
            raise ValueError("WebSocket ticket TTL must be 10..300 seconds")
        self.ttl_seconds = ttl_seconds
        self._lock = RLock()
        self._tickets: dict[str, tuple[datetime, WebSocketTicketClaim]] = {}

    def issue(self, *, principal: str, role: str) -> tuple[str, WebSocketTicketClaim]:
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=self.ttl_seconds)
        claim = WebSocketTicketClaim(
            principal=principal, role=role, expires_at=expires_at
        )
        ticket = secrets.token_urlsafe(32)
        with self._lock:
            self._purge(now)
            self._tickets[self._digest(ticket)] = (expires_at, claim)
        return ticket, claim

    def consume(self, ticket: str) -> WebSocketTicketClaim:
        if not isinstance(ticket, str) or len(ticket) < 32:
            raise WebSocketTicketError("invalid WebSocket ticket")
        now = datetime.now(timezone.utc)
        digest = self._digest(ticket)
        with self._lock:
            self._purge(now)
            entry = self._tickets.pop(digest, None)
        if entry is None:
            raise WebSocketTicketError("WebSocket ticket is unknown or already used")
        expires_at, claim = entry
        if expires_at <= now:
            raise WebSocketTicketError("WebSocket ticket expired")
        return claim

    def _purge(self, now: datetime) -> None:
        expired = [
            key for key, (expires_at, _) in self._tickets.items() if expires_at <= now
        ]
        for key in expired:
            self._tickets.pop(key, None)

    @staticmethod
    def _digest(ticket: str) -> str:
        return hashlib.sha256(ticket.encode("utf-8")).hexdigest()


websocket_ticket_store = OneTimeWebSocketTicketStore()


__all__ = [
    "OneTimeWebSocketTicketStore",
    "WebSocketTicketClaim",
    "WebSocketTicketError",
    "websocket_ticket_store",
]
