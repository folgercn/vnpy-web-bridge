"""Durable single-leader lease and account-scoped fencing tokens."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Any
from uuid import uuid4

from .errors import (
    ClockRollbackError,
    CommandValidationError,
    FencingError,
    LeaseNotHeldError,
    RepositoryUnavailableError,
)
from .models import (
    EPOCH_TIMESTAMP,
    LeaderToken,
    format_utc,
    parse_utc,
    utc_now,
    validate_identifier,
)
from .repository import DurableExecutionRepository


def _parse_timestamp(text: str) -> datetime:
    parse_utc(text, field_name="lease_expires_at")
    return datetime.fromisoformat(text[:-1] + "+00:00")


class LeaderFencer:
    """Lease/fencing authority backed exclusively by the durable repository.

    An instance may be a standby and read state, but it cannot mutate unless
    ``acquire`` has atomically installed its owner/epoch/token.  Epoch and token
    high-water marks are never decremented or reused, including after release.
    """

    def __init__(
        self,
        repository: DurableExecutionRepository,
        *,
        scope: str | None = None,
        lease_seconds: float = 15.0,
    ) -> None:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        self.repository = repository
        self.scope = scope or repository.scope
        self.lease_seconds = float(lease_seconds)
        self._last_now: datetime | None = None
        self._clock_rollback = False
        self._clock_lock = RLock()
        self._token: LeaderToken | None = None

    @property
    def token(self) -> LeaderToken | None:
        return self._token

    @property
    def held(self) -> bool:
        try:
            state = self.repository.snapshot()
        except RepositoryUnavailableError:
            return False
        lease = state["lease"]
        try:
            expires = _parse_timestamp(
                str(lease.get("lease_expires_at", EPOCH_TIMESTAMP))
            )
        except (FencingError, TypeError, ValueError):
            return False
        return bool(
            self._token
            and lease.get("owner_id") == self._token.owner_id
            and lease.get("epoch") == self._token.epoch
            and lease.get("fencing_token") == self._token.fencing_token
            and lease.get("instance_id") == self._token.instance_id
            and expires > utc_now()
        )

    def _clock(self, value: datetime | None) -> datetime:
        # Sample the default clock under the same lock as the high-water check.
        # Otherwise two dispatch/renew threads can sample t0 < t1 and execute
        # the checks in reverse order, falsely latching a clock rollback.
        with self._clock_lock:
            current = value or utc_now()
            if current.tzinfo is None:
                raise ClockRollbackError("lease clock must be timezone aware")
            current = current.astimezone(timezone.utc)
            if self._last_now is not None and current < self._last_now:
                self._clock_rollback = True
                raise ClockRollbackError("clock rollback detected; fencing is halted")
            self._last_now = current
            if self._clock_rollback:
                raise ClockRollbackError("fencing halted after clock rollback")
            return current

    def acquire(self, owner_id: str, *, now: datetime | None = None) -> LeaderToken:
        owner_id = validate_identifier(owner_id, "owner_id")
        current = self._clock(now)
        expires = current + timedelta(seconds=self.lease_seconds)
        expiry_text = format_utc(expires)
        # Every successful acquire is a new process/lease instance.  Renew is
        # the only operation allowed to preserve epoch/token.
        instance_id = f"leader-instance-{uuid4().hex[:24]}"

        def writer(state: dict[str, Any]) -> LeaderToken:
            lease = state["lease"]
            if lease.get("scope") != self.scope:
                raise FencingError("lease scope mismatch")
            old_owner = lease.get("owner_id", "")
            old_expires = _parse_timestamp(
                lease.get("lease_expires_at", EPOCH_TIMESTAMP)
            )
            old_epoch = int(lease.get("epoch", 0))
            old_token = int(lease.get("fencing_token", 0))
            if old_owner and old_expires > current:
                raise LeaseNotHeldError("another live leader instance owns the lease")
            token = LeaderToken(
                self.scope,
                owner_id,
                old_epoch + 1,
                old_token + 1,
                expiry_text,
                instance_id,
            )
            lease.update(
                {
                    "scope": self.scope,
                    "owner_id": token.owner_id,
                    "epoch": token.epoch,
                    "fencing_token": token.fencing_token,
                    "lease_expires_at": token.lease_expires_at,
                    "instance_id": token.instance_id,
                }
            )
            return token

        token, _ = self.repository.mutate(writer)
        self._token = token
        return token

    def renew(
        self,
        token: LeaderToken | Mapping[str, Any] | None = None,
        *,
        now: datetime | None = None,
    ) -> LeaderToken:
        supplied = self._coerce_token(token or self._token)
        current = self._clock(now)
        expiry_text = format_utc(current + timedelta(seconds=self.lease_seconds))

        def writer(state: dict[str, Any]) -> LeaderToken:
            self._assert_state_token(state, supplied, current)
            renewed = LeaderToken(
                self.scope,
                supplied.owner_id,
                supplied.epoch,
                supplied.fencing_token,
                expiry_text,
                supplied.instance_id,
            )
            state["lease"]["lease_expires_at"] = expiry_text
            return renewed

        renewed, _ = self.repository.mutate(writer)
        self._token = renewed
        return renewed

    def release(
        self,
        token: LeaderToken | Mapping[str, Any] | None = None,
        *,
        now: datetime | None = None,
    ) -> LeaderToken:
        supplied = self._coerce_token(token or self._token)
        current = self._clock(now)

        def writer(state: dict[str, Any]) -> None:
            self._assert_state_token(state, supplied, current, allow_expired=True)
            state["lease"]["owner_id"] = ""
            state["lease"]["lease_expires_at"] = EPOCH_TIMESTAMP
            state["lease"]["instance_id"] = ""

        self.repository.mutate(writer)
        if self._token == supplied:
            self._token = None
        return supplied

    def validate(
        self,
        token: LeaderToken | Mapping[str, Any] | None = None,
        *,
        now: datetime | None = None,
    ) -> LeaderToken:
        supplied = self._coerce_token(token or self._token)
        current = self._clock(now)
        state = self.repository.snapshot()
        self._assert_state_token(state, supplied, current)
        return supplied

    def admission(
        self,
        *,
        leader_epoch: int | None,
        fencing_token: int | None,
        token: LeaderToken | Mapping[str, Any] | None = None,
        now: datetime | None = None,
    ) -> LeaderToken:
        if leader_epoch is None or fencing_token is None:
            raise FencingError("leader_epoch and fencing_token are required")
        # Final gateway admission must carry the token explicitly.  Falling
        # back to this process's cached token would let a caller omit/lose the
        # wire credential while still reaching ``send_order``/``cancel_order``.
        if token is None:
            raise FencingError("explicit fencing token is required for mutation")
        supplied = self.validate(token, now=now)
        if supplied.epoch != leader_epoch or supplied.fencing_token != fencing_token:
            raise FencingError("fencing epoch/token mismatch")
        return supplied

    def planned_dispatch_admission(
        self,
        *,
        leader_epoch: int | None,
        fencing_token: int | None,
        token: LeaderToken | Mapping[str, Any] | None = None,
        now: datetime | None = None,
    ) -> LeaderToken:
        """Admit an in-flight immutable-plan child across a same-lease renew.

        ``FinalExecutionRuntime`` snapshots one leader credential before it
        dispatches the children of an accepted immutable plan.  A concurrent
        renew may move only the durable expiry forward while that snapshot is
        in flight.  Bind every durable leader-identity field exactly and accept
        the older expiry only while that same durable lease remains active.

        This deliberately does not replace :meth:`admission`: renew, release,
        ordinary sends, and cancels continue to require the exact current
        expiry.
        """

        if leader_epoch is None or fencing_token is None:
            raise FencingError("leader_epoch and fencing_token are required")
        if token is None:
            raise FencingError("explicit fencing token is required for mutation")
        supplied = self._coerce_token(token)
        current = self._clock(now)
        state = self.repository.snapshot()
        self._assert_state_token(
            state,
            supplied,
            current,
            allow_renewed_expiry_snapshot=True,
        )
        if supplied.epoch != leader_epoch or supplied.fencing_token != fencing_token:
            raise FencingError("fencing epoch/token mismatch")
        return supplied

    def validate_against_state(
        self,
        state: Mapping[str, Any],
        *,
        leader_epoch: int | None,
        fencing_token: int | None,
        token: LeaderToken | Mapping[str, Any] | None,
        now: datetime | None = None,
    ) -> LeaderToken:
        """Validate a token against a transaction candidate without rereading DB."""

        if leader_epoch is None or fencing_token is None or token is None:
            raise FencingError("explicit fencing epoch/token are required")
        supplied = self._coerce_token(token)
        current = self._clock(now)
        self._assert_state_token(state, supplied, current)
        if supplied.epoch != leader_epoch or supplied.fencing_token != fencing_token:
            raise FencingError("fencing epoch/token mismatch")
        return supplied

    def validate_planned_dispatch_against_state(
        self,
        state: Mapping[str, Any],
        *,
        leader_epoch: int | None,
        fencing_token: int | None,
        token: LeaderToken | Mapping[str, Any] | None,
        now: datetime | None = None,
    ) -> LeaderToken:
        """Transaction-candidate form of :meth:`planned_dispatch_admission`."""

        if leader_epoch is None or fencing_token is None or token is None:
            raise FencingError("explicit fencing epoch/token are required")
        supplied = self._coerce_token(token)
        current = self._clock(now)
        self._assert_state_token(
            state,
            supplied,
            current,
            allow_renewed_expiry_snapshot=True,
        )
        if supplied.epoch != leader_epoch or supplied.fencing_token != fencing_token:
            raise FencingError("fencing epoch/token mismatch")
        return supplied

    def current_lease(self) -> dict[str, Any]:
        state = self.repository.snapshot()
        lease = dict(state["lease"])
        try:
            expiry = _parse_timestamp(str(lease["lease_expires_at"]))
        except (CommandValidationError, TypeError, ValueError) as exc:
            raise RepositoryUnavailableError("durable lease expiry is invalid") from exc
        if lease["owner_id"]:
            lease["held"] = expiry > utc_now()
            lease["state"] = "ACTIVE" if lease["held"] else "EXPIRED_BOUND"
        else:
            lease["held"] = False
            lease["state"] = "RELEASED"
        return lease

    def _coerce_token(
        self, token: LeaderToken | Mapping[str, Any] | None
    ) -> LeaderToken:
        if token is None:
            raise FencingError("fencing token is required")
        if isinstance(token, LeaderToken):
            return token
        if not isinstance(token, Mapping):
            raise FencingError("invalid fencing token")
        try:
            scope = token["scope"]
            owner_id = token["owner_id"]
            epoch = token["epoch"]
            fencing_token = token["fencing_token"]
            expires = token["lease_expires_at"]
            instance_id = token.get("instance_id", "")
        except KeyError as exc:
            raise FencingError("incomplete fencing token") from exc
        if not isinstance(scope, str) or scope != self.scope:
            raise FencingError("foreign fencing scope")
        try:
            validate_identifier(owner_id, "owner_id")
        except Exception as exc:
            raise FencingError("invalid fencing owner") from exc
        if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 1:
            raise FencingError("invalid fencing epoch")
        if (
            isinstance(fencing_token, bool)
            or not isinstance(fencing_token, int)
            or fencing_token < 1
        ):
            raise FencingError("invalid fencing token")
        parse_utc(expires, field_name="lease_expires_at")
        if not isinstance(instance_id, str) or not instance_id:
            raise FencingError("fencing token is missing process instance binding")
        return LeaderToken(scope, owner_id, epoch, fencing_token, expires, instance_id)

    def _assert_state_token(
        self,
        state: Mapping[str, Any],
        supplied: LeaderToken,
        now: datetime,
        *,
        allow_expired: bool = False,
        allow_renewed_expiry_snapshot: bool = False,
    ) -> None:
        lease = state.get("lease")
        if not isinstance(lease, Mapping):
            raise FencingError("durable lease is unavailable")
        if lease.get("scope") != self.scope:
            raise FencingError("foreign fencing scope")
        if (
            lease.get("owner_id") != supplied.owner_id
            or lease.get("epoch") != supplied.epoch
            or lease.get("fencing_token") != supplied.fencing_token
            or lease.get("instance_id") != supplied.instance_id
        ):
            raise FencingError("stale or foreign fencing token")
        expiry = _parse_timestamp(str(lease.get("lease_expires_at", EPOCH_TIMESTAMP)))
        durable_expiry_text = lease.get("lease_expires_at")
        if allow_renewed_expiry_snapshot:
            # Only immutable-plan child dispatch may carry the credential that
            # was captured before a concurrent renew.  Identity remains exact,
            # the durable lease must still be active below, and a caller can
            # never present an expiry newer than the durable authority.
            supplied_expiry = _parse_timestamp(supplied.lease_expires_at)
            if supplied_expiry > expiry:
                raise FencingError("fencing lease expiry is newer than durable lease")
        # Release, renew, and every ordinary mutation bind the exact durable
        # expiry.  A caller cannot splice a matching identity onto another
        # expiry in those paths.
        elif supplied.lease_expires_at != durable_expiry_text:
            raise FencingError("fencing lease expiry mismatch")
        if not allow_expired and expiry <= now:
            raise FencingError("fencing lease is expired")


SingleLeaderFencer = LeaderFencer
