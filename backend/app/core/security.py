from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Literal

from fastapi import Depends, Header

from app.core.config import Settings, get_settings
from app.core.errors import AuthRequiredError, PermissionDeniedError

Role = Literal["viewer", "trader", "admin"]


def sha256_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def pbkdf2_password(password: str, *, salt: str | None = None) -> str:
    salt = salt or base64.urlsafe_b64encode(os.urandom(16)).decode("ascii").rstrip("=")
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000)
    return f"pbkdf2_sha256${salt}${_b64_bytes(digest)}"


class CurrentUser:
    def __init__(self, username: str, role: Role) -> None:
        self.username = username
        self.role = role

    def model_dump(self) -> dict[str, str]:
        return {"username": self.username, "role": self.role}


def configured_users(settings: Settings | None = None) -> dict[str, dict[str, str]]:
    settings = settings or get_settings()
    try:
        users = json.loads(settings.auth_users_json)
    except json.JSONDecodeError:
        users = []
    result: dict[str, dict[str, str]] = {}
    for user in users:
        username = str(user.get("username", ""))
        role = str(user.get("role", "viewer"))
        password_hash = str(user.get("password_hash") or user.get("password_sha256") or "")
        if username and role in {"viewer", "trader", "admin"} and password_hash:
            result[username] = {"role": role, "password_hash": password_hash}
    return result


def authenticate_user(username: str, password: str, settings: Settings | None = None) -> CurrentUser | None:
    user = configured_users(settings).get(username)
    if not user:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return CurrentUser(username=username, role=user["role"])  # type: ignore[arg-type]


def verify_password(password: str, password_hash: str) -> bool:
    if password_hash.startswith("pbkdf2_sha256$"):
        try:
            _, salt, expected = password_hash.split("$", 2)
        except ValueError:
            return False
        return hmac.compare_digest(pbkdf2_password(password, salt=salt), password_hash)
    return hmac.compare_digest(password_hash, sha256_password(password))


def create_access_token(user: CurrentUser, settings: Settings | None = None) -> str:
    settings = settings or get_settings()
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user.username,
        "role": user.role,
        "exp": int((datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)).timestamp()),
    }
    signing_input = f"{_b64_json(header)}.{_b64_json(payload)}"
    signature = hmac.new(settings.jwt_secret_key.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256).digest()
    return f"{signing_input}.{_b64_bytes(signature)}"


def decode_access_token(token: str, settings: Settings | None = None) -> CurrentUser:
    settings = settings or get_settings()
    try:
        header_part, payload_part, signature_part = token.split(".")
        signing_input = f"{header_part}.{payload_part}"
        expected = hmac.new(settings.jwt_secret_key.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64_bytes(expected), signature_part):
            raise AuthRequiredError()
        payload = json.loads(_b64_decode(payload_part))
        if int(payload["exp"]) < int(datetime.now(timezone.utc).timestamp()):
            raise AuthRequiredError("登录已过期")
        role = payload.get("role")
        if role not in {"viewer", "trader", "admin"}:
            raise AuthRequiredError()
        return CurrentUser(username=str(payload["sub"]), role=role)
    except AuthRequiredError:
        raise
    except Exception as exc:
        raise AuthRequiredError() from exc


def get_current_user(authorization: Annotated[str | None, Header()] = None) -> CurrentUser:
    if not authorization or not authorization.startswith("Bearer "):
        raise AuthRequiredError()
    return decode_access_token(authorization.removeprefix("Bearer ").strip())


def require_roles(*roles: Role):
    def dependency(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if user.role not in roles:
            raise PermissionDeniedError(detail={"required_roles": list(roles), "role": user.role})
        return user

    return dependency


def _b64_json(value: dict[str, Any]) -> str:
    return _b64_bytes(json.dumps(value, separators=(",", ":")).encode("utf-8"))


def _b64_bytes(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64_decode(value: str) -> str:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(f"{value}{padding}").decode("utf-8")
