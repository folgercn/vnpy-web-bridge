from __future__ import annotations

from app.core.config import Settings
from app.core.security import CurrentUser, authenticate_user, create_access_token, decode_access_token, sha256_password


def test_authenticate_user_from_env_json() -> None:
    settings = Settings(
        auth_users_json=f'[{{"username":"alice","role":"trader","password_sha256":"{sha256_password("pw")}"}}]'
    )

    user = authenticate_user("alice", "pw", settings)

    assert user is not None
    assert user.username == "alice"
    assert user.role == "trader"
    assert authenticate_user("alice", "bad", settings) is None


def test_create_and_decode_access_token() -> None:
    settings = Settings(jwt_secret_key="test-secret")
    token = create_access_token(CurrentUser("admin", "admin"), settings)

    user = decode_access_token(token, settings)

    assert user.username == "admin"
    assert user.role == "admin"
