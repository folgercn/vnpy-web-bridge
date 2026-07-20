from __future__ import annotations

import base64

from app.core.config import Settings
import pytest

from app.core.security import (
    CurrentUser,
    authenticate_user,
    create_access_token,
    decode_access_token,
    pbkdf2_password,
    sha256_password,
)


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


def test_authenticate_user_supports_salted_hash() -> None:
    settings = Settings(auth_users_json=f'[{{"username":"alice","role":"trader","password_hash":"{pbkdf2_password("pw", salt="salt")}"}}]')

    assert authenticate_user("alice", "pw", settings) is not None
    assert authenticate_user("alice", "bad", settings) is None


def test_production_rejects_default_jwt_secret() -> None:
    with pytest.raises(ValueError):
        Settings(app_env="production")


def test_production_requires_long_jwt_secret() -> None:
    with pytest.raises(ValueError):
        Settings(app_env="production", jwt_secret_key="short", auth_users_json='[{"username":"admin","role":"admin","password_hash":"x"}]')


def test_production_requires_admin_user() -> None:
    with pytest.raises(ValueError):
        Settings(app_env="production", jwt_secret_key="x" * 32, auth_users_json='[{"username":"viewer","role":"viewer","password_hash":"x"}]')


def test_production_accepts_admin_and_long_secret() -> None:
    settings = Settings(app_env="production", jwt_secret_key="x" * 32, auth_users_json='[{"username":"admin","role":"admin","password_hash":"x"}]')

    assert settings.app_env == "production"


def test_production_rejects_enabled_commodity_simnow_without_trust_config() -> None:
    with pytest.raises(ValueError, match="COMMODITY_SIMNOW_ACCOUNT_HASHES"):
        Settings(
            app_env="production",
            jwt_secret_key="x" * 32,
            auth_users_json='[{"username":"admin","role":"admin","password_hash":"x"}]',
            commodity_simnow_enabled=True,
        )


def test_production_accepts_enabled_commodity_simnow_with_trust_config() -> None:
    settings = Settings(
        app_env="production",
        jwt_secret_key="x" * 32,
        auth_users_json='[{"username":"admin","role":"admin","password_hash":"x"}]',
        commodity_simnow_enabled=True,
        commodity_simnow_account_hashes="a" * 64,
        commodity_simnow_trusted_public_keys_json=(
            '{"research-key":"' + base64.b64encode(bytes(32)).decode("ascii") + '"}'
        ),
    )

    assert settings.commodity_simnow_enabled is True
