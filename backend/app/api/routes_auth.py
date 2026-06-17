from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.core.errors import AuthRequiredError, ok
from app.core.security import CurrentUser, authenticate_user, create_access_token, get_current_user
from app.schemas.auth import LoginRequestDTO
from app.services.audit_service import audit_service

router = APIRouter()


@router.post("/auth/login")
def login(payload: LoginRequestDTO, request: Request) -> dict:
    source_ip = request.client.host if request.client else None
    user = authenticate_user(payload.username, payload.password)
    if not user:
        audit_service.record(
            action="login_failed",
            request={"username": payload.username},
            error_code="AUTH_REQUIRED",
            error_message="用户名或密码错误",
            source_ip=source_ip,
        )
        raise AuthRequiredError("用户名或密码错误")

    token = create_access_token(user)
    audit_service.record(
        action="login_success",
        user_id=user.username,
        role=user.role,
        request={"username": user.username},
        source_ip=source_ip,
    )
    return ok({"access_token": token, "token_type": "bearer", "user": user.model_dump()})


@router.post("/auth/logout")
def logout(user: CurrentUser = Depends(get_current_user)) -> dict:
    return ok({"logged_out": True, "user": user.model_dump()})


@router.get("/auth/me")
def me(user: CurrentUser = Depends(get_current_user)) -> dict:
    return ok(user.model_dump())
