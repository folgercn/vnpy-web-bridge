from __future__ import annotations

from pydantic import BaseModel, Field


class LoginRequestDTO(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class LoginResponseDTO(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict[str, str]
