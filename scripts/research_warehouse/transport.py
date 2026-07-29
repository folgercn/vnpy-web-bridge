"""Allowlisted HTTPS transport with redirect revalidation."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .acquisition_models import HttpResponse
from .errors import RegistryError
from .policy import validate_redirect


class Transport(Protocol):
    def open(
        self,
        url: str,
        *,
        allowed_hosts: tuple[str, ...],
        accept: str,
        user_agent: str,
        timeout_seconds: float,
    ) -> AbstractContextManager[HttpResponse]: ...


class _AllowlistRedirectHandler(HTTPRedirectHandler):
    def __init__(self, allowed_hosts: tuple[str, ...]) -> None:
        self.allowed_hosts = allowed_hosts

    def redirect_request(
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl,
    ):
        validate_redirect(newurl, self.allowed_hosts)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class UrllibTransport:
    @contextmanager
    def open(
        self,
        url: str,
        *,
        allowed_hosts: tuple[str, ...],
        accept: str,
        user_agent: str,
        timeout_seconds: float,
    ) -> Iterator[HttpResponse]:
        opener = build_opener(_AllowlistRedirectHandler(allowed_hosts))
        request = Request(
            url,
            headers={"Accept": accept, "User-Agent": user_agent},
        )
        try:
            response = opener.open(request, timeout=timeout_seconds)
        except HTTPError as exc:
            raise RegistryError(f"official source returned HTTP {exc.code}") from exc
        except (TimeoutError, URLError, OSError) as exc:
            raise RegistryError("official source request failed") from exc
        try:
            headers = {key.lower(): value for key, value in response.headers.items()}

            def chunks() -> Iterator[bytes]:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        return
                    yield chunk

            yield HttpResponse(
                final_url=response.geturl(),
                status=int(response.status),
                headers=headers,
                chunks=chunks(),
            )
        except (TimeoutError, OSError) as exc:
            raise RegistryError("official source body download failed") from exc
        finally:
            response.close()
