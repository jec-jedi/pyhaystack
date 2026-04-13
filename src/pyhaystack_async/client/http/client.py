"""Async HTTP client using httpx."""

from __future__ import annotations

import logging
import re
import ssl
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import httpx

from .auth import BasicAuthenticationCredentials, DigestAuthenticationCredentials
from .exceptions import (
    HTTPConnectionError,
    HTTPRedirectError,
    HTTPStatusError,
    HTTPTimeoutError,
)

_PROTO_RE = re.compile(r"^[a-z]+://")


@dataclass(slots=True)
class HTTPResponse:
    """Normalised HTTP response."""

    status_code: int
    headers: dict[str, str]
    body: bytes
    cookies: dict[str, str]

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def content_type(self) -> str | None:
        ct = self.headers.get("content-type")
        if ct is None:
            return None
        return ct.split(";")[0].strip()


class AsyncHttpClient:
    """Async HTTP client wrapping ``httpx.AsyncClient``."""

    def __init__(
        self,
        *,
        uri: str | None = None,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        auth: BasicAuthenticationCredentials | DigestAuthenticationCredentials | None = None,
        timeout: float | None = 30.0,
        proxies: dict[str, str] | None = None,
        tls_verify: bool | str = True,
        tls_cert: str | None = None,
        log: logging.Logger | None = None,
    ):
        self.uri = uri
        self.params = params
        self.headers = headers
        self.cookies = cookies
        self.auth = auth
        self.timeout = timeout
        self.proxies = proxies
        self.tls_verify = tls_verify
        self.tls_cert = tls_cert
        self.log = log
        self._client: httpx.AsyncClient | None = None

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            verify: bool | ssl.SSLContext = True
            if isinstance(self.tls_verify, str):
                ctx = ssl.create_default_context(cafile=self.tls_verify)
                verify = ctx
            elif not self.tls_verify:
                verify = False

            self._client = httpx.AsyncClient(
                verify=verify,
                cert=self.tls_cert,
                timeout=httpx.Timeout(self.timeout or 30.0),
                follow_redirects=True,
                limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def request(
        self,
        method: str,
        uri: str,
        *,
        body: bytes | str | None = None,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        auth: BasicAuthenticationCredentials | DigestAuthenticationCredentials | None = None,
        timeout: float | None = None,
        tls_verify: bool | str | None = None,
        accept_status: set[int] | None = None,
        exclude_params: bool | None = None,
        exclude_headers: bool | None = None,
        exclude_cookies: bool | None = None,
    ) -> HTTPResponse:
        # Resolve absolute URL
        if not _PROTO_RE.match(uri):
            if self.uri is None:
                raise ValueError("uri must be absolute or base set in uri attribute")
            uri = urljoin(self.uri, uri)

        merged_params = self._merge(params, self.params, exclude_params)
        merged_headers = self._merge(headers, self.headers, exclude_headers)
        merged_cookies = self._merge(cookies, self.cookies, exclude_cookies)

        # Resolve auth
        resolved_auth = auth or self.auth
        httpx_auth: httpx.BasicAuth | httpx.DigestAuth | None = None
        if resolved_auth is not None:
            if isinstance(resolved_auth, BasicAuthenticationCredentials):
                httpx_auth = httpx.BasicAuth(resolved_auth.username, resolved_auth.password)
            elif isinstance(resolved_auth, DigestAuthenticationCredentials):
                httpx_auth = httpx.DigestAuth(resolved_auth.username, resolved_auth.password)

        client = await self._ensure_client()

        if self.log is not None:
            self.log.debug("HTTP %s %s", method, uri)

        try:
            response = await client.request(
                method=method,
                url=uri,
                content=body,
                params=merged_params or None,
                headers=merged_headers or None,
                cookies=merged_cookies or None,
                auth=httpx_auth,
                timeout=timeout or self.timeout or 30.0,
            )

            if accept_status and response.status_code in accept_status:
                pass  # don't raise
            elif response.status_code >= 400:
                raise HTTPStatusError(
                    f"HTTP {response.status_code}: {uri}",
                    status=response.status_code,
                    headers=dict(response.headers),
                    body=response.content,
                )

        except httpx.TimeoutException as e:
            raise HTTPTimeoutError(str(e)) from e
        except httpx.TooManyRedirects as e:
            raise HTTPRedirectError(str(e)) from e
        except httpx.ConnectError as e:
            raise HTTPConnectionError(str(e)) from e
        except (HTTPStatusError, HTTPTimeoutError, HTTPRedirectError, HTTPConnectionError):
            raise
        except httpx.HTTPError as e:
            raise HTTPConnectionError(str(e)) from e

        return HTTPResponse(
            status_code=response.status_code,
            headers=dict(response.headers),
            body=response.content,
            cookies={k: v for k, v in response.cookies.items()},
        )

    async def get(self, uri: str, **kwargs: Any) -> HTTPResponse:
        return await self.request("GET", uri, **kwargs)

    async def post(
        self,
        uri: str,
        *,
        body: bytes | str | None = None,
        body_type: str | None = None,
        body_size: int | None = None,
        **kwargs: Any,
    ) -> HTTPResponse:
        headers = dict(kwargs.pop("headers", None) or {})
        if body_type:
            headers["Content-Type"] = body_type
        if body_size is not None:
            headers["Content-Length"] = str(body_size)
        return await self.request("POST", uri, body=body, headers=headers, **kwargs)

    @staticmethod
    def _merge(
        given: dict | None,
        defaults: dict | None,
        exclude: bool | None,
    ) -> dict[str, str]:
        if exclude is True:
            result: dict[str, str] = {}
        else:
            result = dict(defaults or {})
        if given:
            result.update(given)
        return result
