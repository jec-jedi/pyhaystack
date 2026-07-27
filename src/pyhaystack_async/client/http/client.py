"""Async HTTP client using httpx."""

from __future__ import annotations

import asyncio
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


def _normalise_base_uri(uri: str | None) -> str | None:
    if uri is None or uri.endswith("/"):
        return uri
    return f"{uri}/"


def _normalise_headers(headers: httpx.Headers) -> dict[str, str]:
    return {key.lower(): value for key, value in headers.items()}


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
        tls_verify: bool | str | ssl.SSLContext = True,
        legacy_tls: bool = False,
        tls_cert: str | None = None,
        log: logging.Logger | None = None,
    ):
        self.uri = _normalise_base_uri(uri)
        self.params = params
        self.headers = headers
        self.cookies = cookies
        self.auth = auth
        self.timeout = timeout
        self.proxies = proxies
        self.tls_verify = tls_verify
        self.legacy_tls = legacy_tls
        self.tls_cert = tls_cert
        self.log = log
        self._client: httpx.AsyncClient | None = None
        self._client_proxy: str | None = None
        self._client_lock: asyncio.Lock = asyncio.Lock()

    def _resolve_verify(
        self,
        tls_verify: bool | str | ssl.SSLContext | None = None,
    ) -> bool | ssl.SSLContext:
        resolved = self.tls_verify if tls_verify is None else tls_verify
        if isinstance(resolved, ssl.SSLContext):
            return resolved
        if self.legacy_tls:
            return self._build_legacy_context(resolved)
        if isinstance(resolved, str):
            return ssl.create_default_context(cafile=resolved)
        if not resolved:
            return False
        return True

    @staticmethod
    def _build_legacy_context(tls_verify: bool | str) -> ssl.SSLContext:
        context = ssl.create_default_context(
            cafile=tls_verify if isinstance(tls_verify, str) else None,
        )
        context.minimum_version = ssl.TLSVersion.TLSv1
        context.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
        if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
            context.options |= ssl.OP_LEGACY_SERVER_CONNECT

        if not tls_verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        return context

    def _resolve_proxy(self, uri: str) -> str | None:
        if not self.proxies:
            return None

        scheme = uri.split(":", 1)[0].lower()
        for key in (f"{scheme}://", scheme, "all://", "all"):
            proxy = self.proxies.get(key)
            if proxy is not None:
                return proxy

        if len(self.proxies) == 1:
            return next(iter(self.proxies.values()))

        return None

    def _build_httpx_client(
        self,
        *,
        tls_verify: bool | str | ssl.SSLContext | None = None,
        proxy: str | None = None,
    ) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            verify=self._resolve_verify(tls_verify),
            cert=self.tls_cert,
            proxy=proxy,
            timeout=httpx.Timeout(self.timeout or 30.0),
            follow_redirects=True,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )

    async def _ensure_client(self, *, proxy: str | None = None) -> httpx.AsyncClient:
        async with self._client_lock:
            if (
                self._client is None
                or self._client.is_closed
                or self._client_proxy != proxy
            ):
                if self._client is not None and not self._client.is_closed:
                    await self._client.aclose()
                self._client = self._build_httpx_client(proxy=proxy)
                self._client_proxy = proxy
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
        tls_verify: bool | str | ssl.SSLContext | None = None,
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

        proxy = self._resolve_proxy(uri)

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

        temp_client: httpx.AsyncClient | None = None
        if tls_verify is None:
            client = await self._ensure_client(proxy=proxy)
        else:
            temp_client = self._build_httpx_client(tls_verify=tls_verify, proxy=proxy)
            client = temp_client

        if self.log is not None:
            self.log.debug("HTTP %s %s", method, uri)

        try:
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
                    pass
                elif response.status_code >= 400:
                    raise HTTPStatusError(
                        f"HTTP {response.status_code}: {uri}",
                        status=response.status_code,
                        headers=_normalise_headers(response.headers),
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
        finally:
            if temp_client is not None:
                await temp_client.aclose()

        return HTTPResponse(
            status_code=response.status_code,
            headers=_normalise_headers(response.headers),
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
