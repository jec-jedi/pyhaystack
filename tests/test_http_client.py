"""Tests for async HTTP client."""

from __future__ import annotations

import asyncio
import ssl
from unittest.mock import patch

import certifi
import httpx
import pytest
import respx

from pyhaystack_async.client.http.auth import BasicAuthenticationCredentials
from pyhaystack_async.client.http.client import AsyncHttpClient
from pyhaystack_async.client.http.exceptions import (
    HTTPStatusError,
)


@pytest.mark.asyncio
async def test_get_request_basic():
    """Test basic GET request."""
    with respx.mock:
        respx.get("https://example.com/api/about").mock(
            return_value=httpx.Response(200, text="OK", headers={"Content-Type": "text/plain"})
        )
        client = AsyncHttpClient(uri="https://example.com/")
        try:
            resp = await client.get("api/about")
            assert resp.status_code == 200
            assert resp.text == "OK"
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_post_request():
    """Test POST request with body."""
    with respx.mock:
        respx.post("https://example.com/api/read").mock(
            return_value=httpx.Response(200, text="data")
        )
        client = AsyncHttpClient(uri="https://example.com/")
        try:
            resp = await client.post("api/read", body=b"test body")
            assert resp.status_code == 200
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_http_status_error():
    """Test that non-accepted status codes raise HTTPStatusError."""
    with respx.mock:
        respx.get("https://example.com/api/fail").mock(
            return_value=httpx.Response(500, text="Server Error")
        )
        client = AsyncHttpClient(uri="https://example.com/")
        try:
            with pytest.raises(HTTPStatusError) as exc_info:
                await client.get("api/fail")
            assert exc_info.value.status == 500
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_accept_status_bypasses_error():
    """Test that accept_status prevents raising on known codes."""
    with respx.mock:
        respx.get("https://example.com/api/auth").mock(
            return_value=httpx.Response(401, text="Unauthorized")
        )
        client = AsyncHttpClient(uri="https://example.com/")
        try:
            resp = await client.get("api/auth", accept_status={401})
            assert resp.status_code == 401
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_headers_cookies_merge():
    """Test that default headers/cookies merge with per-request ones."""
    with respx.mock:
        route = respx.get("https://example.com/api/test").mock(
            return_value=httpx.Response(200)
        )
        client = AsyncHttpClient(
            uri="https://example.com/",
            headers={"X-Default": "yes"},
            cookies={"session": "abc"},
        )
        try:
            await client.get(
                "api/test",
                headers={"X-Extra": "added"},
                cookies={"extra": "cookie"},
            )
            req = route.calls[0].request
            assert req.headers.get("x-default") == "yes"
            assert req.headers.get("x-extra") == "added"
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_exclude_headers():
    """Test exclude_headers=True drops defaults."""
    with respx.mock:
        route = respx.get("https://example.com/api/test").mock(
            return_value=httpx.Response(200)
        )
        client = AsyncHttpClient(
            uri="https://example.com/",
            headers={"X-Default": "yes"},
        )
        try:
            await client.get("api/test", exclude_headers=True)
            req = route.calls[0].request
            assert req.headers.get("x-default") is None
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_basic_auth():
    """Test BasicAuthenticationCredentials integration."""
    with respx.mock:
        route = respx.get("https://example.com/api/test").mock(
            return_value=httpx.Response(200)
        )
        client = AsyncHttpClient(uri="https://example.com/")
        client.auth = BasicAuthenticationCredentials("user", "pass")
        try:
            await client.get("api/test")
            req = route.calls[0].request
            assert "authorization" in req.headers
            assert req.headers["authorization"].startswith("Basic ")
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_base_uri_without_trailing_slash():
    """Relative requests work when the base URI omits the trailing slash."""
    with respx.mock:
        respx.get("https://example.com/api/about").mock(
            return_value=httpx.Response(200, text="OK")
        )
        client = AsyncHttpClient(uri="https://example.com")
        try:
            resp = await client.get("api/about")
            assert resp.status_code == 200
        finally:
            await client.close()


def test_resolve_proxy_prefers_scheme_match():
    """Proxy resolution prefers scheme-specific entries before global fallbacks."""
    client = AsyncHttpClient(
        proxies={
            "all://": "http://proxy-all.local:8080",
            "https://": "http://proxy-https.local:8443",
        }
    )

    assert client._resolve_proxy("https://example.com/api") == "http://proxy-https.local:8443"
    assert client._resolve_proxy("http://example.com/api") == "http://proxy-all.local:8080"


def test_default_tls_resolution_keeps_legacy_mode_disabled():
    """The default uses httpx verification without enabling legacy TLS."""
    client = AsyncHttpClient()

    assert client.legacy_tls is False
    assert client._resolve_verify() is True


def test_ssl_context_is_preserved():
    """A caller-provided context is passed through unchanged."""
    context = ssl.create_default_context()
    client = AsyncHttpClient(tls_verify=context, legacy_tls=True)

    assert client._resolve_verify() is context


def test_ca_file_resolution_keeps_certificate_verification():
    """A CA-file path still creates a verified context."""
    client = AsyncHttpClient(tls_verify=certifi.where())

    context = client._resolve_verify()

    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_legacy_tls_builds_compatible_verified_context():
    """Legacy TLS lowers protocol and cipher restrictions without disabling verification."""
    client = AsyncHttpClient(legacy_tls=True)

    context = client._resolve_verify()

    assert isinstance(context, ssl.SSLContext)
    assert context.minimum_version == ssl.TLSVersion.TLSv1
    assert context.maximum_version == ssl.TLSVersion.MAXIMUM_SUPPORTED
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_legacy_tls_false_disables_context_verification():
    """Legacy TLS can explicitly disable certificate and hostname verification."""
    client = AsyncHttpClient(tls_verify=False, legacy_tls=True)

    context = client._resolve_verify()

    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_NONE
    assert context.check_hostname is False


def test_legacy_tls_passes_context_and_certificate_to_httpx():
    """HTTPX receives the generated verification context and existing client cert."""
    client = AsyncHttpClient(legacy_tls=True, tls_cert="client.pem")

    with patch("pyhaystack_async.client.http.client.httpx.AsyncClient") as async_client:
        client._build_httpx_client()

    kwargs = async_client.call_args.kwargs
    assert isinstance(kwargs["verify"], ssl.SSLContext)
    assert kwargs["cert"] == "client.pem"


def test_invalid_legacy_ca_file_raises():
    """Invalid CA-file configuration remains visible to the caller."""
    client = AsyncHttpClient(tls_verify="/missing/ca.pem", legacy_tls=True)

    with pytest.raises((OSError, ssl.SSLError)):
        client._resolve_verify()


@pytest.mark.asyncio
async def test_concurrent_requests_no_client_teardown():
    """Concurrent requests do not close a client that another task is using."""
    with respx.mock:
        respx.get("https://example.com/api/a").mock(
            return_value=httpx.Response(200, text="a")
        )
        respx.get("https://example.com/api/b").mock(
            return_value=httpx.Response(200, text="b")
        )
        client = AsyncHttpClient(uri="https://example.com/")
        try:
            resp_a, resp_b = await asyncio.gather(
                client.get("api/a"),
                client.get("api/b"),
            )
            assert resp_a.text == "a"
            assert resp_b.text == "b"
        finally:
            await client.close()
