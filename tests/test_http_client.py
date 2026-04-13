"""Tests for async HTTP client."""

from __future__ import annotations

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
