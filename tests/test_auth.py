"""Tests for vendor auth flows using mocked HTTP."""

from __future__ import annotations

import httpx
import pytest
import respx

from pyhaystack_async.client.http.client import AsyncHttpClient

# ---------------------------------------------------------------------------
# NiagaraAX
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_niagara_ax_auth():
    """Two-phase NiagaraAX authentication."""
    from pyhaystack_async.client.ops.niagara_ax import authenticate_niagara_ax

    with respx.mock:
        # Phase 1: GET /login → set session cookie
        respx.get("https://niagara.local/login").mock(
            return_value=httpx.Response(
                200,
                text="<html>session</html>",
                headers={
                    "set-cookie": "niagara_session=abc123; Path=/",
                },
            )
        )
        # Phase 2: POST /login → success (no "login" in response)
        respx.post("https://niagara.local/login").mock(
            return_value=httpx.Response(200, text="Welcome")
        )

        client = AsyncHttpClient(uri="https://niagara.local/")
        try:
            auth, cookies = await authenticate_niagara_ax(client, "admin", "secret")
            assert auth.username == "admin"
            assert auth.password == "secret"
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_niagara_ax_auth_failure():
    """NiagaraAX login fails when response contains 'login'."""
    from pyhaystack_async.client.ops.niagara_ax import authenticate_niagara_ax

    with respx.mock:
        respx.get("https://niagara.local/login").mock(
            return_value=httpx.Response(200, text="ok")
        )
        respx.post("https://niagara.local/login").mock(
            return_value=httpx.Response(200, text="login page still showing")
        )

        client = AsyncHttpClient(uri="https://niagara.local/")
        try:
            with pytest.raises(IOError, match="login failed"):
                await authenticate_niagara_ax(client, "admin", "wrong")
        finally:
            await client.close()


# ---------------------------------------------------------------------------
# SkySpark legacy
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_skyspark_legacy_auth():
    """SkySpark HMAC-SHA1 authentication."""
    from pyhaystack_async.client.ops.skyspark_legacy import authenticate_skyspark

    with respx.mock:
        respx.get("https://sky.local/auth/demo/api?admin").mock(
            return_value=httpx.Response(
                200,
                text="username:admin\nuserSalt:abc123\nnonce:xyz789",
            )
        )
        respx.post("https://sky.local/auth/demo/api?admin").mock(
            return_value=httpx.Response(200, text="cookie: skysparkSession=tok123")
        )

        client = AsyncHttpClient(uri="https://sky.local/")
        try:
            cookies = await authenticate_skyspark(client, "admin", "pass", "demo")
            assert "skysparkSession" in cookies
            assert cookies["skysparkSession"] == "tok123"
        finally:
            await client.close()


# ---------------------------------------------------------------------------
# WideSky OAuth2
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_widesky_auth():
    """WideSky OAuth2 password grant."""
    from pyhaystack_async.client.ops.widesky import authenticate_widesky

    token_response = {
        "token_type": "Bearer",
        "access_token": "test_access_token_123",
        "expires_in": 9999999999999,
        "refresh_token": "test_refresh",
    }

    with respx.mock:
        respx.post("https://ws.local/oauth2/token").mock(
            return_value=httpx.Response(
                200,
                json=token_response,
                headers={"Content-Type": "application/json"},
            )
        )

        client = AsyncHttpClient(uri="https://ws.local/")
        try:
            result = await authenticate_widesky(
                client, "user", "pass", "client_id", "client_secret", "oauth2/token"
            )
            assert result["token_type"] == "Bearer"
            assert result["access_token"] == "test_access_token_123"
            assert result["expires_in"] == 9999999999999
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_widesky_auth_missing_field():
    """WideSky auth raises on missing required fields."""
    from pyhaystack_async.client.ops.widesky import authenticate_widesky

    with respx.mock:
        respx.post("https://ws.local/oauth2/token").mock(
            return_value=httpx.Response(
                200,
                json={"token_type": "Bearer"},
                headers={"Content-Type": "application/json"},
            )
        )

        client = AsyncHttpClient(uri="https://ws.local/")
        try:
            with pytest.raises(ValueError, match="missing access_token"):
                await authenticate_widesky(
                    client, "user", "pass", "cid", "csecret", "oauth2/token"
                )
        finally:
            await client.close()
