"""Tests for vendor auth flows using mocked HTTP."""

from __future__ import annotations

from base64 import standard_b64encode, urlsafe_b64encode
from binascii import unhexlify
from hashlib import sha256
from unittest.mock import patch

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


@pytest.mark.asyncio
async def test_niagara_ax_auth_failure_html_page():
    """NiagaraAX login fails when the login page is embedded in HTML."""
    from pyhaystack_async.client.ops.niagara_ax import authenticate_niagara_ax

    with respx.mock:
        respx.get("https://niagara.local/login").mock(
            return_value=httpx.Response(200, text="ok")
        )
        respx.post("https://niagara.local/login").mock(
            return_value=httpx.Response(
                200,
                text="<html><body>login page still showing</body></html>",
            )
        )

        client = AsyncHttpClient(uri="https://niagara.local/")
        try:
            with pytest.raises(IOError, match="login failed"):
                await authenticate_niagara_ax(client, "admin", "wrong")
        finally:
            await client.close()


# ---------------------------------------------------------------------------
# Niagara4 SCRAM
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_niagara4_scram_auth():
    """Niagara4 SCRAM authentication completes successfully."""
    from pyhaystack_async.client.ops.niagara4_scram import authenticate_niagara4_scram
    from pyhaystack_async.util import scram

    nonce = "nonce123"
    server_salt = standard_b64encode(b"salt").decode()
    server_first_msg = f"r={nonce}server,s={server_salt},i=4096"
    salted_pwd = scram.salted_password_hex_salt("73616c74", 4096, "sha256", "pass")
    client_first_msg = f"n=admin,r={nonce}"
    client_final_without_proof = f"c={standard_b64encode(b'n,,').decode()},r={nonce}server"
    auth_msg = f"{client_first_msg},{server_first_msg},{client_final_without_proof}"
    server_signature = scram.compute_server_signature(salted_pwd, auth_msg, sha256)
    server_final_msg = f"v={standard_b64encode(unhexlify(server_signature)).decode()}"

    def security_check(request: httpx.Request) -> httpx.Response:
        body = request.content.decode() if request.content else ""
        if body.startswith("action=sendClientFirstMessage"):
            return httpx.Response(
                200,
                text=server_first_msg,
                headers={"Set-Cookie": "JSESSIONID=abc123; Path=/"},
            )
        if body.startswith("action=sendClientFinalMessage"):
            return httpx.Response(200, text=server_final_msg)
        return httpx.Response(200)

    with patch(
        "pyhaystack_async.client.ops.niagara4_scram.scram.get_nonce_16",
        return_value=nonce,
    ):
        with respx.mock:
            respx.get("https://niagara.local/prelogin?clear=true").mock(
                return_value=httpx.Response(200)
            )
            respx.post("https://niagara.local/prelogin").mock(
                return_value=httpx.Response(200)
            )
            respx.post("https://niagara.local/j_security_check").mock(
                side_effect=security_check
            )

            client = AsyncHttpClient(uri="https://niagara.local")
            try:
                cookies = await authenticate_niagara4_scram(client, "admin", "pass")
                assert cookies == {"JSESSIONID": "abc123", "niagara_userid": "admin"}
            finally:
                await client.close()


@pytest.mark.asyncio
async def test_niagara4_scram_auth_signature_mismatch():
    """Niagara4 SCRAM rejects mismatched server signatures."""
    from pyhaystack_async.client.ops.niagara4_scram import authenticate_niagara4_scram

    nonce = "nonce123"
    server_salt = standard_b64encode(b"salt").decode()
    server_first_msg = f"r={nonce}server,s={server_salt},i=4096"

    def security_check(request: httpx.Request) -> httpx.Response:
        body = request.content.decode() if request.content else ""
        if body.startswith("action=sendClientFirstMessage"):
            return httpx.Response(
                200,
                text=server_first_msg,
                headers={"Set-Cookie": "JSESSIONID=abc123; Path=/"},
            )
        if body.startswith("action=sendClientFinalMessage"):
            return httpx.Response(200, text="v=ZmFrZQ==")
        return httpx.Response(200)

    with patch(
        "pyhaystack_async.client.ops.niagara4_scram.scram.get_nonce_16",
        return_value=nonce,
    ):
        with respx.mock:
            respx.get("https://niagara.local/prelogin?clear=true").mock(
                return_value=httpx.Response(200)
            )
            respx.post("https://niagara.local/prelogin").mock(
                return_value=httpx.Response(200)
            )
            respx.post("https://niagara.local/j_security_check").mock(
                side_effect=security_check
            )

            client = AsyncHttpClient(uri="https://niagara.local")
            try:
                with pytest.raises(ValueError, match="server signature mismatch"):
                    await authenticate_niagara4_scram(client, "admin", "pass")
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


@pytest.mark.asyncio
async def test_skyspark_legacy_auth_missing_param():
    """SkySpark legacy auth raises on malformed login parameter replies."""
    from pyhaystack_async.client.ops.skyspark_legacy import authenticate_skyspark

    with respx.mock:
        respx.get("https://sky.local/auth/demo/api?admin").mock(
            return_value=httpx.Response(
                200,
                text="username:admin\nuserSalt:abc123",
            )
        )

        client = AsyncHttpClient(uri="https://sky.local/")
        try:
            with pytest.raises(ValueError, match="missing nonce"):
                await authenticate_skyspark(client, "admin", "pass", "demo")
        finally:
            await client.close()


# ---------------------------------------------------------------------------
# SkySpark SCRAM
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_skyspark_scram_auth():
    """SkySpark SCRAM authentication completes the handshake and returns a bearer token."""
    from pyhaystack_async.client.ops.skyspark_scram import authenticate_skyspark_scram

    nonce = "nonce123"
    server_salt = urlsafe_b64encode(b"salt").decode().rstrip("=")
    server_first_msg = f"r={nonce}server,s={server_salt},i=4096"
    server_data = standard_b64encode(server_first_msg.encode()).decode().rstrip("=")

    def ui_callback(request: httpx.Request) -> httpx.Response:
        auth_header = request.headers["authorization"]
        if auth_header.startswith("HELLO username="):
            return httpx.Response(
                401,
                headers={"WWW-Authenticate": "handshakeToken=hs123, hash=SHA-256"},
            )
        if auth_header.startswith("SCRAM handshakeToken=hs123, data="):
            return httpx.Response(
                401,
                headers={"WWW-Authenticate": f"data={server_data}"},
            )
        if auth_header.startswith("scram handshaketoken=hs123,data="):
            return httpx.Response(
                200,
                headers={"Authentication-Info": "authToken=token123,key=attest123"},
            )
        raise AssertionError(f"Unexpected Authorization header: {auth_header!r}")

    with patch(
        "pyhaystack_async.client.ops.skyspark_scram.scram.get_nonce",
        return_value=nonce,
    ):
        with respx.mock:
            respx.get("https://sky.local/user/login").mock(
                return_value=httpx.Response(200, text="ok")
            )
            route = respx.get("https://sky.local/ui").mock(side_effect=ui_callback)

            client = AsyncHttpClient(uri="https://sky.local")
            try:
                headers = await authenticate_skyspark_scram(client, "admin", "pass")
                assert headers == {"Authorization": "Bearer authToken=token123"}
                assert route.call_count == 3
            finally:
                await client.close()


@pytest.mark.asyncio
async def test_skyspark_scram_auth_invalid_nonce():
    """SkySpark SCRAM rejects a server nonce that does not include the client nonce."""
    from pyhaystack_async.client.ops.skyspark_scram import authenticate_skyspark_scram

    nonce = "nonce123"
    server_salt = urlsafe_b64encode(b"salt").decode().rstrip("=")
    server_first_msg = f"r=wrongnonce,s={server_salt},i=4096"
    server_data = standard_b64encode(server_first_msg.encode()).decode().rstrip("=")

    def ui_callback(request: httpx.Request) -> httpx.Response:
        auth_header = request.headers["authorization"]
        if auth_header.startswith("HELLO username="):
            return httpx.Response(
                401,
                headers={"WWW-Authenticate": "handshakeToken=hs123, hash=SHA-256"},
            )
        if auth_header.startswith("SCRAM handshakeToken=hs123, data="):
            return httpx.Response(
                401,
                headers={"WWW-Authenticate": f"data={server_data}"},
            )
        raise AssertionError(f"Unexpected Authorization header: {auth_header!r}")

    with patch(
        "pyhaystack_async.client.ops.skyspark_scram.scram.get_nonce",
        return_value=nonce,
    ):
        with respx.mock:
            respx.get("https://sky.local/user/login").mock(
                return_value=httpx.Response(200, text="ok")
            )
            respx.get("https://sky.local/ui").mock(side_effect=ui_callback)

            client = AsyncHttpClient(uri="https://sky.local")
            try:
                with pytest.raises(ValueError, match="invalid nonce"):
                    await authenticate_skyspark_scram(client, "admin", "pass")
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
