"""Tests for session base and loader."""

from __future__ import annotations

import ssl
from unittest.mock import AsyncMock, patch

import hszinc
import pytest

from pyhaystack_async.client.http.client import HTTPResponse
from pyhaystack_async.client.loader import connect, get_implementation
from pyhaystack_async.client.niagara import (
    Niagara4HaystackSession,
    NiagaraHaystackSession,
)
from pyhaystack_async.client.session import HaystackSession
from pyhaystack_async.client.widesky import WideskyHaystackSession


class DummySession(HaystackSession):
    @property
    def is_logged_in(self) -> bool:
        return True

    async def _authenticate(self) -> None:
        return None

    async def logout(self) -> None:
        return None


def test_loader_alias_resolution():
    """Test that short aliases resolve to correct classes."""
    cls = get_implementation("widesky")
    assert cls.__name__ == "WideskyHaystackSession"

    cls = get_implementation("ax")
    assert cls.__name__ == "NiagaraHaystackSession"

    cls = get_implementation("n4")
    assert cls.__name__ == "Niagara4HaystackSession"

    cls = get_implementation("skyspark")
    assert cls.__name__ == "SkysparkScramHaystackSession"

    cls = get_implementation("skyspark2")
    assert cls.__name__ == "SkysparkHaystackSession"


def test_loader_connect_factory():
    """Test connect() creates session instances."""
    session = connect(
        "widesky",
        uri="https://example.com/",
        username="u",
        password="p",
        client_id="cid",
        client_secret="csecret",
    )
    assert session.__class__.__name__ == "WideskyHaystackSession"


def test_loader_unknown_raises():
    """Test unknown implementation raises ImportError."""
    with pytest.raises(ImportError):
        get_implementation("nonexistent_platform")


@pytest.mark.parametrize("session_class", [NiagaraHaystackSession, Niagara4HaystackSession])
def test_niagara_sessions_forward_tls_http_args(session_class):
    """Both Niagara session constructors retain the shared client's TLS settings."""
    context = ssl.create_default_context()
    session = session_class(
        uri="https://example.com/",
        username="u",
        password="p",
        http_args={"tls_verify": context, "legacy_tls": True},
    )

    assert session._client.tls_verify is context
    assert session._client.legacy_tls is True
    assert session._client._resolve_verify() is context


@pytest.mark.parametrize("session_class", [NiagaraHaystackSession, Niagara4HaystackSession])
def test_niagara_sessions_keep_secure_tls_defaults(session_class):
    """Niagara sessions retain modern verified TLS unless explicitly configured."""
    session = session_class(
        uri="https://example.com/",
        username="u",
        password="p",
    )

    assert session._client.legacy_tls is False
    assert session._client._resolve_verify() is True


@pytest.mark.asyncio
async def test_session_context_manager():
    """Test async context manager lifecycle."""
    session = connect(
        "widesky",
        uri="https://example.com/",
        username="u",
        password="p",
        client_id="cid",
        client_secret="csecret",
    )
    async with session:
        assert session._client is not None


def test_entity_creation():
    """Test Entity dataclass."""
    from pyhaystack_async.client.entity.entity import Entity

    e = Entity(session=None, entity_id="p:demo:r:123", tags={"dis": "Test", "site": True})
    assert e.id.name == "p:demo:r:123"
    assert e.dis == "Test"
    assert e.has_tag("site")
    assert not e.has_tag("equip")
    e._update_tags({"equip": True})
    assert e.has_tag("equip")


@pytest.mark.parametrize("mode", [hszinc.MODE_ZINC, hszinc.MODE_JSON])
def test_parse_grid_returns_grid(mode: str):
    """Test _parse_grid handles hszinc.parse() returning a single Grid."""
    session = DummySession("https://example.com/", "haystack")
    grid = hszinc.Grid()
    grid.column["dis"] = {}
    grid.append({"dis": "About"})

    body = hszinc.dump(grid, mode=mode)
    if isinstance(body, str):
        body = body.encode("utf-8")

    response = HTTPResponse(
        status_code=200,
        headers={"content-type": mode},
        body=body,
        cookies={},
    )

    parsed = session._parse_grid(response, mode)
    assert isinstance(parsed, hszinc.Grid)
    assert parsed[0]["dis"] == "About"


@pytest.mark.asyncio
async def test_widesky_session_accepts_relative_expires_in():
    """WideSky sessions treat OAuth2 expires_in durations as relative seconds."""
    session = WideskyHaystackSession(
        uri="https://ws.local",
        username="user",
        password="pass",
        client_id="cid",
        client_secret="csecret",
    )

    with patch(
        "pyhaystack_async.client.widesky.authenticate_widesky",
        new=AsyncMock(
            return_value={
                "token_type": "Bearer",
                "access_token": "token123",
                "expires_in": 3600,
            }
        ),
    ):
        try:
            await session._authenticate()
            assert session.is_logged_in is True
            assert session._client.headers == {"Authorization": "Bearer token123"}
        finally:
            await session.close()
