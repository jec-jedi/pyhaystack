"""Tests for session base and loader."""

from __future__ import annotations

import hszinc
import pytest

from pyhaystack_async.client.loader import connect, get_implementation
from pyhaystack_async.client.http.client import HTTPResponse
from pyhaystack_async.client.session import HaystackSession


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
