"""Tests for SkySpark SCRAM point writes."""

from __future__ import annotations

import hszinc
import httpx
import pytest
import respx

from pyhaystack_async.client.http.exceptions import HTTPStatusError
from pyhaystack_async.client.loader import get_implementation
from pyhaystack_async.client.skyspark import SkysparkScramHaystackSession

BASE_URI = "https://skyspark.example/"
POINT = "p:thgr:r:323bd44b-6c859c1a"


def _dump_grid(grid: hszinc.Grid) -> bytes:
    body = hszinc.dump(grid, mode=hszinc.MODE_ZINC)
    return body.encode("utf-8") if isinstance(body, str) else body


def _response_grid() -> bytes:
    grid = hszinc.Grid()
    grid.column["id"] = {}
    grid.append({"id": hszinc.Ref(POINT)})
    return _dump_grid(grid)


def test_skyspark_loader_alias():
    assert get_implementation("skyspark") is SkysparkScramHaystackSession


@pytest.mark.asyncio
async def test_skyspark_point_write_posts_zinc_grid():
    with respx.mock:
        route = respx.post(f"{BASE_URI}api/demo/pointWrite").mock(
            return_value=httpx.Response(
                200,
                content=_response_grid(),
                headers={"Content-Type": "text/zinc"},
            )
        )
        session = SkysparkScramHaystackSession(
            uri=BASE_URI,
            username="sky-user",
            password="secret",
            project="demo",
        )
        session._authenticated = True
        session._client.headers = {"Authorization": "Bearer token"}

        try:
            result = await session.point_write(
                POINT,
                level=8,
                val=12.5,
                duration="15min",
            )
        finally:
            await session.close()

        assert route.called
        request = route.calls[0].request
        assert request.method == "POST"
        assert request.headers["authorization"] == "Bearer token"
        assert request.headers["content-type"].startswith("text/zinc")
        assert request.headers["accept"] == "text/zinc"

        sent_grid = hszinc.parse(request.content.decode(), mode=hszinc.MODE_ZINC)
        row = sent_grid[0]
        assert row["id"].name == POINT
        assert row["level"] == 8
        assert row["val"] == 12.5
        assert row["who"] == "sky-user"
        assert row["duration"] == "15min"
        assert result[0]["id"].name == POINT


@pytest.mark.asyncio
async def test_skyspark_point_write_sends_attest_key():
    with respx.mock:
        route = respx.post(f"{BASE_URI}api/demo/pointWrite").mock(
            return_value=httpx.Response(
                200,
                content=_response_grid(),
                headers={"Content-Type": "text/zinc"},
            )
        )
        session = SkysparkScramHaystackSession(
            uri=BASE_URI,
            username="sky-user",
            password="secret",
            project="demo",
        )
        session._authenticated = True
        session._client.headers = {
            "Authorization": "Bearer authToken=token123",
            "Attest-Key": "attest123",
        }

        try:
            await session.point_write(POINT, level=8, val=12.5)
        finally:
            await session.close()

        request = route.calls[0].request
        assert request.headers["authorization"] == "Bearer authToken=token123"
        assert request.headers["attest-key"] == "attest123"
        assert "cookie" not in request.headers


@pytest.mark.asyncio
async def test_skyspark_point_write_omits_attest_key_when_absent():
    with respx.mock:
        route = respx.post(f"{BASE_URI}api/demo/pointWrite").mock(
            return_value=httpx.Response(
                200,
                content=_response_grid(),
                headers={"Content-Type": "text/zinc"},
            )
        )
        session = SkysparkScramHaystackSession(
            uri=BASE_URI,
            username="sky-user",
            password="secret",
            project="demo",
        )
        session._authenticated = True
        session._client.headers = {"Authorization": "Bearer authToken=token123"}

        try:
            await session.point_write(POINT, level=8, val=12.5)
        finally:
            await session.close()

        request = route.calls[0].request
        assert request.headers["authorization"] == "Bearer authToken=token123"
        assert "attest-key" not in request.headers


@pytest.mark.asyncio
async def test_skyspark_point_write_rebuilds_attestation_after_401():
    with respx.mock:
        route = respx.post(f"{BASE_URI}api/demo/pointWrite").mock(
            side_effect=[
                httpx.Response(401, text="expired"),
                httpx.Response(
                    200,
                    content=_response_grid(),
                    headers={"Content-Type": "text/zinc"},
                ),
            ]
        )
        session = SkysparkScramHaystackSession(
            uri=BASE_URI,
            username="sky-user",
            password="secret",
            project="demo",
        )
        session._authenticated = True
        session._client.headers = {
            "Authorization": "Bearer authToken=token123",
            "Attest-Key": "attest123",
        }

        async def _reauthenticate() -> None:
            session._authenticated = True
            session._client.headers = {
                "Authorization": "Bearer authToken=token456",
                "Attest-Key": "attest456",
            }

        session._authenticate = _reauthenticate  # type: ignore[method-assign]

        try:
            await session.point_write(POINT, level=8, val=12.5)
        finally:
            await session.close()

        assert route.call_count == 2
        first = route.calls[0].request
        second = route.calls[1].request
        assert first.headers["authorization"] == "Bearer authToken=token123"
        assert first.headers["attest-key"] == "attest123"
        assert second.headers["authorization"] == "Bearer authToken=token456"
        assert second.headers["attest-key"] == "attest456"


@pytest.mark.asyncio
async def test_skyspark_point_write_omits_write_fields_without_level():
    with respx.mock:
        route = respx.post(f"{BASE_URI}api/demo/pointWrite").mock(
            return_value=httpx.Response(200, content=_response_grid())
        )
        session = SkysparkScramHaystackSession(
            uri=BASE_URI,
            username="sky-user",
            password="secret",
            project="demo",
        )
        session._authenticated = True

        try:
            await session.point_write(POINT)
        finally:
            await session.close()

        sent_grid = hszinc.parse(route.calls[0].request.content.decode(), mode=hszinc.MODE_ZINC)
        assert list(sent_grid.column) == ["id"]
        assert sent_grid[0]["id"].name == POINT


@pytest.mark.asyncio
async def test_skyspark_point_write_raises_for_haystack_http_errors():
    with respx.mock:
        respx.post(f"{BASE_URI}api/demo/pointWrite").mock(
            return_value=httpx.Response(500, text="server error")
        )
        session = SkysparkScramHaystackSession(
            uri=BASE_URI,
            username="sky-user",
            password="secret",
            project="demo",
        )
        session._authenticated = True

        try:
            with pytest.raises(HTTPStatusError):
                await session.point_write(POINT, level=8, val=12.5)
        finally:
            await session.close()
