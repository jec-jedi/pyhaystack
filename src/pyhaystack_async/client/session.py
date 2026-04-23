"""Core async Haystack session — base class for all vendor implementations."""

from __future__ import annotations

import asyncio
import logging
import weakref
from time import time
from typing import Any

import hszinc

from ..exception import HaystackError
from .http.client import AsyncHttpClient, HTTPResponse
from .http.exceptions import HTTPStatusError


class HaystackSession:
    """Async base session for Project Haystack servers.

    Subclasses must implement:
        - ``_authenticate`` — perform vendor-specific login
        - ``is_logged_in`` property
        - ``logout`` — optional cleanup
    """

    def __init__(
        self,
        uri: str,
        api_dir: str,
        *,
        grid_format: str = hszinc.MODE_ZINC,
        http_args: dict[str, Any] | None = None,
        log: logging.Logger | None = None,
        pint: bool = False,
        cache_expiry: float = 3600.0,
    ):
        if log is None:
            log = logging.getLogger(f"pyhaystack_async.{self.__class__.__name__}")
        self._log = log

        http_args = dict(http_args or {})
        if bool(http_args.pop("debug", None)) and "log" not in http_args:
            http_args["log"] = log.getChild("http")

        self._client = AsyncHttpClient(uri=uri, **http_args)
        self._api_dir = api_dir
        self._grid_format = grid_format

        # Auth state
        self._auth_lock = asyncio.Lock()
        self._auth_in_progress: asyncio.Task[None] | None = None

        # Entity cache (weakrefs)
        self._entities: weakref.WeakValueDictionary = weakref.WeakValueDictionary()

        # Grid cache
        self._cache_lock = asyncio.Lock()
        self._cache_expiry = cache_expiry
        self._grid_cache: dict[str, tuple[float, Any]] = {}

        hszinc.use_pint(pint)

    # --- Lifecycle ----------------------------------------------------------

    async def __aenter__(self) -> HaystackSession:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        try:
            await self.logout()
        except Exception:
            self._log.debug("Logout failed during __aexit__", exc_info=True)
        await self._client.close()

    async def close(self) -> None:
        await self._client.close()

    # --- Authentication -----------------------------------------------------

    @property
    def is_logged_in(self) -> bool:
        raise NotImplementedError

    async def authenticate(self) -> None:
        """Ensure we are logged in, performing auth if needed."""
        if self.is_logged_in:
            return
        async with self._auth_lock:
            # Double-check after acquiring lock
            if self.is_logged_in:
                return
            await self._authenticate()

    async def _authenticate(self) -> None:
        """Vendor-specific authentication. Must be overridden."""
        raise NotImplementedError

    async def logout(self) -> None:
        """Vendor-specific logout. Override if needed."""

    # --- High-level Haystack ops --------------------------------------------

    async def about(self, *, cache: bool = True) -> hszinc.Grid:
        return await self._get_grid("about", cache=cache)

    async def ops(self, *, cache: bool = True) -> hszinc.Grid:
        return await self._get_grid("ops", cache=cache)

    async def formats(self, *, cache: bool = True) -> hszinc.Grid:
        return await self._get_grid("formats", cache=cache)

    async def read(
        self,
        ids: str | hszinc.Ref | list[str | hszinc.Ref] | None = None,
        filter_expr: str | None = None,
        limit: int | None = None,
        accept_status: set[int] | None = None,
    ) -> hszinc.Grid:
        """Read entities by ID(s) or filter expression."""
        if ids is not None:
            if isinstance(ids, (str, hszinc.Ref)):
                ids = [ids]
            if filter_expr is not None:
                raise ValueError("Specify ids or filter_expr, not both")
            refs = [self._obj_to_ref(r) for r in ids]
            if len(refs) == 1:
                return await self._get_grid(
                    "read",
                    args={"id": refs[0]},
                    accept_status=accept_status,
                )
            else:
                grid = hszinc.Grid()
                grid.column["id"] = {}
                grid.extend([{"id": r} for r in refs])
                return await self._post_grid(
                    "read",
                    grid,
                    accept_status=accept_status,
                )
        else:
            args: dict[str, Any] = {"filter": filter_expr}
            if limit is not None:
                args["limit"] = int(limit)
            return await self._get_grid(
                "read",
                args=args,
                accept_status=accept_status,
            )

    async def nav(self, nav_id: str | None = None) -> hszinc.Grid:
        return await self._get_grid("nav", args={"nav_id": nav_id} if nav_id else None)

    async def watch_sub(
        self,
        points: list,
        *,
        watch_id: str | None = None,
        watch_dis: str | None = None,
        lease: int | None = None,
    ) -> hszinc.Grid:
        grid = hszinc.Grid()
        grid.column["id"] = {}
        grid.extend([{"id": self._obj_to_ref(p)} for p in points])
        if watch_id is not None:
            grid.metadata["watchId"] = watch_id
        if watch_dis is not None:
            grid.metadata["watchDis"] = watch_dis
        if lease is not None:
            grid.metadata["lease"] = lease
        return await self._post_grid("watchSub", grid)

    async def watch_unsub(
        self,
        watch: str,
        points: list | None = None,
    ) -> hszinc.Grid:
        grid = hszinc.Grid()
        grid.column["id"] = {}
        if points is not None:
            grid.extend([{"id": self._obj_to_ref(p)} for p in points])
        else:
            grid.metadata["close"] = hszinc.MARKER
        grid.metadata["watchId"] = watch
        return await self._post_grid("watchSub", grid)

    async def watch_poll(self, watch: str, *, refresh: bool = False) -> hszinc.Grid:
        grid = hszinc.Grid()
        grid.column["empty"] = {}
        grid.metadata["watchId"] = watch
        if refresh:
            grid.metadata["refresh"] = hszinc.MARKER
        return await self._post_grid("watchPoll", grid)

    async def point_write(
        self,
        point: str | hszinc.Ref,
        *,
        level: int | None = None,
        val: Any = None,
        who: str | None = None,
        duration: Any = None,
    ) -> hszinc.Grid:
        args: dict[str, Any] = {"id": self._obj_to_ref(point)}
        if level is not None:
            args["level"] = level
            args["val"] = val
            if who:
                args["who"] = who
            else:
                if self._client.auth and hasattr(self._client.auth, "username"):
                    args["who"] = self._client.auth.username
                else:
                    args["who"] = "pyhaystack-async"
            if duration:
                args["duration"] = duration
        return await self._get_grid("pointWrite", args=args)

    async def his_read(
        self,
        point: str | hszinc.Ref,
        rng: Any,
    ) -> hszinc.Grid:
        if isinstance(rng, slice):
            str_rng = ",".join(
                hszinc.dump_scalar(p) for p in (rng.start, rng.stop)
            )
        elif not isinstance(rng, str):
            str_rng = hszinc.dump_scalar(rng)
        else:
            str_rng = hszinc.dump_scalar(rng, mode=hszinc.MODE_ZINC)
        return await self._get_grid(
            "hisRead", args={"id": self._obj_to_ref(point), "range": str_rng}
        )

    async def his_write(
        self,
        point: str | hszinc.Ref,
        timestamp_records: dict | Any,
    ) -> hszinc.Grid:
        grid = hszinc.Grid()
        grid.metadata["id"] = self._obj_to_ref(point)
        grid.column["ts"] = {}
        grid.column["val"] = {}

        if hasattr(timestamp_records, "to_dict"):
            timestamp_records = timestamp_records.to_dict()

        records = sorted(timestamp_records.items(), key=lambda r: r[0])
        for ts, val in records:
            grid.append({"ts": ts, "val": val})
        return await self._post_grid("hisWrite", grid)

    async def invoke_action(
        self,
        entity: str | hszinc.Ref,
        action: str,
        **action_args: Any,
    ) -> hszinc.Grid:
        grid = hszinc.Grid()
        grid.metadata["id"] = self._obj_to_ref(entity)
        grid.metadata["action"] = action
        for arg in action_args:
            grid.column[arg] = {}
        grid.append(action_args)
        return await self._post_grid("invokeAction", grid)

    # --- Internal transport helpers -----------------------------------------

    async def _get(self, uri: str, *, api: bool = True, **kwargs: Any) -> HTTPResponse:
        if api:
            uri = f"{self._api_dir}/{uri}"
        return await self._client.get(uri, **kwargs)

    async def _post(
        self,
        uri: str,
        *,
        api: bool = True,
        body: bytes | str | None = None,
        body_type: str | None = None,
        **kwargs: Any,
    ) -> HTTPResponse:
        if api:
            uri = f"{self._api_dir}/{uri}"
        return await self._client.post(uri, body=body, body_type=body_type, **kwargs)

    async def _get_grid(
        self,
        uri: str,
        *,
        args: dict[str, Any] | None = None,
        cache: bool = False,
        cache_key: str | None = None,
        expect_format: str | None = None,
        accept_status: set[int] | None = None,
        exclude_cookies: bool | None = None,
        headers: dict[str, str] | None = None,
        retries: int = 2,
    ) -> hszinc.Grid:
        """GET a Haystack grid with auth-check and optional caching."""
        if expect_format is None:
            expect_format = self._grid_format

        if cache:
            key = cache_key or uri
            cached = await self._check_cache(key)
            if cached is not None:
                return cached

        await self.authenticate()

        # Build accept header
        req_headers = dict(headers or {})
        if expect_format == hszinc.MODE_ZINC:
            req_headers["Accept"] = "text/zinc"
        elif expect_format == hszinc.MODE_JSON:
            req_headers["Accept"] = "application/json"

        # Convert args to query params
        params: dict[str, str] | None = None
        if args:
            params = {
                k: hszinc.dump_scalar(v) if not isinstance(v, str) else v
                for k, v in args.items()
            }

        last_exc: Exception | None = None
        for attempt in range(retries + 1):
            try:
                response = await self._client.request(
                    "GET",
                    f"{self._api_dir}/{uri}",
                    params=params,
                    headers=req_headers,
                    accept_status=accept_status or {200, 404},
                    exclude_cookies=exclude_cookies,
                )
                self._on_http_grid_response(response)
                grid = self._parse_grid(response, expect_format)

                if cache:
                    await self._store_cache(cache_key or uri, grid)
                return grid
            except HTTPStatusError as e:
                last_exc = e
                if e.status == 401 and attempt < retries:
                    self._log.debug("Auth lost (401), re-authenticating…")
                    self._on_auth_lost()
                    await self.authenticate()
                    continue
                raise
            except Exception:
                raise

        assert last_exc is not None
        raise last_exc

    async def _post_grid(
        self,
        uri: str,
        grid: hszinc.Grid,
        *,
        post_format: str | None = None,
        expect_format: str | None = None,
        accept_status: set[int] | None = None,
        exclude_cookies: bool | None = None,
        headers: dict[str, str] | None = None,
        retries: int = 2,
    ) -> hszinc.Grid:
        """POST a Haystack grid with auth-check."""
        if post_format is None:
            post_format = self._grid_format
        if expect_format is None:
            expect_format = self._grid_format

        await self.authenticate()

        body = hszinc.dump(grid, mode=post_format)
        if isinstance(body, str):
            body = body.encode("utf-8")

        req_headers = dict(headers or {})
        if post_format == hszinc.MODE_ZINC:
            req_headers["Content-Type"] = "text/zinc; charset=utf-8"
        elif post_format == hszinc.MODE_JSON:
            req_headers["Content-Type"] = "application/json; charset=utf-8"
        if expect_format == hszinc.MODE_ZINC:
            req_headers["Accept"] = "text/zinc"
        elif expect_format == hszinc.MODE_JSON:
            req_headers["Accept"] = "application/json"

        last_exc: Exception | None = None
        for attempt in range(retries + 1):
            try:
                response = await self._client.request(
                    "POST",
                    f"{self._api_dir}/{uri}",
                    body=body,
                    headers=req_headers,
                    accept_status=accept_status or {200, 404},
                    exclude_cookies=exclude_cookies,
                )
                self._on_http_grid_response(response)
                return self._parse_grid(response, expect_format)
            except HTTPStatusError as e:
                last_exc = e
                if e.status == 401 and attempt < retries:
                    self._log.debug("Auth lost (401), re-authenticating…")
                    self._on_auth_lost()
                    await self.authenticate()
                    continue
                raise

        assert last_exc is not None
        raise last_exc

    # --- Grid parsing -------------------------------------------------------

    def _parse_grid(self, response: HTTPResponse, mode: str) -> hszinc.Grid:
        """Parse a Haystack grid from the HTTP response body."""
        grid = hszinc.parse(response.body.decode("utf-8", errors="replace"), mode=mode)
        if grid is None:
            raise HaystackError("Empty response from server")
        if "err" in grid.metadata:
            dis = grid.metadata.get("dis", "Unknown error")
            tb = grid.metadata.get("errTrace")
            raise HaystackError(str(dis), traceback=str(tb) if tb else None)
        return grid

    # --- Cache --------------------------------------------------------------

    async def _check_cache(self, key: str) -> hszinc.Grid | None:
        async with self._cache_lock:
            entry = self._grid_cache.get(key)
            if entry is None:
                return None
            expiry, grid = entry
            if time() > expiry:
                del self._grid_cache[key]
                return None
            return grid

    async def _store_cache(self, key: str, grid: hszinc.Grid) -> None:
        async with self._cache_lock:
            self._grid_cache[key] = (time() + self._cache_expiry, grid)

    # --- Hooks for subclasses -----------------------------------------------

    def _on_http_grid_response(self, response: HTTPResponse) -> None:
        """Hook for subclasses to inspect every grid response (e.g. WideSky 401)."""

    def _on_auth_lost(self) -> None:
        """Hook called when a 401 is detected during grid ops."""

    # --- Helpers ------------------------------------------------------------

    @staticmethod
    def _obj_to_ref(obj: Any) -> hszinc.Ref:
        if isinstance(obj, hszinc.Ref):
            return obj
        if isinstance(obj, str):
            return hszinc.Ref(obj)
        if hasattr(obj, "id"):
            return obj.id
        raise TypeError(f"Cannot convert {type(obj).__name__} to Ref")
