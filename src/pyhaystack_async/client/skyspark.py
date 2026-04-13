"""SkySpark async session implementations (legacy HMAC + SCRAM)."""

from __future__ import annotations

from typing import Any

import hszinc

from .mixins.skyspark import EvalMixin
from .ops.skyspark_legacy import authenticate_skyspark
from .ops.skyspark_scram import authenticate_skyspark_scram
from .session import HaystackSession


class SkysparkHaystackSession(EvalMixin, HaystackSession):
    """Async session for SkySpark servers (legacy HMAC-SHA1 auth)."""

    def __init__(
        self,
        uri: str,
        username: str,
        password: str,
        project: str = "",
        **kwargs: Any,
    ):
        super().__init__(uri, f"api/{project}", **kwargs)
        self._project = project
        self._username = username
        self._password = password
        self._authenticated = False

    @property
    def is_logged_in(self) -> bool:
        return self._authenticated

    async def _authenticate(self) -> None:
        cookies = await authenticate_skyspark(
            self._client, self._username, self._password, self._project
        )
        self._authenticated = True
        self._client.cookies = cookies

    async def logout(self) -> None:
        try:
            resp = await self._get("/user/logout", api=False)
            if resp.status_code != 200:
                self._log.warning("Failed to close SkySpark session (status=%d)", resp.status_code)
            else:
                self._log.info("SkySpark session closed")
        except Exception:
            self._log.warning("SkySpark logout failed", exc_info=True)
        finally:
            self._authenticated = False
            self._client.cookies = None

    def _on_auth_lost(self) -> None:
        self._authenticated = False
        self._client.cookies = None


class SkysparkScramHaystackSession(EvalMixin, HaystackSession):
    """Async session for SkySpark servers (SCRAM bearer-token auth).

    Defaults to exclude_cookies=True to prevent SkySpark from
    demanding attestation keys on cookie round-trips.
    """

    def __init__(
        self,
        uri: str,
        username: str,
        password: str,
        project: str,
        **kwargs: Any,
    ):
        super().__init__(uri, f"api/{project}", **kwargs)
        self._username = username
        self._password = password
        self._project = project
        self._authenticated = False

    @property
    def is_logged_in(self) -> bool:
        return self._authenticated

    async def _authenticate(self) -> None:
        auth_headers = await authenticate_skyspark_scram(
            self._client, self._username, self._password
        )
        self._authenticated = True
        self._client.cookies = None
        self._client.headers = auth_headers

    async def _get_grid(
        self, uri: str, *, exclude_cookies: bool | None = True, **kwargs: Any,
    ) -> hszinc.Grid:
        return await super()._get_grid(uri, exclude_cookies=exclude_cookies, **kwargs)

    async def _post_grid(
        self, uri: str, grid: hszinc.Grid, *,
        exclude_cookies: bool | None = True, **kwargs: Any,
    ) -> hszinc.Grid:
        return await super()._post_grid(
            uri, grid, exclude_cookies=exclude_cookies, **kwargs,
        )

    async def his_read(self, point, rng, **kwargs: Any) -> hszinc.Grid:
        """SkySpark requires POST for his_read by default."""
        grid = hszinc.Grid()
        grid.column["id"] = {}
        grid.column["range"] = {}
        if isinstance(rng, slice):
            str_rng = ",".join(hszinc.dump_scalar(p) for p in (rng.start, rng.stop))
        elif not isinstance(rng, str):
            str_rng = hszinc.dump_scalar(rng)
        else:
            str_rng = hszinc.dump_scalar(rng, mode=hszinc.MODE_ZINC)
        grid.append({"id": self._obj_to_ref(point), "range": str_rng})
        return await self._post_grid("hisRead", grid)

    async def logout(self) -> None:
        try:
            resp = await self._get("/user/logout", api=False)
            if resp.status_code != 200:
                self._log.warning(
                    "Failed to close SkySpark SCRAM session (status=%d)",
                    resp.status_code,
                )
            else:
                self._log.info("SkySpark SCRAM session closed")
        except Exception:
            self._log.warning("SkySpark SCRAM logout failed", exc_info=True)
        finally:
            self._authenticated = False
            self._client.headers = None

    def _on_auth_lost(self) -> None:
        self._authenticated = False
        self._client.headers = None
