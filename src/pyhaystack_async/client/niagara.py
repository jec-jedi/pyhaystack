"""NiagaraAX and Niagara4 async session implementations."""

from __future__ import annotations

from typing import Any

import hszinc

from .mixins.encoding import EncodingMixin
from .mixins.niagara import BQLMixin
from .ops.niagara4_scram import authenticate_niagara4_scram
from .ops.niagara_ax import authenticate_niagara_ax
from .session import HaystackSession


class NiagaraHaystackSession(BQLMixin, EncodingMixin, HaystackSession):
    """Async session for NiagaraAX servers (cookie-digest auth)."""

    def __init__(
        self,
        uri: str,
        username: str,
        password: str,
        **kwargs: Any,
    ):
        super().__init__(uri, "haystack", **kwargs)
        self._username = username
        self._password = password
        self._authenticated = False

    @property
    def is_logged_in(self) -> bool:
        return self._authenticated

    async def _authenticate(self) -> None:
        auth, cookies = await authenticate_niagara_ax(
            self._client, self._username, self._password
        )
        self._authenticated = True
        self._client.auth = auth
        self._client.cookies = cookies

    async def logout(self) -> None:
        try:
            resp = await self._get("/logout", api=False)
            if resp.status_code != 200:
                self._log.warning("Failed to close NiagaraAX session (status=%d)", resp.status_code)
            else:
                self._log.info("NiagaraAX session closed")
        except Exception:
            self._log.warning("NiagaraAX logout failed", exc_info=True)
        finally:
            self._authenticated = False
            self._client.auth = None
            self._client.cookies = None

    def _on_auth_lost(self) -> None:
        self._authenticated = False
        self._client.auth = None
        self._client.cookies = None


class Niagara4HaystackSession(BQLMixin, EncodingMixin, HaystackSession):
    """Async session for Niagara4 servers (SCRAM-SHA256 auth)."""

    def __init__(
        self,
        uri: str,
        username: str,
        password: str,
        *,
        grid_format: str = hszinc.MODE_JSON,
        **kwargs: Any,
    ):
        super().__init__(uri, "haystack", grid_format=grid_format, **kwargs)
        self._username = username
        self._password = password
        self._authenticated = False

    @property
    def is_logged_in(self) -> bool:
        return self._authenticated

    async def _authenticate(self) -> None:
        cookies = await authenticate_niagara4_scram(
            self._client, self._username, self._password
        )
        self._authenticated = True
        self._client.cookies = cookies

    async def logout(self) -> None:
        try:
            resp = await self._get("/logout", api=False)
            if resp.status_code != 200:
                self._log.warning("Failed to close Niagara4 session (status=%d)", resp.status_code)
            else:
                self._log.info("Niagara4 session closed")
        except Exception:
            self._log.warning("Niagara4 logout failed", exc_info=True)
        finally:
            self._authenticated = False
            self._client.auth = None
            self._client.cookies = None

    def _on_auth_lost(self) -> None:
        self._authenticated = False
        self._client.cookies = None
