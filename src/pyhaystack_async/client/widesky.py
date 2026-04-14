"""WideSky async session implementation (OAuth2 M2M)."""

from __future__ import annotations

from time import time
from typing import Any

from .http.client import HTTPResponse
from .mixins.widesky import CRUDMixin, MultiHisMixin, PasswordMixin
from .ops.widesky import authenticate_widesky
from .session import HaystackSession


class WideskyHaystackSession(CRUDMixin, MultiHisMixin, PasswordMixin, HaystackSession):
    """Async session for WideSky servers (OAuth2 password grant)."""

    def __init__(
        self,
        uri: str,
        username: str,
        password: str,
        client_id: str,
        client_secret: str,
        *,
        api_dir: str = "api",
        auth_dir: str = "oauth2/token",
        impersonate: str | None = None,
        **kwargs: Any,
    ):
        super().__init__(uri, api_dir, **kwargs)
        self._auth_dir = auth_dir
        self._username = username
        self._password = password
        self._client_id = client_id
        self._client_secret = client_secret
        self._auth_result: dict | None = None
        self._auth_expires_at: float | None = None
        self._impersonate = impersonate

    @property
    def is_logged_in(self) -> bool:
        if self._auth_result is None or self._auth_expires_at is None:
            return False
        return self._auth_expires_at > time()

    @staticmethod
    def _resolve_expiry_time(expires_in: Any) -> float | None:
        try:
            expiry_value = float(expires_in)
        except (TypeError, ValueError):
            return None

        if expiry_value <= 0:
            return None

        now = time()
        if expiry_value > (1000.0 * now):
            return expiry_value / 1000.0
        if expiry_value > now:
            return expiry_value
        return now + expiry_value

    async def _authenticate(self) -> None:
        result = await authenticate_widesky(
            self._client,
            self._username,
            self._password,
            self._client_id,
            self._client_secret,
            self._auth_dir,
        )
        self._auth_result = result
        self._auth_expires_at = self._resolve_expiry_time(result.get("expires_in"))
        token_type = result["token_type"]
        access_token = result["access_token"]
        headers = {"Authorization": f"{token_type} {access_token}"}
        if self._impersonate:
            headers["X-IMPERSONATE"] = self._impersonate
        self._client.headers = headers

    async def read(self, ids=None, filter_expr=None, limit=None) -> Any:
        """WideSky accepts 404 on reads."""
        return await super().read(
            ids=ids,
            filter_expr=filter_expr,
            limit=limit,
            accept_status={200, 404},
        )

    def _on_http_grid_response(self, response: HTTPResponse) -> None:
        """Clear auth on 401 so next request triggers re-authentication."""
        if response.status_code == 401 and self._auth_result is not None:
            self._log.warning("WideSky auth lost (HTTP 401)")
            self._auth_result = None
            self._auth_expires_at = None
            self._client.headers = {}

    def _on_auth_lost(self) -> None:
        self._auth_result = None
        self._auth_expires_at = None
        self._client.headers = {}

    async def logout(self) -> None:
        """WideSky tokens expire naturally; just clear local state."""
        self._auth_result = None
        self._auth_expires_at = None
        self._client.headers = {}
