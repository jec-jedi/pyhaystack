"""NiagaraAX async authentication.

Two-phase login flow:
1. GET /login (no auth) → capture session cookies
2. POST /login with Basic auth + cookieDigest params → regex-validate response
"""

from __future__ import annotations

import re

from ...client.http.auth import BasicAuthenticationCredentials
from ...client.http.client import AsyncHttpClient, HTTPResponse
from ...client.http.exceptions import HTTPStatusError

_LOGIN_RE = re.compile(r"login", re.IGNORECASE)


async def authenticate_niagara_ax(
    client: AsyncHttpClient,
    username: str,
    password: str,
) -> tuple[BasicAuthenticationCredentials, dict[str, str]]:
    """Perform NiagaraAX two-phase authentication.

    Returns (auth_credentials, cookies) on success.
    Raises on failure.
    """
    base_uri = client.uri or ""

    # Phase 1: GET /login to obtain session cookie
    try:
        response = await client.request(
            "GET",
            f"{base_uri}login",
            cookies={},
            headers={},
            exclude_cookies=True,
            exclude_headers=True,
            accept_status={200, 302, 404},
        )
    except HTTPStatusError as e:
        if e.status != 404:
            raise
        response = HTTPResponse(
            status_code=404, headers={}, body=b"", cookies={}
        )

    cookies = dict(response.cookies)

    # Phase 2: POST /login with Basic auth
    niagara_session = cookies.get("niagara_session", "")
    auth = BasicAuthenticationCredentials(username, password)

    try:
        login_resp = await client.request(
            "POST",
            f"{base_uri}login",
            params={
                "token": "",
                "scheme": "cookieDigest",
                "absPathBase": "/",
                "content-type": "application/x-niagara-login-support",
                "Referer": f"{base_uri}login/",
                "accept": "text/zinc; charset=utf-8",
                "cookiePostfix": niagara_session,
            },
            headers={},
            cookies=cookies,
            auth=auth,
            exclude_cookies=True,
            accept_status={200, 302, 404},
        )
    except HTTPStatusError as e:
        if e.status != 404:
            raise

        # 404 is acceptable for some NiagaraAX versions
        return auth, cookies

    if _LOGIN_RE.match(login_resp.text):
        raise IOError("NiagaraAX login failed — response contains 'login'")

    # Merge any new cookies from login response
    cookies.update(login_resp.cookies)
    return auth, cookies
