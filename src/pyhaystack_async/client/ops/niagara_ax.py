"""NiagaraAX async authentication.

Two-phase login flow:
1. GET /login (no auth) → capture session cookies
2. POST /login with Basic auth + cookieDigest params → regex-validate response
"""

from __future__ import annotations

import re

from ...client.http.auth import BasicAuthenticationCredentials
from ...client.http.client import AsyncHttpClient

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
    # Phase 1: GET /login to obtain session cookie
    response = await client.request(
        "GET",
        "login",
        cookies={},
        headers={},
        exclude_cookies=True,
        exclude_headers=True,
        accept_status={200, 302, 404},
    )

    cookies = dict(response.cookies)

    # Phase 2: POST /login with Basic auth
    niagara_session = cookies.get("niagara_session", "")
    auth = BasicAuthenticationCredentials(username, password)

    login_resp = await client.request(
        "POST",
        "login",
        params={
            "token": "",
            "scheme": "cookieDigest",
            "absPathBase": "/",
            "content-type": "application/x-niagara-login-support",
            "Referer": f"{client.uri or ''}login/",
            "accept": "text/zinc; charset=utf-8",
            "cookiePostfix": niagara_session,
        },
        headers={},
        cookies=cookies,
        auth=auth,
        exclude_cookies=True,
        accept_status={200, 302, 404},
    )
    if login_resp.status_code == 404:
        return auth, cookies

    if _LOGIN_RE.search(login_resp.text):
        raise IOError("NiagaraAX login failed — response contains 'login'")

    # Merge any new cookies from login response
    cookies.update(login_resp.cookies)
    return auth, cookies
