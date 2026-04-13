"""WideSky OAuth2 async authentication.

Flow:
1. POST to auth_dir with Basic auth (client_id:client_secret)
   and JSON body {username, password, grant_type: "password"}
2. Parse JSON response for access_token, token_type, expires_in
"""

from __future__ import annotations

import base64
import json

from ...client.http.client import AsyncHttpClient


async def authenticate_widesky(
    client: AsyncHttpClient,
    username: str,
    password: str,
    client_id: str,
    client_secret: str,
    auth_dir: str,
) -> dict:
    """Perform WideSky OAuth2 password-grant authentication.

    Returns dict with token_type, access_token, expires_in, etc.
    """
    # Build auth header
    credentials = f"{client_id}:{client_secret}".encode()
    basic_auth = base64.b64encode(credentials).decode("ascii")

    auth_headers = {
        "Authorization": f"Basic {basic_auth}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    auth_body = json.dumps({
        "username": username,
        "password": password,
        "grant_type": "password",
    }).encode()

    resp = await client.request(
        "POST",
        auth_dir,
        body=auth_body,
        headers=auth_headers,
        exclude_headers=True,
        accept_status={200},
    )

    content_type = resp.content_type
    if content_type is None or content_type != "application/json":
        raise ValueError(f"WideSky auth: unexpected content type: {content_type}")

    reply = json.loads(resp.text)
    for key in ("token_type", "access_token", "expires_in"):
        if key not in reply:
            raise ValueError(f"WideSky auth: missing {key} in reply: {reply}")

    return reply
