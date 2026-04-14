"""SkySpark legacy HMAC-SHA1 async authentication.

Flow:
1. GET /auth/<project>/api?<username> → parse username, userSalt, nonce
2. Compute HMAC-SHA1 digest
3. POST login with nonce + digest → extract cookie from response body
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re

from ...client.http.client import AsyncHttpClient

_COOKIE_RE = re.compile(r"^cookie[ \t]*:[ \t]*([^=]+)=(.*)$", re.IGNORECASE)


def _compute_digest(username: str, password: str, user_salt: str, nonce: str) -> str:
    """Compute SkySpark HMAC-SHA1 digest."""
    message = f"{username}:{user_salt}".encode()
    password_bytes = password.encode()

    hmac_result = base64.b64encode(
        hmac.new(key=password_bytes, msg=message, digestmod=hashlib.sha1).digest()
    )

    digest_msg = f"{hmac_result.decode()}:{nonce}".encode()
    digest = hashlib.sha1(digest_msg).digest()
    return base64.b64encode(digest).decode()


async def authenticate_skyspark(
    client: AsyncHttpClient,
    username: str,
    password: str,
    project: str,
) -> dict[str, str]:
    """Perform SkySpark legacy authentication.

    Returns cookies dict on success.
    """
    login_uri = f"auth/{project}/api?{username}"

    # Step 1: GET login params
    resp = await client.request(
        "GET",
        login_uri,
        cookies={},
        headers={},
        exclude_cookies=True,
        exclude_headers=True,
        accept_status={200},
    )

    login_params: dict[str, str] = {}
    for raw_line in resp.text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if ":" not in line:
            raise ValueError(f"SkySpark login failed — malformed login response line: {line!r}")
        key, value = line.split(":", 1)
        login_params[key.strip()] = value.strip()

    missing = [key for key in ("username", "userSalt", "nonce") if key not in login_params]
    if missing:
        missing_keys = ", ".join(missing)
        raise ValueError(f"SkySpark login failed — missing {missing_keys} in response")

    sk_username = login_params["username"]
    user_salt = login_params["userSalt"]
    nonce = login_params["nonce"]

    # Step 2: Compute digest
    digest = _compute_digest(sk_username, password, user_salt, nonce)

    # Step 3: POST login
    resp = await client.request(
        "POST",
        login_uri,
        body=f"nonce:{nonce}\ndigest:{digest}",
        headers={"Content-Type": "text/plain; charset=utf-8"},
        cookies={},
        exclude_cookies=True,
        exclude_headers=True,
        accept_status={200},
    )

    # Parse cookie from response body
    cookie_match = _COOKIE_RE.match(resp.text.strip())
    if not cookie_match:
        raise IOError("SkySpark login failed — no cookie in response")

    cookie_name, cookie_value = cookie_match.groups()
    return {cookie_name: cookie_value}
