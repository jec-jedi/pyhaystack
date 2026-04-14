"""Niagara4 async SCRAM-SHA256 authentication.

Multi-step flow:
1. GET /prelogin?clear=true → prepare
2. POST /prelogin?j_username=<user> → receive params
3. POST /j_security_check (clientFirstMessage) → get server salt/nonce/iterations
4. POST /j_security_check (clientFinalMessage) → verify server signature
5. POST /j_security_check (validate) → confirm login
"""

from __future__ import annotations

import re
from base64 import b64decode, standard_b64encode
from binascii import hexlify
from hashlib import sha256

from ...client.http.client import AsyncHttpClient
from ...client.http.exceptions import HTTPStatusError
from ...util import scram

_JSESSIONID_RE = re.compile(r"JSESSIONID=([^;]+)")


def _get_jsessionid(set_cookie_header: str) -> str:
    """Extract JSESSIONID from Set-Cookie header."""
    m = _JSESSIONID_RE.search(set_cookie_header)
    if m is None:
        raise ValueError(f"No JSESSIONID in Set-Cookie: {set_cookie_header!r}")
    return m.group(1)


async def authenticate_niagara4_scram(
    client: AsyncHttpClient,
    username: str,
    password: str,
) -> dict[str, str]:
    """Perform Niagara4 SCRAM-SHA256 authentication.

    Returns cookies dict (JSESSIONID + niagara_userid) on success.
    """
    # Step 1: Clear prelogin state
    resp = await client.request(
        "GET",
        "prelogin?clear=true",
        cookies={},
        headers={},
        exclude_cookies=True,
        exclude_headers=True,
        accept_status={200},
    )
    if resp.status_code != 200:
        raise HTTPStatusError("Unable to connect to Niagara4 server", status=resp.status_code)

    # Step 2: Send username to prelogin
    await client.request(
        "POST",
        "prelogin",
        params={"j_username": username},
        cookies={},
        headers={},
        exclude_cookies=True,
        exclude_headers=True,
        accept_status={200, 302},
    )

    # Step 3: Client first message
    nonce = scram.get_nonce_16()
    client_first_msg = f"n={username},r={nonce}"

    msg_body = f"action=sendClientFirstMessage&clientFirstMessage=n,,{client_first_msg}"
    cookies_for_auth = {"niagara_userid": username}

    resp = await client.request(
        "POST",
        "j_security_check",
        body=msg_body.encode(),
        headers={"Content-Type": "application/x-niagara-login-support"},
        cookies=cookies_for_auth,
        accept_status={200, 302},
    )

    # Parse JSESSIONID from Set-Cookie
    set_cookie = resp.headers.get("set-cookie", "")
    jsessionid = _get_jsessionid(set_cookie)

    # Parse server first message
    server_first_msg = resp.body.decode("utf-8")
    parts = server_first_msg.split(",")
    server_nonce = scram.regex_after_equal(parts[0])
    server_salt = hexlify(b64decode(scram.regex_after_equal(parts[1]))).decode()
    server_iterations = scram.regex_after_equal(parts[2])

    # Step 4: Client final message
    salted_pwd = scram.salted_password_hex_salt(
        server_salt, server_iterations, "sha256", password
    )

    client_final_without_proof = f"c={standard_b64encode(b'n,,').decode()},r={server_nonce}"
    auth_msg = f"{client_first_msg},{server_first_msg},{client_final_without_proof}"
    client_proof = scram.create_client_proof(salted_pwd, auth_msg, sha256)

    client_final_message = f"{client_final_without_proof},p={client_proof}"
    final_body = f"action=sendClientFinalMessage&clientFinalMessage={client_final_message}"

    cookies_step4 = {"niagara_userid": username, "JSESSIONID": jsessionid}
    resp = await client.request(
        "POST",
        "j_security_check",
        body=final_body.strip().encode(),
        headers={"Content-Type": "application/x-niagara-login-support"},
        cookies=cookies_step4,
        accept_status={200, 302},
    )

    # Verify server signature
    server_final_msg = resp.body.decode("utf-8")
    expected_sig = scram.compute_server_signature(salted_pwd, auth_msg, sha256)
    remote_sig = hexlify(b64decode(scram.regex_after_equal(server_final_msg))).decode()

    if expected_sig != remote_sig:
        raise ValueError("Niagara4 SCRAM: server signature mismatch")

    # Step 5: Validate login
    result_cookies = {"JSESSIONID": jsessionid, "niagara_userid": username}
    client.cookies = result_cookies

    resp = await client.request(
        "POST",
        "j_security_check",
        body=None,
        headers={"Content-Type": "application/x-niagara-login-support"},
        accept_status={200},
    )
    if resp.status_code != 200:
        raise HTTPStatusError(
            "Niagara4 server refused final validation",
            status=resp.status_code,
        )

    return result_cookies
