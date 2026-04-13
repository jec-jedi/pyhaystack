"""SkySpark SCRAM-SHA256 async authentication with bearer token.

Flow:
1. GET /user/login → verify server available
2. GET /ui with HELLO header → get algorithm + handshakeToken from 401 WWW-Authenticate
3. GET /ui with SCRAM + clientFirstMessage → get server nonce/salt/iterations from 401
4. GET /ui with computed client proof → get authToken from Authentication-Info header
"""

from __future__ import annotations

from base64 import b64decode, standard_b64encode
from hashlib import sha1, sha256

from ...client.http.client import AsyncHttpClient
from ...client.http.exceptions import HTTPStatusError
from ...util import scram


async def authenticate_skyspark_scram(
    client: AsyncHttpClient,
    username: str,
    password: str,
) -> dict[str, str]:
    """Perform SkySpark SCRAM authentication.

    Returns headers dict with Authorization bearer token.
    """
    base_uri = client.uri or ""

    # Step 1: Test server availability
    await client.request(
        "GET",
        f"{base_uri}user/login",
        cookies={},
        headers={},
        exclude_cookies=True,
        exclude_headers=True,
        accept_status={200, 302},
    )

    # Step 2: HELLO handshake
    nonce = scram.get_nonce()
    salt_username = scram.base64_no_padding(username)
    hello_msg = f"HELLO username={salt_username}"

    try:
        await client.request(
            "GET",
            f"{base_uri}ui",
            headers={"Authorization": hello_msg},
            exclude_cookies=True,
            accept_status={401, 303},
        )
    except HTTPStatusError as e:
        if e.status not in (401, 303):
            raise
        server_response = e.headers.get("WWW-Authenticate", "")
        header_parts = server_response.split(",")
        algorithm_str = scram.regex_after_equal(header_parts[1]).replace("-", "").lower()

        if algorithm_str == "sha256":
            algorithm = sha256
            algorithm_name = "sha256"
        elif algorithm_str == "sha1":
            algorithm = sha1
            algorithm_name = "sha1"
        else:
            raise ValueError(f"Unsupported SCRAM algorithm: {algorithm_str}")

        handshake_token = scram.regex_after_equal(header_parts[0])

    # Step 3: SCRAM client second message
    client_second_msg = f"n={username},r={nonce}"
    client_second_msg_encoded = scram.base64_no_padding(client_second_msg)
    auth_header = f"SCRAM handshakeToken={handshake_token}, data={client_second_msg_encoded}"

    try:
        await client.request(
            "GET",
            f"{base_uri}ui",
            headers={"Authorization": auth_header},
            exclude_cookies=True,
            exclude_headers=True,
            accept_status={401, 303},
        )
    except HTTPStatusError as e:
        if e.status not in (401, 303):
            raise
        www_auth = e.headers.get("WWW-Authenticate", "")
        tab_header = www_auth.split(",")
        server_data = scram.regex_after_equal(tab_header[0])

        # Fix base64 padding
        missing = len(server_data) % 4
        if missing:
            server_data += "=" * (4 - missing)

        server_data_decoded = b64decode(server_data).decode()
        parts = server_data_decoded.split(",")
        server_first_msg = server_data_decoded
        server_nonce = scram.regex_after_equal(parts[0])
        server_salt = scram.regex_after_equal(parts[1])
        server_iterations = scram.regex_after_equal(parts[2])

        if not server_nonce.startswith(nonce):
            raise ValueError("SkySpark SCRAM: server returned invalid nonce")

    # Step 4: Compute client proof and send final message
    salted_pwd = scram.salted_password(
        server_salt, server_iterations, algorithm_name, password
    )

    client_final_no_proof = f"c={standard_b64encode(b'n,,').decode()},r={server_nonce}"
    auth_msg = f"{client_second_msg},{server_first_msg},{client_final_no_proof}"
    client_proof = scram.create_client_proof(salted_pwd, auth_msg, algorithm)

    client_final = f"{client_final_no_proof},p={client_proof}"
    client_final_b64 = scram.base64_no_padding(client_final)
    final_header = f"scram handshaketoken={handshake_token},data={client_final_b64}"

    resp = await client.request(
        "GET",
        f"{base_uri}ui",
        headers={"Authorization": final_header},
        exclude_cookies=True,
        exclude_headers=True,
        accept_status={200, 302},
    )

    # Extract authToken from Authentication-Info header
    auth_info = resp.headers.get("authentication-info", "")
    info_parts = auth_info.split(",")
    auth_token = scram.regex_after_equal(info_parts[0])

    return {"Authorization": f"Bearer authToken={auth_token}"}
