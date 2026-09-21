"""SkySpark SCRAM-SHA256 async authentication with bearer token.

Flow:
1. GET /user/auth with HELLO header → get algorithm + handshakeToken
2. GET /user/auth with SCRAM client-first message → get server nonce/salt/iterations
3. GET /user/auth with computed client proof → get authToken from Authentication-Info
"""

from __future__ import annotations

from base64 import b64decode, standard_b64encode
from hashlib import sha1, sha256

from ...client.http.client import AsyncHttpClient
from ...util import scram


def _challenge_header(headers: dict[str, str], name: str) -> str:
    value = headers.get(name)
    if not value:
        raise ValueError(f"SkySpark SCRAM: missing {name} header")
    return value


def _challenge_params(value: str) -> dict[str, str]:
    params: dict[str, str] = {}
    for part in value.split(","):
        if "=" not in part:
            continue
        key, param_value = part.strip().split("=", 1)
        params[key.rsplit(" ", 1)[-1].lower()] = param_value.strip()
    return params


async def authenticate_skyspark_scram(
    client: AsyncHttpClient,
    username: str,
    password: str,
) -> dict[str, str]:
    """Perform SkySpark SCRAM authentication.

    Returns headers dict with Authorization bearer token.
    """
    # Step 1: HELLO handshake
    nonce = scram.get_nonce()
    salt_username = scram.base64_no_padding(username)
    hello_msg = f"HELLO username={salt_username}"

    resp = await client.request(
        "GET",
        "user/auth",
        headers={"Authorization": hello_msg},
        exclude_cookies=True,
        exclude_headers=True,
        accept_status={401, 303},
    )
    if resp.status_code not in {401, 303}:
        raise ValueError(f"SkySpark SCRAM: expected challenge, got HTTP {resp.status_code}")

    server_response = _challenge_header(resp.headers, "www-authenticate")
    challenge = _challenge_params(server_response)
    algorithm_str = challenge.get("hash")
    if algorithm_str is None:
        header_parts = [part.strip() for part in server_response.split(",")]
        if len(header_parts) < 2:
            raise ValueError(f"SkySpark SCRAM: malformed challenge: {server_response!r}")
        algorithm_str = scram.regex_after_equal(header_parts[1])
    algorithm_str = algorithm_str.replace("-", "").lower()
    if algorithm_str == "sha256":
        algorithm = sha256
        algorithm_name = "sha256"
    elif algorithm_str == "sha1":
        algorithm = sha1
        algorithm_name = "sha1"
    else:
        raise ValueError(f"Unsupported SCRAM algorithm: {algorithm_str}")

    handshake_token = challenge.get("handshaketoken")
    if handshake_token is None:
        raise ValueError(f"SkySpark SCRAM: missing handshakeToken in {server_response!r}")

    # Step 2: SCRAM client-first message
    client_first_msg = f"n={username},r={nonce}"
    client_first_msg_encoded = scram.base64_no_padding(f"n,,{client_first_msg}")
    auth_header = f"SCRAM data={client_first_msg_encoded}, handshakeToken={handshake_token}"

    resp = await client.request(
        "GET",
        "user/auth",
        headers={"Authorization": auth_header},
        exclude_cookies=True,
        exclude_headers=True,
        accept_status={401, 303},
    )
    if resp.status_code not in {401, 303}:
        raise ValueError(
            f"SkySpark SCRAM: expected server-first message, got HTTP {resp.status_code}"
        )

    www_auth = _challenge_header(resp.headers, "www-authenticate")
    server_data = _challenge_params(www_auth).get("data")
    if server_data is None:
        raise ValueError(f"SkySpark SCRAM: missing server data in {www_auth!r}")

    missing = len(server_data) % 4
    if missing:
        server_data += "=" * (4 - missing)

    server_data_decoded = b64decode(server_data, altchars=b"-_").decode()
    parts = server_data_decoded.split(",")
    if len(parts) < 3:
        raise ValueError(f"SkySpark SCRAM: malformed server data: {server_data_decoded!r}")

    server_first_msg = server_data_decoded
    server_nonce = scram.regex_after_equal(parts[0])
    server_salt = scram.regex_after_equal(parts[1])
    server_iterations = scram.regex_after_equal(parts[2])

    if not server_nonce.startswith(nonce):
        raise ValueError("SkySpark SCRAM: server returned invalid nonce")

    # Step 4: Compute client proof and send final message
    salted_pwd = scram.salted_password(server_salt, server_iterations, algorithm_name, password)

    client_final_no_proof = f"c={standard_b64encode(b'n,,').decode()},r={server_nonce}"
    auth_msg = f"{client_first_msg},{server_first_msg},{client_final_no_proof}"
    client_proof = scram.create_client_proof(salted_pwd, auth_msg, algorithm)

    client_final = f"{client_final_no_proof},p={client_proof}"
    client_final_b64 = scram.base64_no_padding(client_final)
    final_header = f"scram handshaketoken={handshake_token},data={client_final_b64}"

    resp = await client.request(
        "GET",
        "user/auth",
        headers={"Authorization": final_header},
        exclude_cookies=True,
        exclude_headers=True,
        accept_status={200, 302},
    )

    # Extract authToken from Authentication-Info header
    auth_info = _challenge_header(resp.headers, "authentication-info")
    info_parts = auth_info.split(",")
    auth_token = scram.regex_after_equal(info_parts[0])

    return {"Authorization": f"Bearer authToken={auth_token}"}
