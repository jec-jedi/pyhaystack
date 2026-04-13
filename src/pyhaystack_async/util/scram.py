"""SCRAM authentication helpers.

Ported from the original pyhaystack implementation with Python 3.10+ cleanup.
"""

from __future__ import annotations

import hmac
import os
import re
from base64 import standard_b64encode, urlsafe_b64decode, urlsafe_b64encode
from binascii import hexlify, unhexlify
from hashlib import pbkdf2_hmac, sha256


def get_nonce() -> str:
    """Generate a 64-char hex nonce (32 random bytes)."""
    return os.urandom(32).hex()


def get_nonce_16() -> str:
    """Generate a URL-safe base64 nonce (16 random bytes)."""
    return urlsafe_b64encode(os.urandom(16)).decode()


def hash_sha256(data: bytes, algorithm=sha256) -> str:
    """Hash data with the given algorithm, return hex digest."""
    h = algorithm()
    h.update(data)
    return h.hexdigest()


def salted_password(
    salt: str, iterations: int | str, algorithm_name: str, password: str
) -> str:
    """Derive salted password using PBKDF2 with URL-safe base64 salt.

    Used by SkySpark SCRAM.
    """
    dk = pbkdf2_hmac(
        algorithm_name,
        password.encode(),
        urlsafe_b64decode(salt),
        int(iterations),
    )
    return hexlify(dk).decode()


def salted_password_hex_salt(
    salt: str, iterations: int | str, algorithm_name: str, password: str
) -> str:
    """Derive salted password using PBKDF2 with hex-encoded salt.

    Used by Niagara4 SCRAM.
    """
    dk = pbkdf2_hmac(
        algorithm_name,
        password.encode(),
        unhexlify(salt),
        int(iterations),
    )
    return hexlify(dk).decode()


def base64_no_padding(s: str) -> str:
    """URL-safe base64 encode a string, stripping padding."""
    return urlsafe_b64encode(s.encode()).decode().rstrip("=")


def regex_after_equal(s: str) -> str:
    """Extract the value after the first '=' in a string."""
    m = re.search(r"=(.*)$", s)
    if m is None:
        raise ValueError(f"No '=' found in: {s!r}")
    return m.group(1)


def xor_hex(s1: str, s2: str) -> str:
    """XOR two hex-encoded strings, return hex result."""
    result = int(s1, 16) ^ int(s2, 16)
    # Preserve leading zeros by using the length of the longer input
    length = max(len(s1), len(s2))
    return format(result, f"0{length}x")


def create_client_proof(salted_password_hex: str, auth_msg: str, algorithm) -> str:
    """Create SCRAM client proof for authentication."""
    client_key = hmac.new(
        unhexlify(salted_password_hex),
        b"Client Key",
        algorithm,
    ).hexdigest()

    stored_key = hash_sha256(unhexlify(client_key), algorithm)

    client_signature = hmac.new(
        unhexlify(stored_key),
        auth_msg.encode(),
        algorithm,
    ).hexdigest()

    client_proof_hex = xor_hex(client_key, client_signature)
    return standard_b64encode(unhexlify(client_proof_hex)).decode()


def compute_server_signature(salted_password_hex: str, auth_msg: str, algorithm) -> str:
    """Compute expected server signature for verification."""
    server_key = hmac.new(
        unhexlify(salted_password_hex),
        b"Server Key",
        algorithm,
    ).hexdigest()

    return hmac.new(
        unhexlify(server_key),
        auth_msg.encode(),
        algorithm,
    ).hexdigest()
