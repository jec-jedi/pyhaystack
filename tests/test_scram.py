"""Tests for SCRAM utilities."""

from __future__ import annotations

from hashlib import sha256

from pyhaystack_async.util.scram import (
    base64_no_padding,
    compute_server_signature,
    create_client_proof,
    get_nonce,
    get_nonce_16,
    regex_after_equal,
    salted_password,
    salted_password_hex_salt,
    xor_hex,
)


def test_get_nonce_length():
    n = get_nonce()
    assert len(n) == 64  # 32 bytes → 64 hex chars


def test_get_nonce_16_is_base64():
    n = get_nonce_16()
    assert isinstance(n, str)
    assert len(n) > 0


def test_base64_no_padding():
    result = base64_no_padding("admin")
    assert "=" not in result
    assert isinstance(result, str)


def test_regex_after_equal():
    assert regex_after_equal("key=value") == "value"
    assert regex_after_equal("r=abc123xyz") == "abc123xyz"


def test_xor_hex():
    assert xor_hex("ff", "00") == "ff"
    assert xor_hex("aa", "55") == "ff"
    assert xor_hex("ff", "ff") == "00"


def test_salted_password():
    """Basic smoke test for PBKDF2 derivation with b64 salt."""
    result = salted_password("dGVzdA==", 1, "sha256", "password")
    assert isinstance(result, str)
    assert len(result) > 0


def test_salted_password_hex_salt():
    """Basic smoke test for PBKDF2 derivation with hex salt."""
    result = salted_password_hex_salt("74657374", 1, "sha256", "password")
    assert isinstance(result, str)
    assert len(result) > 0


def test_create_client_proof_and_server_signature():
    """Verify client proof and server signature computation don't crash."""
    salt_pwd = salted_password("dGVzdA==", 4096, "sha256", "pencil")
    auth_msg = (
        "n=user,r=rOprNGfwEbeRWgbNEkqO,"
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,"
        "s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,c=biws,"
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
    )
    proof = create_client_proof(salt_pwd, auth_msg, sha256)
    assert isinstance(proof, str)

    sig = compute_server_signature(salt_pwd, auth_msg, sha256)
    assert isinstance(sig, str)
    assert len(sig) == 64  # sha256 hexdigest
