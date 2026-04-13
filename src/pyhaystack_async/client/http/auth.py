"""Authentication credential containers."""

from dataclasses import dataclass


@dataclass
class AuthenticationCredentials:
    """Base class for auth credentials."""


@dataclass
class BasicAuthenticationCredentials(AuthenticationCredentials):
    """HTTP Basic authentication credentials."""
    username: str
    password: str


@dataclass
class DigestAuthenticationCredentials(AuthenticationCredentials):
    """HTTP Digest authentication credentials."""
    username: str
    password: str
