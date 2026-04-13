"""Niagara encoding utilities mixin."""

from __future__ import annotations

import re

_ESCAPE_RE = re.compile(r"~([0-9a-fA-F]{2})")


def _unescape_match(m: re.Match) -> str:
    return bytes.fromhex(m.group(1)).decode("utf-8", errors="replace")


class EncodingMixin:
    """Mixin providing Niagara ~xy hex unescape."""

    @classmethod
    def unescape(cls, s: str) -> str:
        """Convert Niagara's ``~xy`` hex-encoded characters to readable UTF-8."""
        return _ESCAPE_RE.sub(_unescape_match, s)
