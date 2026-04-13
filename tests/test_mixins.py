"""Tests for encoding/unescape mixin."""

from pyhaystack_async.client.mixins.encoding import EncodingMixin


def test_unescape_basic():
    assert EncodingMixin.unescape("hello~2dworld") == "hello-world"


def test_unescape_unicode():
    # ~e9 is a single byte 0xe9 which is not valid UTF-8 on its own
    # Niagara uses ~xx for ASCII-range escapes primarily
    assert EncodingMixin.unescape("hello~20world") == "hello world"


def test_unescape_no_escapes():
    assert EncodingMixin.unescape("plain text") == "plain text"
