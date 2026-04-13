"""HTTP exception classes."""


class HTTPBaseError(IOError):
    """Base class for HTTP errors."""


class HTTPConnectionError(HTTPBaseError):
    """Failed to connect to host."""


class HTTPTimeoutError(HTTPConnectionError):
    """Request timed out."""


class HTTPRedirectError(HTTPBaseError):
    """Server redirections are looping."""


class HTTPStatusError(HTTPBaseError):
    """Server returned a failed HTTP status."""

    def __init__(
        self,
        message: str,
        status: int,
        headers: dict | None = None,
        body: bytes | None = None,
    ):
        self.status = status
        self.headers = headers or {}
        self.body = body
        super().__init__(message, status)
