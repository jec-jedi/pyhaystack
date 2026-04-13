"""Custom exceptions for pyhaystack-async."""


class HaystackError(Exception):
    """Error grid returned by the Haystack server."""

    def __init__(self, message: str, traceback: str | None = None, *args, **kwargs):
        super().__init__(message, *args, **kwargs)
        self.traceback = traceback


class AuthenticationError(Exception):
    """Authentication with the Haystack server failed."""


class NotLoggedInError(Exception):
    """Operation attempted while not authenticated."""


class NoResponseFromServer(Exception):
    pass


class NoCookieReceived(Exception):
    pass


class UnknownHistoryType(Exception):
    pass
