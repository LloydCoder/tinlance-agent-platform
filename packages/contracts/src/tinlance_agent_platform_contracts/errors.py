"""Shared error types at the Platform wire boundary."""


class PlatformAuthenticationFailure(PermissionError):
    """A credential or authenticated identity could not be verified."""
