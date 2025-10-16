"""
Exception classes for MCP PKI Authentication System.
"""

from typing import Optional


class MCPAuthError(Exception):
    """Base exception for all MCP authentication errors."""
    
    def __init__(self, message: str, error_code: Optional[str] = None) -> None:
        super().__init__(message)
        self.error_code = error_code


class AuthenticationError(MCPAuthError):
    """Raised when authentication fails."""
    
    def __init__(
        self, 
        message: str, 
        error_code: Optional[str] = None,
        failure_reason: Optional[str] = None
    ) -> None:
        super().__init__(message, error_code)
        self.failure_reason = failure_reason


class KeyError(MCPAuthError):
    """Raised when key operations fail."""
    pass


class InvalidKeyError(KeyError):
    """Raised when a key is invalid or corrupted."""
    pass


class KeyNotFoundError(KeyError):
    """Raised when a required key is not found."""
    pass


class DuplicateKeyError(KeyError):
    """Raised when attempting to add a duplicate key."""
    pass


class ConfigurationError(MCPAuthError):
    """Raised when configuration is invalid."""
    pass


class TimestampError(MCPAuthError):
    """Raised when timestamp validation fails."""
    
    def __init__(
        self, 
        message: str, 
        skew_seconds: Optional[float] = None,
        max_skew_seconds: Optional[float] = None
    ) -> None:
        super().__init__(message)
        self.skew_seconds = skew_seconds
        self.max_skew_seconds = max_skew_seconds


class NonceError(MCPAuthError):
    """Raised when nonce validation fails."""
    pass


class ReplayAttackError(NonceError):
    """Raised when a replay attack is detected."""
    pass


class ValidationError(MCPAuthError):
    """Raised when message or data validation fails."""
    pass


class ProtocolError(MCPAuthError):
    """Raised when protocol violations occur."""
    pass


class UnknownServerError(AuthenticationError):
    """Raised when connecting to an unknown server."""
    pass


class KeyMismatchError(AuthenticationError):
    """Raised when server key doesn't match expected key."""
    pass


class RateLimitError(MCPAuthError):
    """Raised when rate limits are exceeded."""
    
    def __init__(
        self, 
        message: str, 
        retry_after: Optional[float] = None
    ) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class TimeoutError(MCPAuthError):
    """Raised when authentication times out."""
    pass


class NetworkError(MCPAuthError):
    """Raised when network operations fail."""
    pass