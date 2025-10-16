"""
MCP PKI Authentication System

A mutual authentication system for the Model Context Protocol (MCP) using 
ed25519 public key infrastructure.
"""

__version__ = "1.0.0"
__author__ = "RAPID ARCHITECT"

from .exceptions import (
    MCPAuthError,
    AuthenticationError,
    KeyError as MCPKeyError,
    ConfigurationError,
    TimestampError,
    NonceError,
    ValidationError,
)

__all__ = [
    "__version__",
    "__author__",
    "MCPAuthError",
    "AuthenticationError", 
    "MCPKeyError",
    "ConfigurationError",
    "TimestampError",
    "NonceError",
    "ValidationError",
]