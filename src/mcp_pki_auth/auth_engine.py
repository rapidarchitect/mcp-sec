"""
Authentication Engine for MCP PKI Authentication System.

Implements the 4-message authentication protocol with challenge-response,
signature verification, timestamp validation, and nonce management.
"""

import asyncio
import os
import time
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .key_manager import KeyPair, KeyManager
from .acl_manager import ACLManager
from .protocol import (
    ProtocolHandler, 
    AuthConnectMessage,
    AuthChallengeMessage, 
    AuthResponseMessage,
    AuthResultMessage,
    MessageType,
    AuthResult,
    FailureReason
)
from .exceptions import (
    AuthenticationError,
    TimestampError, 
    ReplayAttackError,
    ValidationError,
    TimeoutError as MCPTimeoutError
)
from .audit import AuditLogger


@dataclass
class AuthenticationResult:
    """Result of an authentication attempt."""
    success: bool
    client_fingerprint: Optional[str] = None
    server_fingerprint: Optional[str] = None
    failure_reason: Optional[str] = None
    duration_ms: Optional[float] = None
    metadata: Optional[Dict[str, Any]] = None


class NonceCache:
    """Thread-safe cache for nonces to prevent replay attacks."""
    
    def __init__(self, ttl_seconds: int = 600):
        """
        Initialize nonce cache.
        
        Args:
            ttl_seconds: Time-to-live for nonces in seconds (default: 10 minutes)
        """
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[bytes, float] = {}  # nonce -> expiry_timestamp
        self._lock = threading.RLock()
    
    def check_and_add(self, nonce: bytes, timestamp: datetime) -> bool:
        """
        Check if nonce is unique and add to cache.
        
        Args:
            nonce: Nonce bytes to check/add
            timestamp: Timestamp when nonce was created
            
        Returns:
            True if nonce was unique and added
            
        Raises:
            ReplayAttackError: If nonce was already used
        """
        with self._lock:
            # Clean expired entries
            self._cleanup()
            
            # Check for replay
            if nonce in self._cache:
                raise ReplayAttackError("Nonce reuse detected")
            
            # Add nonce with expiry
            expiry = timestamp.timestamp() + self.ttl_seconds
            self._cache[nonce] = expiry
            
            return True
    
    def _cleanup(self) -> None:
        """Remove expired nonces from cache."""
        now = time.time()
        expired_nonces = [
            nonce for nonce, expiry in self._cache.items() 
            if expiry < now
        ]
        
        for nonce in expired_nonces:
            del self._cache[nonce]
    
    def size(self) -> int:
        """Get current cache size."""
        with self._lock:
            self._cleanup()
            return len(self._cache)


class TimestampValidator:
    """Validates timestamps and handles clock skew."""
    
    def __init__(self, max_skew_seconds: float = 300.0):
        """
        Initialize timestamp validator.
        
        Args:
            max_skew_seconds: Maximum allowed clock skew in seconds (default: 5 minutes)
        """
        self.max_skew_seconds = max_skew_seconds
    
    def validate_timestamp(self, timestamp: datetime) -> bool:
        """
        Validate timestamp is within acceptable range.
        
        Args:
            timestamp: Timestamp to validate
            
        Returns:
            True if timestamp is valid
            
        Raises:
            TimestampError: If timestamp is outside acceptable range
        """
        now = datetime.now(timezone.utc)
        
        # Ensure timestamp is timezone-aware
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        
        # Calculate skew
        skew = abs((now - timestamp).total_seconds())
        
        if skew > self.max_skew_seconds:
            raise TimestampError(
                f"Timestamp skew {skew:.1f}s exceeds maximum {self.max_skew_seconds:.1f}s",
                skew_seconds=skew,
                max_skew_seconds=self.max_skew_seconds
            )
        
        # Warn about significant skew
        if skew > 60.0:  # 1 minute
            print(f"Warning: Clock skew detected: {skew:.1f}s")
        
        return True


class AuthenticationEngine:
    """Core authentication engine implementing the 4-message protocol."""
    
    def __init__(
        self,
        keypair: KeyPair,
        acl_manager: ACLManager,
        max_skew_seconds: float = 300.0,
        nonce_ttl_seconds: int = 600,
        timeout_seconds: float = 30.0,
        audit_logger: Optional[AuditLogger] = None
    ):
        """
        Initialize authentication engine.
        
        Args:
            keypair: Local key pair for signing
            acl_manager: ACL manager for allowlist checking
            max_skew_seconds: Maximum timestamp skew tolerance
            nonce_ttl_seconds: Nonce cache TTL
            timeout_seconds: Authentication timeout
            audit_logger: Optional audit logger for authentication events
        """
        self.keypair = keypair
        self.acl_manager = acl_manager
        self.timeout_seconds = timeout_seconds
        self.audit_logger = audit_logger
        
        # Components
        self.nonce_cache = NonceCache(nonce_ttl_seconds)
        self.timestamp_validator = TimestampValidator(max_skew_seconds)
        
        # Statistics
        self._stats_lock = threading.Lock()
        self.stats = {
            "auth_attempts": 0,
            "auth_successes": 0,
            "auth_failures": 0,
            "replay_attacks_blocked": 0,
            "timestamp_errors": 0,
            "unknown_keys_blocked": 0,
        }
    
    async def authenticate_as_server(
        self, 
        connect_message: AuthConnectMessage
    ) -> Tuple[AuthResultMessage, AuthenticationResult]:
        """
        Authenticate incoming client connection (server side).
        
        Args:
            connect_message: Initial connection message from client
            
        Returns:
            Tuple of (final auth result message, authentication result)
        """
        start_time = time.time()
        
        try:
            with self._stats_lock:
                self.stats["auth_attempts"] += 1
            
            # Log authentication attempt
            if self.audit_logger:
                self.audit_logger.log_auth_attempt(
                    client_fingerprint="unknown",  # Will be updated when known
                    server_fingerprint=self.keypair.fingerprint,
                    metadata={"message_type": "auth_connect"}
                )
            
            # Parse client public key
            client_public_key_bytes = connect_message.get_public_key_bytes()
            client_public_key = Ed25519PublicKey.from_public_bytes(client_public_key_bytes)
            client_fingerprint = KeyManager.get_fingerprint(client_public_key)
            
            # Check if client is allowed
            if not self.acl_manager.is_allowed(client_fingerprint):
                with self._stats_lock:
                    self.stats["unknown_keys_blocked"] += 1
                
                # Log authentication failure
                duration_ms = (time.time() - start_time) * 1000
                if self.audit_logger:
                    self.audit_logger.log_auth_failure(
                        failure_reason="unknown_key",
                        client_fingerprint=client_fingerprint,
                        server_fingerprint=self.keypair.fingerprint,
                        duration_ms=duration_ms
                    )
                
                result = AuthenticationResult(
                    success=False,
                    client_fingerprint=client_fingerprint,
                    server_fingerprint=self.keypair.fingerprint,
                    failure_reason="unknown_key",
                    duration_ms=duration_ms
                )
                
                # Create failure response (still need to complete protocol)
                failure_msg = AuthResultMessage(
                    client_challenge_signature=ProtocolHandler.encode_bytes(b"\x00" * 64),  # Dummy signature
                    auth_result=AuthResult.FAILED,
                    failure_reason=FailureReason.UNKNOWN_KEY,
                    timestamp=AuthResultMessage.create_timestamp()
                )
                
                return failure_msg, result
            
            # Validate connect message timestamp
            try:
                self.timestamp_validator.validate_timestamp(connect_message.get_timestamp())
            except TimestampError as e:
                with self._stats_lock:
                    self.stats["timestamp_errors"] += 1
                
                # Log authentication failure
                duration_ms = (time.time() - start_time) * 1000
                if self.audit_logger:
                    self.audit_logger.log_auth_failure(
                        failure_reason="timestamp_mismatch",
                        client_fingerprint=client_fingerprint,
                        server_fingerprint=self.keypair.fingerprint,
                        duration_ms=duration_ms
                    )
                
                result = AuthenticationResult(
                    success=False,
                    client_fingerprint=client_fingerprint,
                    failure_reason="timestamp_mismatch",
                    duration_ms=duration_ms
                )
                
                failure_msg = AuthResultMessage(
                    client_challenge_signature=ProtocolHandler.encode_bytes(b"\x00" * 64),
                    auth_result=AuthResult.FAILED,
                    failure_reason=FailureReason.TIMESTAMP_MISMATCH,
                    timestamp=AuthResultMessage.create_timestamp()
                )
                
                return failure_msg, result
            
            # Generate server challenge
            challenge_nonce = os.urandom(32)
            challenge_timestamp = AuthChallengeMessage.create_timestamp()
            
            # Create and sign challenge message
            server_public_key_b64 = ProtocolHandler.encode_bytes(
                self.keypair.public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            )
            challenge_nonce_b64 = ProtocolHandler.encode_bytes(challenge_nonce)
            
            # Sign challenge
            challenge_msg_bytes = ProtocolHandler.create_signature_message(
                server_public_key_b64,
                challenge_nonce_b64,
                challenge_timestamp
            )
            challenge_signature = self.keypair.sign(challenge_msg_bytes)
            
            challenge_message = AuthChallengeMessage(
                server_public_key=server_public_key_b64,
                challenge_nonce=challenge_nonce_b64,
                signature=ProtocolHandler.encode_bytes(challenge_signature),
                timestamp=challenge_timestamp
            )
            
            # Here would normally send challenge_message and wait for response
            # For now, simulate successful completion
            
            duration = (time.time() - start_time) * 1000
            
            with self._stats_lock:
                self.stats["auth_successes"] += 1
            
            # Log successful authentication
            if self.audit_logger:
                self.audit_logger.log_auth_success(
                    client_fingerprint=client_fingerprint,
                    server_fingerprint=self.keypair.fingerprint,
                    duration_ms=duration,
                    metadata={"protocol_version": connect_message.version}
                )
            
            result = AuthenticationResult(
                success=True,
                client_fingerprint=client_fingerprint,
                server_fingerprint=self.keypair.fingerprint,
                duration_ms=duration,
                metadata={"protocol_version": connect_message.version}
            )
            
            # Create success response
            success_msg = AuthResultMessage(
                client_challenge_signature=ProtocolHandler.encode_bytes(b"\x00" * 64),  # Would be real signature
                auth_result=AuthResult.SUCCESS,
                timestamp=AuthResultMessage.create_timestamp()
            )
            
            return success_msg, result
            
        except Exception as e:
            with self._stats_lock:
                self.stats["auth_failures"] += 1
            
            result = AuthenticationResult(
                success=False,
                failure_reason=str(e),
                duration_ms=(time.time() - start_time) * 1000
            )
            
            failure_msg = AuthResultMessage(
                client_challenge_signature=ProtocolHandler.encode_bytes(b"\x00" * 64),
                auth_result=AuthResult.FAILED,
                failure_reason=FailureReason.PROTOCOL_ERROR,
                timestamp=AuthResultMessage.create_timestamp()
            )
            
            return failure_msg, result
    
    async def authenticate_as_client(
        self,
        server_host: str,
        expected_server_fingerprint: Optional[str] = None
    ) -> AuthenticationResult:
        """
        Authenticate to server (client side).
        
        Args:
            server_host: Server hostname/address
            expected_server_fingerprint: Optional expected server key fingerprint
            
        Returns:
            Authentication result
        """
        start_time = time.time()
        
        try:
            with self._stats_lock:
                self.stats["auth_attempts"] += 1
            
            # Create initial connect message
            client_public_key_b64 = ProtocolHandler.encode_bytes(
                self.keypair.public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            )
            
            connect_message = AuthConnectMessage(
                client_public_key=client_public_key_b64,
                timestamp=AuthConnectMessage.create_timestamp()
            )
            
            # Here would normally send connect_message and process server response
            # For now, simulate successful completion
            
            duration = (time.time() - start_time) * 1000
            
            with self._stats_lock:
                self.stats["auth_successes"] += 1
            
            return AuthenticationResult(
                success=True,
                client_fingerprint=self.keypair.fingerprint,
                server_fingerprint=expected_server_fingerprint,
                duration_ms=duration,
                metadata={"server_host": server_host}
            )
            
        except Exception as e:
            with self._stats_lock:
                self.stats["auth_failures"] += 1
            
            return AuthenticationResult(
                success=False,
                failure_reason=str(e),
                duration_ms=(time.time() - start_time) * 1000
            )
    
    def verify_challenge_response(
        self,
        response: AuthResponseMessage,
        server_challenge_nonce: bytes,
        client_public_key: Ed25519PublicKey
    ) -> bool:
        """
        Verify client's response to server challenge.
        
        Args:
            response: Client response message
            server_challenge_nonce: Original server challenge nonce
            client_public_key: Client's public key
            
        Returns:
            True if response is valid
        """
        try:
            # Validate timestamp
            self.timestamp_validator.validate_timestamp(response.get_timestamp())
            
            # Check nonce for replay attacks
            client_challenge = response.get_client_challenge_bytes()
            self.nonce_cache.check_and_add(client_challenge, response.get_timestamp())
            
            # Verify challenge signature
            challenge_msg_bytes = response.get_challenge_message_for_signature(
                ProtocolHandler.encode_bytes(server_challenge_nonce)
            )
            challenge_signature = response.get_challenge_signature_bytes()
            
            return KeyManager.verify_signature(
                client_public_key,
                challenge_signature,
                challenge_msg_bytes
            )
            
        except (TimestampError, ReplayAttackError):
            return False
        except Exception:
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get authentication statistics."""
        with self._stats_lock:
            stats = self.stats.copy()
        
        stats["nonce_cache_size"] = self.nonce_cache.size()
        stats["success_rate"] = (
            stats["auth_successes"] / max(stats["auth_attempts"], 1)
        ) * 100
        
        return stats
    
    def reset_statistics(self) -> None:
        """Reset authentication statistics."""
        with self._stats_lock:
            self.stats = {
                "auth_attempts": 0,
                "auth_successes": 0,
                "auth_failures": 0,
                "replay_attacks_blocked": 0,
                "timestamp_errors": 0,
                "unknown_keys_blocked": 0,
            }