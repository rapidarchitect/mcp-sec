"""
Network transport layer for MCP PKI Authentication System.

Provides HTTP/HTTPS and WebSocket transport for authentication messages
with async/await support, connection pooling, and retry logic.
"""

import asyncio
import json
import uuid
from typing import Dict, Any, Optional, Callable, List, Union
from urllib.parse import urlparse
from dataclasses import dataclass
import ssl

import httpx
from websockets.client import connect as ws_connect
from websockets.exceptions import ConnectionClosed, InvalidURI

from .protocol import (
    ProtocolHandler,
    BaseAuthMessage,
    AuthConnectMessage,
    AuthChallengeMessage,
    AuthResponseMessage,
    AuthResultMessage,
    MessageType
)
from .exceptions import NetworkError, TimeoutError as MCPTimeoutError, ValidationError
from .audit import get_audit_logger, EventType, LogLevel


@dataclass
class TransportConfig:
    """Transport configuration."""
    timeout_seconds: float = 30.0
    max_retries: int = 3
    retry_delay_seconds: float = 1.0
    max_connections: int = 100
    verify_ssl: bool = True
    user_agent: str = "MCP-PKI-Auth/1.0"


class AuthenticationTransport:
    """Base class for authentication transports."""
    
    def __init__(self, config: Optional[TransportConfig] = None):
        self.config = config or TransportConfig()
        self.session_id = str(uuid.uuid4())
        self._audit_logger = get_audit_logger()
    
    async def send_message(self, url: str, message: BaseAuthMessage) -> BaseAuthMessage:
        """Send authentication message and receive response."""
        raise NotImplementedError
    
    async def close(self) -> None:
        """Close transport and cleanup resources."""
        pass
    
    def _log_transport_event(self, event_type: str, message: str, **kwargs):
        """Log transport events to audit logger."""
        if self._audit_logger:
            self._audit_logger.log_event({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": event_type,
                "level": LogLevel.DEBUG,
                "message": message,
                "component": "transport",
                "session_id": self.session_id,
                **kwargs
            })


class HTTPTransport(AuthenticationTransport):
    """HTTP/HTTPS transport for MCP authentication messages."""
    
    def __init__(self, config: Optional[TransportConfig] = None):
        super().__init__(config)
        self._client: Optional[httpx.AsyncClient] = None
        self._setup_client()
    
    def _setup_client(self) -> None:
        """Setup HTTP client with connection pooling."""
        limits = httpx.Limits(
            max_keepalive_connections=self.config.max_connections,
            max_connections=self.config.max_connections,
            keepalive_expiry=30.0
        )
        
        timeout = httpx.Timeout(
            timeout=self.config.timeout_seconds,
            connect=10.0,
            read=self.config.timeout_seconds,
            write=10.0,
            pool=5.0
        )
        
        # SSL context
        ssl_context = ssl.create_default_context() if self.config.verify_ssl else False
        
        self._client = httpx.AsyncClient(
            limits=limits,
            timeout=timeout,
            verify=ssl_context,
            headers={
                "User-Agent": self.config.user_agent,
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
        )
    
    async def send_message(self, url: str, message: BaseAuthMessage) -> BaseAuthMessage:
        """Send HTTP POST with authentication message."""
        if not self._client:
            raise NetworkError("HTTP client not initialized")
        
        # Serialize message
        message_data = ProtocolHandler.serialize_message(message)
        
        retry_count = 0
        last_exception = None
        
        while retry_count <= self.config.max_retries:
            try:
                # Log attempt
                if self._audit_logger:
                    self._audit_logger.log_event({
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "event_type": "transport_request",
                        "level": LogLevel.DEBUG,
                        "message": f"Sending {message.type} to {url}",
                        "component": "transport",
                        "session_id": self.session_id,
                        "metadata": {
                            "url": url,
                            "message_type": message.type,
                            "retry_count": retry_count
                        }
                    })
                
                # Send request
                response = await self._client.post(url, content=message_data)
                response.raise_for_status()
                
                # Parse response
                response_message = ProtocolHandler.deserialize_message(response.content)
                
                # Log success
                if self._audit_logger:
                    self._audit_logger.log_event({
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "event_type": "transport_response",
                        "level": LogLevel.DEBUG,
                        "message": f"Received {response_message.type} from {url}",
                        "component": "transport",
                        "session_id": self.session_id,
                        "metadata": {
                            "url": url,
                            "response_message_type": response_message.type,
                            "status_code": response.status_code
                        }
                    })
                
                return response_message
                
            except httpx.TimeoutException as e:
                last_exception = MCPTimeoutError(f"HTTP request timed out: {e}")
            except httpx.HTTPStatusError as e:
                if e.response.status_code >= 500 and retry_count < self.config.max_retries:
                    # Retry server errors
                    last_exception = NetworkError(f"HTTP {e.response.status_code}: {e.response.text}")
                else:
                    # Don't retry client errors
                    raise NetworkError(f"HTTP {e.response.status_code}: {e.response.text}")
            except (httpx.RequestError, httpx.ConnectError) as e:
                last_exception = NetworkError(f"HTTP request failed: {e}")
            except ValidationError as e:
                # Don't retry validation errors
                raise e
            except Exception as e:
                last_exception = NetworkError(f"Unexpected error: {e}")
            
            # Wait before retry
            if retry_count < self.config.max_retries:
                await asyncio.sleep(self.config.retry_delay_seconds * (2 ** retry_count))
            
            retry_count += 1
        
        # All retries exhausted
        if last_exception:
            raise last_exception
        else:
            raise NetworkError("All retry attempts failed")
    
    async def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None


class WebSocketTransport(AuthenticationTransport):
    """WebSocket transport for persistent MCP authentication connections."""
    
    def __init__(self, config: Optional[TransportConfig] = None):
        super().__init__(config)
        self._connections: Dict[str, Any] = {}  # URL -> WebSocket connection
        self._response_handlers: Dict[str, asyncio.Queue] = {}  # message_id -> response queue
    
    async def _get_connection(self, url: str):
        """Get or create WebSocket connection to URL."""
        if url not in self._connections:
            try:
                # Parse WebSocket URL
                parsed = urlparse(url)
                if parsed.scheme not in ('ws', 'wss'):
                    raise NetworkError(f"Invalid WebSocket URL scheme: {parsed.scheme}")
                
                # Create SSL context for wss://
                ssl_context = None
                if parsed.scheme == 'wss':
                    ssl_context = ssl.create_default_context() if self.config.verify_ssl else ssl.SSLContext()
                    if not self.config.verify_ssl:
                        ssl_context.check_hostname = False
                        ssl_context.verify_mode = ssl.CERT_NONE
                
                # Connect
                connection = await ws_connect(
                    url,
                    ssl=ssl_context,
                    ping_interval=20,
                    ping_timeout=10,
                    close_timeout=10,
                    user_agent_header=self.config.user_agent
                )
                
                self._connections[url] = connection
                
                # Start message handler task
                asyncio.create_task(self._handle_messages(url, connection))
                
                if self._audit_logger:
                    self._audit_logger.log_event({
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "event_type": "websocket_connected",
                        "level": LogLevel.INFO,
                        "message": f"WebSocket connected to {url}",
                        "component": "transport",
                        "session_id": self.session_id,
                        "metadata": {"url": url}
                    })
                
            except (ConnectionClosed, InvalidURI, OSError) as e:
                raise NetworkError(f"WebSocket connection failed: {e}")
        
        return self._connections[url]
    
    async def _handle_messages(self, url: str, connection):
        """Handle incoming WebSocket messages."""
        try:
            async for raw_message in connection:
                try:
                    # Parse message
                    message = ProtocolHandler.deserialize_message(raw_message)
                    
                    # Extract message ID from metadata
                    message_id = getattr(message, 'metadata', {}).get('message_id')
                    
                    if message_id and message_id in self._response_handlers:
                        # Put response in appropriate queue
                        await self._response_handlers[message_id].put(message)
                    else:
                        # Unexpected message
                        if self._audit_logger:
                            self._audit_logger.log_event({
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "event_type": "websocket_unexpected_message",
                                "level": LogLevel.WARNING,
                                "message": f"Unexpected WebSocket message: {message.type}",
                                "component": "transport",
                                "session_id": self.session_id,
                                "metadata": {
                                    "url": url,
                                    "message_type": message.type,
                                    "message_id": message_id
                                }
                            })
                
                except Exception as e:
                    if self._audit_logger:
                        self._audit_logger.log_event({
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "event_type": "websocket_message_error",
                            "level": LogLevel.ERROR,
                            "message": f"WebSocket message handling error: {e}",
                            "component": "transport",
                            "session_id": self.session_id,
                            "metadata": {"url": url, "error": str(e)}
                        })
                        
        except ConnectionClosed:
            # Connection closed, cleanup
            if url in self._connections:
                del self._connections[url]
            
            if self._audit_logger:
                self._audit_logger.log_event({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event_type": "websocket_disconnected",
                    "level": LogLevel.INFO,
                    "message": f"WebSocket disconnected from {url}",
                    "component": "transport",
                    "session_id": self.session_id,
                    "metadata": {"url": url}
                })
    
    async def send_message(self, url: str, message: BaseAuthMessage) -> BaseAuthMessage:
        """Send WebSocket message and wait for response."""
        # Generate unique message ID
        message_id = str(uuid.uuid4())
        
        # Add message ID to metadata
        if not hasattr(message, 'metadata'):
            message.metadata = {}
        if message.metadata is None:
            message.metadata = {}
        message.metadata['message_id'] = message_id
        
        # Setup response handler
        response_queue = asyncio.Queue()
        self._response_handlers[message_id] = response_queue
        
        try:
            # Get connection
            connection = await self._get_connection(url)
            
            # Serialize and send message
            message_data = ProtocolHandler.serialize_message(message)
            await connection.send(message_data)
            
            if self._audit_logger:
                self._audit_logger.log_event({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event_type": "websocket_message_sent",
                    "level": LogLevel.DEBUG,
                    "message": f"Sent {message.type} via WebSocket",
                    "component": "transport",
                    "session_id": self.session_id,
                    "metadata": {
                        "url": url,
                        "message_type": message.type,
                        "message_id": message_id
                    }
                })
            
            # Wait for response
            try:
                response = await asyncio.wait_for(
                    response_queue.get(),
                    timeout=self.config.timeout_seconds
                )
                
                if self._audit_logger:
                    self._audit_logger.log_event({
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "event_type": "websocket_message_received",
                        "level": LogLevel.DEBUG,
                        "message": f"Received {response.type} via WebSocket",
                        "component": "transport",
                        "session_id": self.session_id,
                        "metadata": {
                            "url": url,
                            "response_type": response.type,
                            "message_id": message_id
                        }
                    })
                
                return response
                
            except asyncio.TimeoutError:
                raise MCPTimeoutError(f"WebSocket response timeout for {message.type}")
        
        finally:
            # Cleanup response handler
            if message_id in self._response_handlers:
                del self._response_handlers[message_id]
    
    async def close(self) -> None:
        """Close all WebSocket connections."""
        for connection in self._connections.values():
            await connection.close()
        
        self._connections.clear()
        self._response_handlers.clear()


class TransportManager:
    """Manages multiple transport types and routing."""
    
    def __init__(self, config: Optional[TransportConfig] = None):
        self.config = config or TransportConfig()
        self._transports: Dict[str, AuthenticationTransport] = {}
    
    def _get_transport(self, url: str) -> AuthenticationTransport:
        """Get appropriate transport for URL."""
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        
        if scheme in ('ws', 'wss'):
            if 'websocket' not in self._transports:
                self._transports['websocket'] = WebSocketTransport(self.config)
            return self._transports['websocket']
        
        elif scheme in ('http', 'https'):
            if 'http' not in self._transports:
                self._transports['http'] = HTTPTransport(self.config)
            return self._transports['http']
        
        else:
            raise NetworkError(f"Unsupported URL scheme: {scheme}")
    
    async def send_message(self, url: str, message: BaseAuthMessage) -> BaseAuthMessage:
        """Send message using appropriate transport."""
        transport = self._get_transport(url)
        return await transport.send_message(url, message)
    
    async def close(self) -> None:
        """Close all transports."""
        for transport in self._transports.values():
            await transport.close()
        
        self._transports.clear()


class AuthenticationClient:
    """High-level client for MCP authentication over network."""
    
    def __init__(
        self,
        transport_config: Optional[TransportConfig] = None,
        default_server_url: Optional[str] = None
    ):
        self.transport_manager = TransportManager(transport_config)
        self.default_server_url = default_server_url
        self._audit_logger = get_audit_logger()
    
    async def authenticate(
        self,
        client_keypair,
        server_url: Optional[str] = None,
        expected_server_fingerprint: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Perform complete authentication flow over network.
        
        Args:
            client_keypair: Client's KeyPair for signing
            server_url: Server URL (uses default if None)
            expected_server_fingerprint: Expected server key fingerprint
            
        Returns:
            Authentication result with metadata
        """
        url = server_url or self.default_server_url
        if not url:
            raise ValueError("No server URL provided")
        
        session_id = str(uuid.uuid4())
        start_time = time.perf_counter()
        
        try:
            # Log authentication start
            if self._audit_logger:
                self._audit_logger.log_auth_attempt(
                    client_fingerprint=client_keypair.fingerprint,
                    session_id=session_id,
                    metadata={
                        "server_url": url,
                        "expected_server_fingerprint": expected_server_fingerprint
                    }
                )
            
            # Step 1: Send connection request
            from .protocol import ProtocolHandler
            client_public_key_b64 = ProtocolHandler.encode_bytes(
                client_keypair.public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            )
            
            connect_message = AuthConnectMessage(
                client_public_key=client_public_key_b64,
                timestamp=AuthConnectMessage.create_timestamp()
            )
            
            # Send connect message and receive challenge
            challenge_message = await self.transport_manager.send_message(url, connect_message)
            
            if not isinstance(challenge_message, AuthChallengeMessage):
                raise ValidationError(f"Expected AuthChallengeMessage, got {type(challenge_message)}")
            
            # Step 2: Verify server challenge and respond
            server_public_key_bytes = challenge_message.get_server_public_key_bytes()
            server_fingerprint = KeyManager.get_fingerprint(server_public_key_bytes)
            
            # Check expected fingerprint
            if expected_server_fingerprint and server_fingerprint != expected_server_fingerprint:
                raise KeyMismatchError(
                    f"Server fingerprint {server_fingerprint} doesn't match expected {expected_server_fingerprint}"
                )
            
            # Verify server's challenge signature
            challenge_msg_bytes = challenge_message.get_message_for_signature()
            if not KeyManager.verify_signature(
                Ed25519PublicKey.from_public_bytes(server_public_key_bytes),
                challenge_message.get_signature_bytes(),
                challenge_msg_bytes
            ):
                raise AuthenticationError("Invalid server challenge signature")
            
            # Create client response
            import os
            client_challenge = os.urandom(32)
            response_timestamp = AuthResponseMessage.create_timestamp()
            
            # Sign server's challenge
            challenge_signature = client_keypair.sign(
                ProtocolHandler.create_signature_message(
                    challenge_message.challenge_nonce,
                    response_timestamp
                )
            )
            
            response_message = AuthResponseMessage(
                challenge_signature=ProtocolHandler.encode_bytes(challenge_signature),
                client_challenge=ProtocolHandler.encode_bytes(client_challenge),
                timestamp=response_timestamp
            )
            
            # Step 3: Send response and receive final result
            result_message = await self.transport_manager.send_message(url, response_message)
            
            if not isinstance(result_message, AuthResultMessage):
                raise ValidationError(f"Expected AuthResultMessage, got {type(result_message)}")
            
            # Calculate duration
            duration_ms = (time.perf_counter() - start_time) * 1000
            
            # Check authentication result
            success = result_message.auth_result.value == "success"
            
            if success:
                # Log success
                if self._audit_logger:
                    self._audit_logger.log_auth_success(
                        client_fingerprint=client_keypair.fingerprint,
                        server_fingerprint=server_fingerprint,
                        duration_ms=duration_ms,
                        session_id=session_id,
                        metadata={
                            "server_url": url,
                            "protocol_version": connect_message.version
                        }
                    )
                
                return {
                    "success": True,
                    "client_fingerprint": client_keypair.fingerprint,
                    "server_fingerprint": server_fingerprint,
                    "duration_ms": duration_ms,
                    "session_id": session_id,
                    "server_url": url
                }
            else:
                # Authentication failed
                failure_reason = result_message.failure_reason.value if result_message.failure_reason else "unknown"
                
                if self._audit_logger:
                    self._audit_logger.log_auth_failure(
                        failure_reason=failure_reason,
                        client_fingerprint=client_keypair.fingerprint,
                        server_fingerprint=server_fingerprint,
                        duration_ms=duration_ms,
                        session_id=session_id,
                        metadata={"server_url": url}
                    )
                
                return {
                    "success": False,
                    "client_fingerprint": client_keypair.fingerprint,
                    "server_fingerprint": server_fingerprint,
                    "failure_reason": failure_reason,
                    "duration_ms": duration_ms,
                    "session_id": session_id,
                    "server_url": url
                }
        
        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            
            if self._audit_logger:
                self._audit_logger.log_auth_failure(
                    failure_reason=str(e),
                    client_fingerprint=client_keypair.fingerprint,
                    duration_ms=duration_ms,
                    session_id=session_id,
                    metadata={"server_url": url, "exception_type": type(e).__name__}
                )
            
            raise
    
    async def close(self) -> None:
        """Close transport manager."""
        await self.transport_manager.close()
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()


# Add missing imports
import time
from datetime import datetime, timezone
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .key_manager import KeyManager
from .exceptions import KeyMismatchError, AuthenticationError