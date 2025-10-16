"""
Protocol Handler for MCP PKI Authentication System.

Handles JSON message serialization/deserialization, validation, and protocol versioning.
"""

import base64
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Union, List, Literal
from enum import Enum

from pydantic import BaseModel, Field, field_validator, model_validator

from .exceptions import ValidationError, ProtocolError


class MessageType(str, Enum):
    """MCP Authentication message types."""
    AUTH_CONNECT = "auth_connect"
    AUTH_CHALLENGE = "auth_challenge" 
    AUTH_RESPONSE = "auth_response"
    AUTH_RESULT = "auth_result"


class AuthResult(str, Enum):
    """Authentication result values."""
    SUCCESS = "success"
    FAILED = "failed"


class FailureReason(str, Enum):
    """Authentication failure reasons."""
    UNKNOWN_KEY = "unknown_key"
    INVALID_SIGNATURE = "invalid_signature"
    TIMESTAMP_MISMATCH = "timestamp_mismatch"
    REPLAY_DETECTED = "replay_detected"
    PROTOCOL_ERROR = "protocol_error"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"


class BaseAuthMessage(BaseModel):
    """Base class for all authentication messages."""
    
    type: MessageType
    version: str = Field(default="1.0", pattern=r"^\d+\.\d+$")
    timestamp: str = Field(..., description="ISO8601 UTC timestamp")
    
    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: str) -> str:
        """Validate ISO8601 timestamp format."""
        try:
            datetime.fromisoformat(v.replace('Z', '+00:00'))
            return v
        except ValueError:
            raise ValueError("Invalid ISO8601 timestamp format")
    
    def get_timestamp(self) -> datetime:
        """Get timestamp as datetime object."""
        return datetime.fromisoformat(self.timestamp.replace('Z', '+00:00'))
    
    @staticmethod
    def create_timestamp() -> str:
        """Create current timestamp in ISO8601 format."""
        return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


class AuthConnectMessage(BaseAuthMessage):
    """Message 1: Client connection request."""
    
    type: Literal[MessageType.AUTH_CONNECT] = Field(default=MessageType.AUTH_CONNECT)
    client_public_key: str = Field(..., description="Base64-encoded ed25519 public key")
    
    @field_validator("client_public_key")
    @classmethod
    def validate_public_key(cls, v: str) -> str:
        """Validate base64-encoded public key."""
        try:
            key_bytes = base64.b64decode(v)
            if len(key_bytes) != 32:
                raise ValueError("ed25519 public key must be 32 bytes")
            return v
        except Exception:
            raise ValueError("Invalid base64-encoded public key")
    
    def get_public_key_bytes(self) -> bytes:
        """Get public key as raw bytes."""
        return base64.b64decode(self.client_public_key)


class AuthChallengeMessage(BaseAuthMessage):
    """Message 2: Server challenge."""
    
    type: Literal[MessageType.AUTH_CHALLENGE] = Field(default=MessageType.AUTH_CHALLENGE)
    server_public_key: str = Field(..., description="Base64-encoded ed25519 public key")
    challenge_nonce: str = Field(..., description="Base64-encoded 32-byte random nonce")
    signature: str = Field(..., description="Base64-encoded ed25519 signature")
    
    @field_validator("server_public_key")
    @classmethod
    def validate_server_public_key(cls, v: str) -> str:
        """Validate base64-encoded server public key."""
        try:
            decoded = base64.b64decode(v)
            if len(decoded) != 32:
                raise ValueError("server_public_key must be 32 bytes")
            return v
        except Exception:
            raise ValueError("Invalid base64-encoded server_public_key")
    
    @field_validator("challenge_nonce")
    @classmethod
    def validate_challenge_nonce(cls, v: str) -> str:
        """Validate base64-encoded challenge nonce."""
        try:
            decoded = base64.b64decode(v)
            if len(decoded) != 32:
                raise ValueError("challenge_nonce must be 32 bytes")
            return v
        except Exception:
            raise ValueError("Invalid base64-encoded challenge_nonce")
    
    @field_validator("signature")
    @classmethod
    def validate_signature(cls, v: str) -> str:
        """Validate base64-encoded signature."""
        try:
            sig_bytes = base64.b64decode(v)
            if len(sig_bytes) != 64:
                raise ValueError("ed25519 signature must be 64 bytes")
            return v
        except Exception:
            raise ValueError("Invalid base64-encoded signature")
    
    def get_server_public_key_bytes(self) -> bytes:
        """Get server public key as raw bytes."""
        return base64.b64decode(self.server_public_key)
    
    def get_challenge_nonce_bytes(self) -> bytes:
        """Get challenge nonce as raw bytes."""
        return base64.b64decode(self.challenge_nonce)
    
    def get_signature_bytes(self) -> bytes:
        """Get signature as raw bytes."""
        return base64.b64decode(self.signature)
    
    def get_message_for_signature(self) -> bytes:
        """Get message bytes that should be signed."""
        return self._create_signature_message(
            self.server_public_key,
            self.challenge_nonce,
            self.timestamp
        )


class AuthResponseMessage(BaseAuthMessage):
    """Message 3: Client response."""
    
    type: Literal[MessageType.AUTH_RESPONSE] = Field(default=MessageType.AUTH_RESPONSE)
    challenge_signature: str = Field(..., description="Base64-encoded signature of server challenge")
    client_challenge: str = Field(..., description="Base64-encoded 32-byte client challenge")
    
    @field_validator("challenge_signature")
    @classmethod
    def validate_challenge_signature(cls, v: str) -> str:
        """Validate challenge signature."""
        try:
            sig_bytes = base64.b64decode(v)
            if len(sig_bytes) != 64:
                raise ValueError("ed25519 signature must be 64 bytes")
            return v
        except Exception:
            raise ValueError("Invalid base64-encoded challenge signature")
    
    @field_validator("client_challenge")
    @classmethod
    def validate_client_challenge(cls, v: str) -> str:
        """Validate client challenge nonce."""
        try:
            nonce_bytes = base64.b64decode(v)
            if len(nonce_bytes) != 32:
                raise ValueError("Client challenge must be 32 bytes")
            return v
        except Exception:
            raise ValueError("Invalid base64-encoded client challenge")
    
    def get_challenge_signature_bytes(self) -> bytes:
        """Get challenge signature as raw bytes."""
        return base64.b64decode(self.challenge_signature)
    
    def get_client_challenge_bytes(self) -> bytes:
        """Get client challenge as raw bytes."""
        return base64.b64decode(self.client_challenge)
    
    def get_challenge_message_for_signature(
        self, 
        server_challenge_nonce: str
    ) -> bytes:
        """Get message bytes that should be signed for challenge response."""
        return self._create_signature_message(
            server_challenge_nonce,
            self.timestamp
        )


class AuthResultMessage(BaseAuthMessage):
    """Message 4: Server authentication result."""
    
    type: Literal[MessageType.AUTH_RESULT] = Field(default=MessageType.AUTH_RESULT)
    client_challenge_signature: str = Field(..., description="Base64-encoded signature of client challenge")
    auth_result: AuthResult = Field(..., description="Authentication result")
    failure_reason: Optional[FailureReason] = Field(None, description="Reason for failure")
    
    @field_validator("client_challenge_signature")
    @classmethod
    def validate_client_challenge_signature(cls, v: str) -> str:
        """Validate client challenge signature."""
        try:
            sig_bytes = base64.b64decode(v)
            if len(sig_bytes) != 64:
                raise ValueError("ed25519 signature must be 64 bytes")
            return v
        except Exception:
            raise ValueError("Invalid base64-encoded client challenge signature")
    
    @model_validator(mode='after')
    def validate_failure_reason(self) -> 'AuthResultMessage':
        """Validate failure reason consistency."""
        if self.auth_result == AuthResult.FAILED and self.failure_reason is None:
            raise ValueError("failure_reason required when auth_result is 'failed'")
        if self.auth_result == AuthResult.SUCCESS and self.failure_reason is not None:
            raise ValueError("failure_reason not allowed when auth_result is 'success'")
        return self
    
    def get_client_challenge_signature_bytes(self) -> bytes:
        """Get client challenge signature as raw bytes."""
        return base64.b64decode(self.client_challenge_signature)
    
    def get_client_challenge_message_for_signature(
        self, 
        client_challenge: str
    ) -> bytes:
        """Get message bytes that should be signed for client challenge."""
        return self._create_signature_message(
            client_challenge,
            self.timestamp
        )


# Message type mapping
MESSAGE_TYPES = {
    MessageType.AUTH_CONNECT: AuthConnectMessage,
    MessageType.AUTH_CHALLENGE: AuthChallengeMessage,
    MessageType.AUTH_RESPONSE: AuthResponseMessage,
    MessageType.AUTH_RESULT: AuthResultMessage,
}


class ProtocolHandler:
    """Handles MCP authentication protocol message serialization and validation."""
    
    PROTOCOL_VERSION = "1.0"
    
    @staticmethod
    def create_signature_message(*fields: str) -> bytes:
        """
        Create message bytes for signing by concatenating fields with null separators.
        
        Args:
            *fields: String fields to concatenate
            
        Returns:
            Message bytes for signing
        """
        return b'\x00'.join(field.encode('utf-8') for field in fields)
    
    @staticmethod
    def serialize_message(message: BaseAuthMessage) -> bytes:
        """
        Serialize authentication message to JSON bytes.
        
        Args:
            message: Message to serialize
            
        Returns:
            JSON bytes
        """
        try:
            json_str = message.model_dump_json(exclude_none=True, by_alias=True)
            return json_str.encode('utf-8')
        except Exception as e:
            raise ValidationError(f"Failed to serialize message: {e}")
    
    @staticmethod
    def deserialize_message(data: Union[bytes, str]) -> BaseAuthMessage:
        """
        Deserialize JSON data to authentication message.
        
        Args:
            data: JSON bytes or string
            
        Returns:
            Parsed authentication message
            
        Raises:
            ValidationError: If data is invalid
            ProtocolError: If message type is unknown
        """
        try:
            if isinstance(data, bytes):
                data = data.decode('utf-8')
            
            # Parse JSON
            json_data = json.loads(data)
            
            # Determine message type
            msg_type = json_data.get("type")
            if not msg_type:
                raise ProtocolError("Missing message type")
            
            try:
                message_type = MessageType(msg_type)
            except ValueError:
                raise ProtocolError(f"Unknown message type: {msg_type}")
            
            # Get appropriate message class
            message_class = MESSAGE_TYPES[message_type]
            
            # Parse and validate
            return message_class(**json_data)
            
        except json.JSONDecodeError as e:
            raise ValidationError(f"Invalid JSON: {e}")
        except Exception as e:
            if isinstance(e, (ValidationError, ProtocolError)):
                raise
            raise ValidationError(f"Failed to deserialize message: {e}")
    
    @staticmethod
    def validate_protocol_version(version: str) -> bool:
        """
        Validate protocol version compatibility.
        
        Args:
            version: Version string to check
            
        Returns:
            True if compatible
        """
        # For now, only support exact version match
        return version == ProtocolHandler.PROTOCOL_VERSION
    
    @staticmethod
    def encode_bytes(data: bytes) -> str:
        """Encode bytes as base64 string."""
        return base64.b64encode(data).decode('ascii')
    
    @staticmethod
    def decode_bytes(data: str) -> bytes:
        """Decode base64 string to bytes."""
        try:
            return base64.b64decode(data)
        except Exception as e:
            raise ValidationError(f"Invalid base64 data: {e}")


# Add the missing method to BaseAuthMessage
def _create_signature_message(self, *fields: str) -> bytes:
    """Create message bytes for signing."""
    return ProtocolHandler.create_signature_message(*fields)

# Monkey patch the method to all message classes
BaseAuthMessage._create_signature_message = _create_signature_message
AuthConnectMessage._create_signature_message = _create_signature_message
AuthChallengeMessage._create_signature_message = _create_signature_message
AuthResponseMessage._create_signature_message = _create_signature_message
AuthResultMessage._create_signature_message = _create_signature_message