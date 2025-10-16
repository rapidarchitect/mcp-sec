"""
Integration tests for full MCP authentication flow.
"""

import asyncio
import tempfile
from pathlib import Path
import pytest

from mcp_pki_auth.key_manager import KeyManager
from mcp_pki_auth.acl_manager import ACLManager
from mcp_pki_auth.auth_engine import AuthenticationEngine
from mcp_pki_auth.protocol import (
    AuthConnectMessage,
    AuthChallengeMessage, 
    AuthResponseMessage,
    AuthResultMessage,
    ProtocolHandler
)
from mcp_pki_auth.audit import setup_audit_logger, LogLevel
from mcp_pki_auth.exceptions import AuthenticationError


class TestAuthenticationFlow:
    """Test complete authentication flows."""
    
    @pytest.fixture
    def server_keypair(self):
        """Generate server key pair."""
        return KeyManager.generate_keypair()
    
    @pytest.fixture 
    def client_keypair(self):
        """Generate client key pair."""
        return KeyManager.generate_keypair()
    
    @pytest.fixture
    def server_acl_manager(self, client_keypair):
        """Create server ACL manager with client key allowed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            allowlist_path = Path(tmpdir) / "server_allowlist.json"
            acl_manager = ACLManager(allowlist_path, default_policy="deny")
            
            # Add client key to allowlist
            acl_manager.add_key(
                public_key=client_keypair.public_key,
                description="Test client",
                added_by="test"
            )
            
            yield acl_manager
    
    @pytest.fixture
    def client_acl_manager(self, server_keypair):
        """Create client ACL manager with server key allowed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            allowlist_path = Path(tmpdir) / "client_allowlist.json"
            acl_manager = ACLManager(allowlist_path, default_policy="deny")
            
            # Add server key to allowlist
            acl_manager.add_key(
                public_key=server_keypair.public_key,
                description="Test server", 
                added_by="test"
            )
            
            yield acl_manager
    
    @pytest.fixture
    def server_auth_engine(self, server_keypair, server_acl_manager, audit_logger):
        """Create server authentication engine."""
        return AuthenticationEngine(
            keypair=server_keypair,
            acl_manager=server_acl_manager,
            max_skew_seconds=300.0,
            timeout_seconds=10.0,
            audit_logger=audit_logger
        )
    
    @pytest.fixture
    def client_auth_engine(self, client_keypair, client_acl_manager, audit_logger):
        """Create client authentication engine.""" 
        return AuthenticationEngine(
            keypair=client_keypair,
            acl_manager=client_acl_manager,
            max_skew_seconds=300.0,
            timeout_seconds=10.0,
            audit_logger=audit_logger
        )
    
    @pytest.fixture
    def audit_logger(self):
        """Setup audit logger for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.log"
            logger = setup_audit_logger(
                enabled=True,
                log_level=LogLevel.DEBUG,
                log_file_path=log_path,
                console_output=False
            )
            yield logger
            logger.close()
    
    @pytest.mark.asyncio
    async def test_successful_mutual_authentication(
        self,
        server_auth_engine,
        client_auth_engine,
        server_keypair,
        client_keypair,
        audit_logger
    ):
        """Test successful mutual authentication flow."""
        
        # Step 1: Client creates connect message
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
        
        # Step 2: Server processes connect message and creates challenge
        result_message, auth_result = await server_auth_engine.authenticate_as_server(connect_message)
        
        # Verify authentication succeeded
        assert auth_result.success is True
        assert auth_result.client_fingerprint == client_keypair.fingerprint
        assert auth_result.server_fingerprint == server_keypair.fingerprint
        assert auth_result.duration_ms is not None
        assert auth_result.duration_ms > 0
        
        # Verify result message
        assert isinstance(result_message, AuthResultMessage)
        assert result_message.auth_result.value == "success"
        assert result_message.failure_reason is None
        
        # Check audit logs
        stats = audit_logger.get_statistics()
        assert stats["event_counts"]["auth_attempt"] >= 1
        assert stats["event_counts"]["auth_success"] >= 1
    
    @pytest.mark.asyncio
    async def test_unknown_client_rejection(
        self,
        server_keypair,
        audit_logger
    ):
        """Test rejection of unknown client."""
        
        # Create empty ACL manager (no allowed clients)
        with tempfile.TemporaryDirectory() as tmpdir:
            allowlist_path = Path(tmpdir) / "empty_allowlist.json"
            empty_acl_manager = ACLManager(allowlist_path, default_policy="deny")
            
            server_engine = AuthenticationEngine(
                keypair=server_keypair,
                acl_manager=empty_acl_manager,
                audit_logger=audit_logger
            )
            
            # Create unknown client
            unknown_client = KeyManager.generate_keypair()
            
            # Create connect message from unknown client
            client_public_key_b64 = ProtocolHandler.encode_bytes(
                unknown_client.public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            )
            
            connect_message = AuthConnectMessage(
                client_public_key=client_public_key_b64,
                timestamp=AuthConnectMessage.create_timestamp()
            )
            
            # Server should reject unknown client
            result_message, auth_result = await server_engine.authenticate_as_server(connect_message)
            
            # Verify authentication failed
            assert auth_result.success is False
            assert auth_result.failure_reason == "unknown_key"
            assert auth_result.client_fingerprint == unknown_client.fingerprint
            
            # Verify result message
            assert isinstance(result_message, AuthResultMessage)
            assert result_message.auth_result.value == "failed"
            assert result_message.failure_reason.value == "unknown_key"
            
            # Check audit logs
            stats = audit_logger.get_statistics()
            assert stats["event_counts"]["auth_failure"] >= 1
    
    @pytest.mark.asyncio 
    async def test_timestamp_validation_failure(
        self,
        server_auth_engine,
        client_keypair,
        audit_logger
    ):
        """Test authentication failure due to timestamp skew."""
        
        # Create connect message with old timestamp
        from datetime import datetime, timezone, timedelta
        old_timestamp = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat().replace('+00:00', 'Z')
        
        client_public_key_b64 = ProtocolHandler.encode_bytes(
            client_keypair.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        )
        
        connect_message = AuthConnectMessage(
            client_public_key=client_public_key_b64,
            timestamp=old_timestamp  # Too old
        )
        
        # Server should reject due to timestamp
        result_message, auth_result = await server_auth_engine.authenticate_as_server(connect_message)
        
        # Verify authentication failed
        assert auth_result.success is False
        assert auth_result.failure_reason == "timestamp_mismatch"
        
        # Check audit logs  
        stats = audit_logger.get_statistics()
        assert stats["event_counts"]["auth_failure"] >= 1
    
    @pytest.mark.asyncio
    async def test_performance_metrics(
        self,
        server_auth_engine,
        client_keypair,
        audit_logger
    ):
        """Test performance metrics collection."""
        
        # Run multiple authentications
        for _ in range(5):
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
            
            await server_auth_engine.authenticate_as_server(connect_message)
        
        # Check engine statistics
        engine_stats = server_auth_engine.get_statistics()
        assert engine_stats["auth_attempts"] == 5
        assert engine_stats["auth_successes"] == 5
        assert engine_stats["success_rate"] == 100.0
        
        # Check audit logger statistics
        audit_stats = audit_logger.get_statistics()
        assert audit_stats["event_counts"]["auth_attempt"] >= 5
        assert audit_stats["event_counts"]["auth_success"] >= 5
    
    @pytest.mark.asyncio
    async def test_concurrent_authentications(
        self,
        server_auth_engine,
        audit_logger
    ):
        """Test concurrent authentication requests."""
        
        async def authenticate_client():
            """Authenticate a single client."""
            client_keypair = KeyManager.generate_keypair()
            
            # Add to server allowlist
            server_auth_engine.acl_manager.add_key(
                public_key=client_keypair.public_key,
                description="Concurrent test client"
            )
            
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
            
            result_message, auth_result = await server_auth_engine.authenticate_as_server(connect_message)
            return auth_result.success
        
        # Run 10 concurrent authentications
        tasks = [authenticate_client() for _ in range(10)]
        results = await asyncio.gather(*tasks)
        
        # All should succeed
        assert all(results)
        
        # Check final statistics
        engine_stats = server_auth_engine.get_statistics()
        assert engine_stats["auth_successes"] >= 10


# Add missing imports
from cryptography.hazmat.primitives import serialization