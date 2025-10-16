"""
Unit tests for KeyManager module.
"""

import tempfile
from pathlib import Path
import pytest
from cryptography.hazmat.primitives import serialization

from mcp_pki_auth.key_manager import KeyManager, KeyPair
from mcp_pki_auth.exceptions import InvalidKeyError, KeyNotFoundError


class TestKeyPair:
    """Test KeyPair functionality."""
    
    def test_keypair_creation(self):
        """Test creating a KeyPair."""
        keypair = KeyManager.generate_keypair()
        
        assert keypair.private_key is not None
        assert keypair.public_key is not None
        assert isinstance(keypair.fingerprint, str)
        assert len(keypair.fingerprint) == 64  # SHA-256 hex = 64 chars
    
    def test_signing_and_verification(self):
        """Test signing and verification with KeyPair."""
        keypair = KeyManager.generate_keypair()
        test_data = b"test message for signing"
        
        # Sign data
        signature = keypair.sign(test_data)
        assert len(signature) == 64  # ed25519 signature is 64 bytes
        
        # Verify signature
        assert keypair.verify(signature, test_data)
        
        # Verify wrong data fails
        wrong_data = b"wrong message"
        assert not keypair.verify(signature, wrong_data)


class TestKeyManager:
    """Test KeyManager functionality."""
    
    def test_generate_keypair(self):
        """Test key pair generation."""
        keypair = KeyManager.generate_keypair()
        
        assert isinstance(keypair, KeyPair)
        assert KeyManager.validate_keypair(keypair)
    
    def test_save_and_load_keypair(self):
        """Test saving and loading key pairs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            private_path = Path(tmpdir) / "test-private.pem"
            public_path = Path(tmpdir) / "test-public.pem"
            
            # Generate and save
            original_keypair = KeyManager.generate_keypair()
            KeyManager.save_keypair(
                original_keypair,
                private_path,
                public_path
            )
            
            # Check files exist
            assert private_path.exists()
            assert public_path.exists()
            
            # Load keypair
            loaded_keypair = KeyManager.load_keypair(private_path)
            
            # Verify loaded keypair matches original
            assert loaded_keypair.fingerprint == original_keypair.fingerprint
            
            # Test signing with loaded keypair
            test_data = b"test message"
            signature = loaded_keypair.sign(test_data)
            assert original_keypair.verify(signature, test_data)
    
    def test_load_public_key(self):
        """Test loading public key separately."""
        with tempfile.TemporaryDirectory() as tmpdir:
            private_path = Path(tmpdir) / "test-private.pem"
            public_path = Path(tmpdir) / "test-public.pem"
            
            # Generate and save
            keypair = KeyManager.generate_keypair()
            KeyManager.save_keypair(keypair, private_path, public_path)
            
            # Load public key
            public_key = KeyManager.load_public_key(public_path)
            
            # Verify fingerprint matches
            loaded_fp = KeyManager.get_fingerprint(public_key)
            assert loaded_fp == keypair.fingerprint
    
    def test_fingerprint_calculation(self):
        """Test fingerprint calculation."""
        keypair = KeyManager.generate_keypair()
        
        # Test with KeyPair
        fp1 = keypair.fingerprint
        
        # Test with Ed25519PublicKey
        fp2 = KeyManager.get_fingerprint(keypair.public_key)
        
        # Test with raw bytes
        public_bytes = keypair.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        fp3 = KeyManager.get_fingerprint(public_bytes)
        
        # All should be the same
        assert fp1 == fp2 == fp3
        assert len(fp1) == 64  # SHA-256 hex
    
    def test_signature_verification(self):
        """Test signature verification."""
        keypair = KeyManager.generate_keypair()
        test_data = b"test message for signature verification"
        
        # Sign with keypair
        signature = keypair.sign(test_data)
        
        # Verify with KeyManager method
        assert KeyManager.verify_signature(
            keypair.public_key,
            signature,
            test_data
        )
        
        # Verify wrong data fails
        assert not KeyManager.verify_signature(
            keypair.public_key,
            signature,
            b"wrong data"
        )
    
    def test_invalid_key_file(self):
        """Test loading invalid key files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            invalid_file = Path(tmpdir) / "invalid.pem"
            invalid_file.write_text("not a valid key file")
            
            with pytest.raises(InvalidKeyError):
                KeyManager.load_keypair(invalid_file)
    
    def test_missing_key_file(self):
        """Test loading missing key files."""
        nonexistent_file = Path("/nonexistent/path/key.pem")
        
        with pytest.raises(KeyNotFoundError):
            KeyManager.load_keypair(nonexistent_file)
    
    def test_key_validation(self):
        """Test key pair validation."""
        # Valid keypair
        valid_keypair = KeyManager.generate_keypair()
        assert KeyManager.validate_keypair(valid_keypair)
    
    def test_pem_format(self):
        """Test MCP PEM format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            private_path = Path(tmpdir) / "test.pem"
            public_path = Path(tmpdir) / "test.pub"
            
            keypair = KeyManager.generate_keypair()
            KeyManager.save_keypair(keypair, private_path, public_path)
            
            # Check private key format
            private_content = private_path.read_text()
            assert "-----BEGIN MCP PRIVATE KEY-----" in private_content
            assert "-----END MCP PRIVATE KEY-----" in private_content
            
            # Check public key format
            public_content = public_path.read_text()
            assert "-----BEGIN MCP PUBLIC KEY-----" in public_content
            assert "-----END MCP PUBLIC KEY-----" in public_content


if __name__ == '__main__':
    pytest.main([__file__])