"""
Key Manager for MCP PKI Authentication System.

Handles ed25519 key pair generation, storage, loading, and fingerprint calculation.
"""

import hashlib
import os
from pathlib import Path
from typing import Tuple, Union, Optional

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from .exceptions import InvalidKeyError, KeyNotFoundError, MCPAuthError


class KeyPair:
    """Represents an ed25519 key pair."""
    
    def __init__(self, private_key: Ed25519PrivateKey, public_key: Optional[Ed25519PublicKey] = None):
        self.private_key = private_key
        self.public_key = public_key or private_key.public_key()
        self._fingerprint: Optional[str] = None
    
    @property
    def fingerprint(self) -> str:
        """Get SHA-256 fingerprint of the public key."""
        if self._fingerprint is None:
            public_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            self._fingerprint = hashlib.sha256(public_bytes).hexdigest()
        return self._fingerprint
    
    def sign(self, data: bytes) -> bytes:
        """Sign data with the private key."""
        return self.private_key.sign(data)
    
    def verify(self, signature: bytes, data: bytes) -> bool:
        """Verify signature with the public key."""
        try:
            self.public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False


class KeyManager:
    """Manages ed25519 key operations for MCP authentication."""
    
    MCP_PRIVATE_KEY_HEADER = "-----BEGIN MCP PRIVATE KEY-----"
    MCP_PRIVATE_KEY_FOOTER = "-----END MCP PRIVATE KEY-----"
    MCP_PUBLIC_KEY_HEADER = "-----BEGIN MCP PUBLIC KEY-----"
    MCP_PUBLIC_KEY_FOOTER = "-----END MCP PUBLIC KEY-----"
    
    @staticmethod
    def generate_keypair() -> KeyPair:
        """Generate a new ed25519 key pair."""
        private_key = Ed25519PrivateKey.generate()
        return KeyPair(private_key)
    
    @staticmethod
    def save_keypair(
        keypair: KeyPair, 
        private_key_path: Union[str, Path], 
        public_key_path: Optional[Union[str, Path]] = None,
        overwrite: bool = False
    ) -> None:
        """
        Save key pair to disk in MCP PEM format.
        
        Args:
            keypair: KeyPair to save
            private_key_path: Path for private key file
            public_key_path: Optional path for public key file (defaults to private_key_path + .pub)
            overwrite: Whether to overwrite existing files
        """
        private_path = Path(private_key_path)
        
        if public_key_path is None:
            public_path = private_path.with_suffix(private_path.suffix + '.pub')
        else:
            public_path = Path(public_key_path)
        
        # Check for existing files
        if not overwrite:
            if private_path.exists():
                raise FileExistsError(f"Private key file already exists: {private_path}")
            if public_path.exists():
                raise FileExistsError(f"Public key file already exists: {public_path}")
        
        # Ensure parent directories exist
        private_path.parent.mkdir(parents=True, exist_ok=True)
        public_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Save private key
        private_pem = KeyManager._private_key_to_mcp_pem(keypair.private_key)
        private_path.write_bytes(private_pem)
        os.chmod(private_path, 0o600)  # Restrict permissions
        
        # Save public key
        public_pem = KeyManager._public_key_to_mcp_pem(keypair.public_key)
        public_path.write_bytes(public_pem)
    
    @staticmethod
    def load_keypair(private_key_path: Union[str, Path]) -> KeyPair:
        """
        Load key pair from private key file.
        
        Args:
            private_key_path: Path to private key file
            
        Returns:
            KeyPair object
        """
        path = Path(private_key_path)
        if not path.exists():
            raise KeyNotFoundError(f"Private key file not found: {path}")
        
        try:
            private_key_data = path.read_bytes()
            private_key = KeyManager._private_key_from_mcp_pem(private_key_data)
            return KeyPair(private_key)
        except Exception as e:
            raise InvalidKeyError(f"Failed to load private key from {path}: {e}")
    
    @staticmethod
    def load_public_key(public_key_path: Union[str, Path]) -> Ed25519PublicKey:
        """
        Load public key from file.
        
        Args:
            public_key_path: Path to public key file
            
        Returns:
            Ed25519PublicKey object
        """
        path = Path(public_key_path)
        if not path.exists():
            raise KeyNotFoundError(f"Public key file not found: {path}")
        
        try:
            public_key_data = path.read_bytes()
            return KeyManager._public_key_from_mcp_pem(public_key_data)
        except Exception as e:
            raise InvalidKeyError(f"Failed to load public key from {path}: {e}")
    
    @staticmethod
    def get_fingerprint(public_key: Union[Ed25519PublicKey, bytes]) -> str:
        """
        Calculate SHA-256 fingerprint of public key.
        
        Args:
            public_key: Ed25519PublicKey object or raw public key bytes
            
        Returns:
            Hexadecimal fingerprint string
        """
        if isinstance(public_key, Ed25519PublicKey):
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        else:
            public_bytes = public_key
        
        return hashlib.sha256(public_bytes).hexdigest()
    
    @staticmethod
    def verify_signature(
        public_key: Ed25519PublicKey, 
        signature: bytes, 
        data: bytes
    ) -> bool:
        """
        Verify ed25519 signature.
        
        Args:
            public_key: Public key to verify with
            signature: Signature to verify
            data: Data that was signed
            
        Returns:
            True if signature is valid
        """
        try:
            public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False
    
    @staticmethod
    def _private_key_to_mcp_pem(private_key: Ed25519PrivateKey) -> bytes:
        """Convert private key to MCP PEM format."""
        # Get raw private key bytes (32 bytes seed)
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Base64 encode
        import base64
        b64_data = base64.b64encode(private_bytes).decode('ascii')
        
        # Format as PEM
        pem_lines = [KeyManager.MCP_PRIVATE_KEY_HEADER]
        # Split into 64-character lines
        for i in range(0, len(b64_data), 64):
            pem_lines.append(b64_data[i:i+64])
        pem_lines.append(KeyManager.MCP_PRIVATE_KEY_FOOTER)
        
        return '\n'.join(pem_lines).encode('ascii')
    
    @staticmethod
    def _public_key_to_mcp_pem(public_key: Ed25519PublicKey) -> bytes:
        """Convert public key to MCP PEM format."""
        # Get raw public key bytes (32 bytes)
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Base64 encode
        import base64
        b64_data = base64.b64encode(public_bytes).decode('ascii')
        
        # Format as PEM
        pem_lines = [KeyManager.MCP_PUBLIC_KEY_HEADER]
        # Split into 64-character lines
        for i in range(0, len(b64_data), 64):
            pem_lines.append(b64_data[i:i+64])
        pem_lines.append(KeyManager.MCP_PUBLIC_KEY_FOOTER)
        
        return '\n'.join(pem_lines).encode('ascii')
    
    @staticmethod
    def _private_key_from_mcp_pem(pem_data: bytes) -> Ed25519PrivateKey:
        """Load private key from MCP PEM format."""
        pem_str = pem_data.decode('ascii').strip()
        
        if not pem_str.startswith(KeyManager.MCP_PRIVATE_KEY_HEADER):
            raise InvalidKeyError("Invalid MCP private key PEM header")
        
        if not pem_str.endswith(KeyManager.MCP_PRIVATE_KEY_FOOTER):
            raise InvalidKeyError("Invalid MCP private key PEM footer")
        
        # Extract base64 data
        lines = pem_str.split('\n')
        b64_lines = lines[1:-1]  # Remove header and footer
        b64_data = ''.join(b64_lines)
        
        try:
            import base64
            private_bytes = base64.b64decode(b64_data)
            if len(private_bytes) != 32:
                raise InvalidKeyError(f"Invalid private key length: {len(private_bytes)}, expected 32")
            
            return Ed25519PrivateKey.from_private_bytes(private_bytes)
        except Exception as e:
            raise InvalidKeyError(f"Failed to decode private key: {e}")
    
    @staticmethod
    def _public_key_from_mcp_pem(pem_data: bytes) -> Ed25519PublicKey:
        """Load public key from MCP PEM format."""
        pem_str = pem_data.decode('ascii').strip()
        
        if not pem_str.startswith(KeyManager.MCP_PUBLIC_KEY_HEADER):
            raise InvalidKeyError("Invalid MCP public key PEM header")
        
        if not pem_str.endswith(KeyManager.MCP_PUBLIC_KEY_FOOTER):
            raise InvalidKeyError("Invalid MCP public key PEM footer")
        
        # Extract base64 data
        lines = pem_str.split('\n')
        b64_lines = lines[1:-1]  # Remove header and footer
        b64_data = ''.join(b64_lines)
        
        try:
            import base64
            public_bytes = base64.b64decode(b64_data)
            if len(public_bytes) != 32:
                raise InvalidKeyError(f"Invalid public key length: {len(public_bytes)}, expected 32")
            
            return Ed25519PublicKey.from_public_bytes(public_bytes)
        except Exception as e:
            raise InvalidKeyError(f"Failed to decode public key: {e}")
    
    @staticmethod
    def validate_keypair(keypair: KeyPair) -> bool:
        """
        Validate that a key pair works correctly.
        
        Args:
            keypair: KeyPair to validate
            
        Returns:
            True if keypair is valid
        """
        try:
            # Test signing and verification
            test_data = b"test_message_for_validation"
            signature = keypair.sign(test_data)
            return keypair.verify(signature, test_data)
        except Exception:
            return False