"""
ACL Manager for MCP PKI Authentication System.

Manages allowlists for both servers and clients with fingerprint-based indexing.
"""

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .exceptions import (
    DuplicateKeyError, 
    KeyNotFoundError, 
    ValidationError,
    InvalidKeyError
)
from .key_manager import KeyManager


class KeyMetadata:
    """Metadata associated with an allowlisted key."""
    
    def __init__(
        self,
        fingerprint: str,
        public_key: Union[Ed25519PublicKey, bytes],
        description: str,
        added_at: Optional[datetime] = None,
        added_by: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.fingerprint = fingerprint
        
        # Store public key as bytes for JSON serialization
        if isinstance(public_key, Ed25519PublicKey):
            self.public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        else:
            self.public_key_bytes = public_key
            
        self.description = description
        self.added_at = added_at or datetime.now(timezone.utc)
        self.added_by = added_by
        self.metadata = metadata or {}
    
    @property
    def public_key(self) -> Ed25519PublicKey:
        """Get Ed25519PublicKey object."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        return Ed25519PublicKey.from_public_bytes(self.public_key_bytes)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        import base64
        return {
            "fingerprint": self.fingerprint,
            "public_key": base64.b64encode(self.public_key_bytes).decode('ascii'),
            "description": self.description,
            "added_at": self.added_at.isoformat(),
            "added_by": self.added_by,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KeyMetadata":
        """Create from dictionary (JSON deserialization)."""
        import base64
        
        public_key_bytes = base64.b64decode(data["public_key"])
        added_at = datetime.fromisoformat(data["added_at"])
        
        return cls(
            fingerprint=data["fingerprint"],
            public_key=public_key_bytes,
            description=data["description"],
            added_at=added_at,
            added_by=data.get("added_by"),
            metadata=data.get("metadata", {})
        )


class ACLManager:
    """Manages access control lists (allowlists) for MCP authentication."""
    
    def __init__(self, allowlist_path: Union[str, Path], default_policy: str = "deny"):
        """
        Initialize ACL Manager.
        
        Args:
            allowlist_path: Path to allowlist JSON file
            default_policy: Default policy for unknown keys ("allow" or "deny")
        """
        self.allowlist_path = Path(allowlist_path)
        self.default_policy = default_policy
        
        # Thread-safe operations
        self._lock = threading.RLock()
        
        # In-memory index: fingerprint -> KeyMetadata
        self._keys: Dict[str, KeyMetadata] = {}
        
        # Load existing allowlist
        self._load_allowlist()
    
    def add_key(
        self,
        public_key: Union[Ed25519PublicKey, bytes],
        description: str,
        added_by: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        allow_update: bool = False
    ) -> str:
        """
        Add a public key to the allowlist.
        
        Args:
            public_key: Ed25519 public key or raw bytes
            description: Human-readable description
            added_by: Optional identifier of who added the key
            metadata: Optional additional metadata
            allow_update: Whether to update existing key
            
        Returns:
            Fingerprint of the added key
            
        Raises:
            DuplicateKeyError: If key already exists and allow_update=False
            InvalidKeyError: If public key is invalid
        """
        # Calculate fingerprint
        fingerprint = KeyManager.get_fingerprint(public_key)
        
        with self._lock:
            # Check for existing key
            if fingerprint in self._keys and not allow_update:
                raise DuplicateKeyError(f"Key with fingerprint {fingerprint} already exists")
            
            # Create key metadata
            key_metadata = KeyMetadata(
                fingerprint=fingerprint,
                public_key=public_key,
                description=description,
                added_by=added_by,
                metadata=metadata
            )
            
            # Add to index
            self._keys[fingerprint] = key_metadata
            
            # Save to disk
            self._save_allowlist()
            
            return fingerprint
    
    def remove_key(self, fingerprint: str) -> bool:
        """
        Remove a key from the allowlist.
        
        Args:
            fingerprint: SHA-256 fingerprint of key to remove
            
        Returns:
            True if key was removed, False if not found
        """
        with self._lock:
            if fingerprint not in self._keys:
                return False
            
            del self._keys[fingerprint]
            self._save_allowlist()
            return True
    
    def is_allowed(self, public_key: Union[Ed25519PublicKey, bytes, str]) -> bool:
        """
        Check if a key is allowed.
        
        Args:
            public_key: Ed25519 public key, raw bytes, or fingerprint string
            
        Returns:
            True if key is allowed
        """
        if isinstance(public_key, str):
            fingerprint = public_key
        else:
            fingerprint = KeyManager.get_fingerprint(public_key)
        
        with self._lock:
            if fingerprint in self._keys:
                return True
            
            # Fall back to default policy
            return self.default_policy == "allow"
    
    def get_key_metadata(self, fingerprint: str) -> Optional[KeyMetadata]:
        """
        Get metadata for a key.
        
        Args:
            fingerprint: SHA-256 fingerprint
            
        Returns:
            KeyMetadata if found, None otherwise
        """
        with self._lock:
            return self._keys.get(fingerprint)
    
    def list_keys(self) -> List[KeyMetadata]:
        """
        List all keys in the allowlist.
        
        Returns:
            List of KeyMetadata objects
        """
        with self._lock:
            return list(self._keys.values())
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get allowlist statistics.
        
        Returns:
            Dictionary with statistics
        """
        with self._lock:
            return {
                "total_keys": len(self._keys),
                "default_policy": self.default_policy,
                "allowlist_path": str(self.allowlist_path),
                "last_updated": datetime.now(timezone.utc).isoformat()
            }
    
    def reload(self) -> None:
        """Reload allowlist from disk."""
        with self._lock:
            self._load_allowlist()
    
    def _load_allowlist(self) -> None:
        """Load allowlist from JSON file."""
        if not self.allowlist_path.exists():
            # Create empty allowlist
            self._keys = {}
            self._save_allowlist()
            return
        
        try:
            with open(self.allowlist_path, 'r') as f:
                data = json.load(f)
            
            # Validate structure
            if not isinstance(data, dict):
                raise ValidationError("Allowlist must be a JSON object")
            
            if "keys" not in data:
                raise ValidationError("Allowlist missing 'keys' field")
            
            # Load keys
            keys = {}
            for key_data in data["keys"]:
                try:
                    key_metadata = KeyMetadata.from_dict(key_data)
                    keys[key_metadata.fingerprint] = key_metadata
                except Exception as e:
                    # Log warning and skip invalid keys
                    print(f"Warning: Skipping invalid key in allowlist: {e}")
                    continue
            
            self._keys = keys
            
        except json.JSONDecodeError as e:
            raise ValidationError(f"Invalid JSON in allowlist file: {e}")
        except Exception as e:
            raise ValidationError(f"Failed to load allowlist: {e}")
    
    def _save_allowlist(self) -> None:
        """Save allowlist to JSON file."""
        # Ensure parent directory exists
        self.allowlist_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Create allowlist structure
        allowlist_data = {
            "version": "1.0",
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "default_policy": self.default_policy,
            "keys": [key_meta.to_dict() for key_meta in self._keys.values()]
        }
        
        # Write atomically
        temp_path = self.allowlist_path.with_suffix('.tmp')
        try:
            with open(temp_path, 'w') as f:
                json.dump(allowlist_data, f, indent=2)
            
            # Atomic rename
            temp_path.replace(self.allowlist_path)
            
        except Exception as e:
            # Clean up temp file
            if temp_path.exists():
                temp_path.unlink()
            raise ValidationError(f"Failed to save allowlist: {e}")
    
    def export_public_keys(self, output_path: Union[str, Path]) -> None:
        """
        Export all public keys to a directory in PEM format.
        
        Args:
            output_path: Directory to export keys to
        """
        output_dir = Path(output_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        with self._lock:
            for key_metadata in self._keys.values():
                # Create safe filename from fingerprint
                filename = f"{key_metadata.fingerprint[:16]}.pub"
                key_path = output_dir / filename
                
                # Save as MCP PEM format
                pem_data = KeyManager._public_key_to_mcp_pem(key_metadata.public_key)
                key_path.write_bytes(pem_data)
    
    def import_public_keys(
        self, 
        input_path: Union[str, Path], 
        default_description: str = "Imported key",
        added_by: Optional[str] = None
    ) -> int:
        """
        Import public keys from PEM files in a directory.
        
        Args:
            input_path: Directory containing PEM files
            default_description: Default description for imported keys
            added_by: Who is importing the keys
            
        Returns:
            Number of keys successfully imported
        """
        input_dir = Path(input_path)
        if not input_dir.exists():
            raise FileNotFoundError(f"Import directory not found: {input_dir}")
        
        imported_count = 0
        
        # Find PEM files
        pem_files = list(input_dir.glob("*.pem")) + list(input_dir.glob("*.pub"))
        
        for pem_file in pem_files:
            try:
                public_key = KeyManager.load_public_key(pem_file)
                
                # Use filename as description
                description = f"{default_description} ({pem_file.stem})"
                
                self.add_key(
                    public_key=public_key,
                    description=description,
                    added_by=added_by,
                    allow_update=True  # Allow updates during import
                )
                
                imported_count += 1
                
            except Exception as e:
                print(f"Warning: Failed to import {pem_file}: {e}")
                continue
        
        return imported_count