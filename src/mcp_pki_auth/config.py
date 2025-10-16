"""
Configuration Management for MCP PKI Authentication System.

Handles YAML configuration loading, environment variable support,
and configuration validation with default settings.
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional, Union, List
from dataclasses import dataclass, field

import yaml
from pydantic import BaseModel, Field, validator

from .exceptions import ConfigurationError


class KeysConfig(BaseModel):
    """Key configuration section."""
    
    private_key_path: str = Field(..., description="Path to private key file")
    public_key_path: Optional[str] = Field(None, description="Path to public key file")
    
    @validator("private_key_path")
    def validate_private_key_path(cls, v: str) -> str:
        """Validate private key path."""
        if not v:
            raise ValueError("private_key_path cannot be empty")
        return os.path.expanduser(v)
    
    @validator("public_key_path")
    def validate_public_key_path(cls, v: Optional[str]) -> Optional[str]:
        """Validate public key path."""
        if v:
            return os.path.expanduser(v)
        return v


class AllowlistConfig(BaseModel):
    """Allowlist configuration section."""
    
    path: str = Field(..., description="Path to allowlist JSON file")
    default_policy: str = Field("deny", description="Default policy for unknown keys")
    reload_interval: str = Field("5m", description="How often to reload allowlist")
    
    @validator("path")
    def validate_path(cls, v: str) -> str:
        """Validate allowlist path."""
        return os.path.expanduser(v)
    
    @validator("default_policy")
    def validate_default_policy(cls, v: str) -> str:
        """Validate default policy."""
        if v not in ["allow", "deny"]:
            raise ValueError("default_policy must be 'allow' or 'deny'")
        return v
    
    @validator("reload_interval")
    def validate_reload_interval(cls, v: str) -> str:
        """Validate reload interval format."""
        if not v.endswith(('s', 'm', 'h')):
            raise ValueError("reload_interval must end with 's', 'm', or 'h'")
        try:
            int(v[:-1])
        except ValueError:
            raise ValueError("reload_interval must be a number followed by s/m/h")
        return v


class TimestampConfig(BaseModel):
    """Timestamp validation configuration."""
    
    max_skew_seconds: float = Field(300.0, description="Maximum clock skew in seconds")
    
    @validator("max_skew_seconds")
    def validate_max_skew(cls, v: float) -> float:
        """Validate max skew value."""
        if v < 0:
            raise ValueError("max_skew_seconds must be non-negative")
        return v


class AuditConfig(BaseModel):
    """Audit logging configuration."""
    
    enabled: bool = Field(True, description="Enable audit logging")
    log_path: str = Field("", description="Path to audit log file")
    log_level: str = Field("info", description="Log level")
    log_successes: bool = Field(True, description="Log successful authentications")
    log_failures: bool = Field(True, description="Log failed authentications")
    
    @validator("log_path")
    def validate_log_path(cls, v: str) -> str:
        """Validate log path."""
        if v:
            return os.path.expanduser(v)
        return v
    
    @validator("log_level")
    def validate_log_level(cls, v: str) -> str:
        """Validate log level."""
        valid_levels = ["debug", "info", "warning", "error", "critical"]
        if v.lower() not in valid_levels:
            raise ValueError(f"log_level must be one of: {', '.join(valid_levels)}")
        return v.lower()


class ServerConfig(BaseModel):
    """Server-specific configuration."""
    
    enabled: bool = Field(True, description="Enable MCP authentication")
    mode: str = Field("enforced", description="Authentication mode")
    keys: KeysConfig = Field(..., description="Key configuration")
    client_allowlist: AllowlistConfig = Field(..., description="Client allowlist configuration")
    timestamp: TimestampConfig = Field(default_factory=TimestampConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    
    @validator("mode")
    def validate_mode(cls, v: str) -> str:
        """Validate authentication mode."""
        valid_modes = ["enforced", "permissive", "disabled"]
        if v not in valid_modes:
            raise ValueError(f"mode must be one of: {', '.join(valid_modes)}")
        return v


class ClientConfig(BaseModel):
    """Client-specific configuration."""
    
    enabled: bool = Field(True, description="Enable MCP authentication")
    keys: KeysConfig = Field(..., description="Key configuration")
    server_allowlist: AllowlistConfig = Field(..., description="Server allowlist configuration")
    prompt_on_unknown: bool = Field(True, description="Prompt user for unknown servers")
    timestamp: TimestampConfig = Field(default_factory=TimestampConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)


class MCPAuthConfig(BaseModel):
    """Complete MCP authentication configuration."""
    
    server: Optional[ServerConfig] = Field(None, description="Server configuration")
    client: Optional[ClientConfig] = Field(None, description="Client configuration")
    
    @validator("server", "client", pre=True, always=True)
    def at_least_one_config(cls, v, values, field):
        """Ensure at least one of server or client is configured."""
        if field.name == "client" and not values.get("server") and not v:
            raise ValueError("At least one of 'server' or 'client' must be configured")
        return v


class ConfigManager:
    """Manages configuration loading and validation."""
    
    DEFAULT_SERVER_CONFIG = {
        "enabled": True,
        "mode": "enforced",
        "keys": {
            "private_key_path": "/etc/mcp/server-private-key.pem",
            "public_key_path": "/etc/mcp/server-public-key.pem"
        },
        "client_allowlist": {
            "path": "/etc/mcp/client-allowlist.json",
            "default_policy": "deny",
            "reload_interval": "5m"
        },
        "timestamp": {
            "max_skew_seconds": 300
        },
        "audit": {
            "enabled": True,
            "log_path": "/var/log/mcp/auth-audit.log",
            "log_level": "info",
            "log_successes": True,
            "log_failures": True
        }
    }
    
    DEFAULT_CLIENT_CONFIG = {
        "enabled": True,
        "keys": {
            "private_key_path": "~/.mcp/client-private-key.pem",
            "public_key_path": "~/.mcp/client-public-key.pem"
        },
        "server_allowlist": {
            "path": "~/.mcp/server-allowlist.json",
            "default_policy": "prompt",
            "reload_interval": "5m"
        },
        "prompt_on_unknown": True,
        "timestamp": {
            "max_skew_seconds": 300
        },
        "audit": {
            "enabled": True,
            "log_path": "~/.mcp/auth-audit.log",
            "log_level": "info"
        }
    }
    
    def __init__(self):
        """Initialize configuration manager."""
        self._config: Optional[MCPAuthConfig] = None
    
    def load_config(
        self,
        config_path: Optional[Union[str, Path]] = None,
        config_data: Optional[Dict[str, Any]] = None,
        role: str = "server"
    ) -> MCPAuthConfig:
        """
        Load configuration from file or data.
        
        Args:
            config_path: Path to YAML configuration file
            config_data: Configuration dictionary (alternative to file)
            role: Default role if not specified ("server" or "client")
            
        Returns:
            Validated configuration object
            
        Raises:
            ConfigurationError: If configuration is invalid
        """
        try:
            if config_data is None:
                config_data = self._load_config_file(config_path)
            
            # Apply environment variable overrides
            config_data = self._apply_env_overrides(config_data)
            
            # Add default configuration for specified role if missing
            if "mcp_auth" not in config_data:
                config_data = {"mcp_auth": {}}
            
            auth_config = config_data["mcp_auth"]
            
            if role == "server" and "server" not in auth_config:
                auth_config["server"] = self.DEFAULT_SERVER_CONFIG
            elif role == "client" and "client" not in auth_config:
                auth_config["client"] = self.DEFAULT_CLIENT_CONFIG
            
            # Validate configuration
            self._config = MCPAuthConfig(**auth_config)
            return self._config
            
        except Exception as e:
            raise ConfigurationError(f"Failed to load configuration: {e}")
    
    def get_config(self) -> MCPAuthConfig:
        """
        Get current configuration.
        
        Returns:
            Current configuration object
            
        Raises:
            ConfigurationError: If no configuration loaded
        """
        if self._config is None:
            raise ConfigurationError("No configuration loaded. Call load_config() first.")
        return self._config
    
    def _load_config_file(self, config_path: Optional[Union[str, Path]]) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        if config_path is None:
            # Look for default config files
            default_paths = [
                "/etc/mcp/auth.yml",
                "~/.mcp/auth.yml", 
                "./mcp-auth.yml",
                "./config/auth.yml"
            ]
            
            for path_str in default_paths:
                path = Path(path_str).expanduser()
                if path.exists():
                    config_path = path
                    break
        
        if config_path is None:
            # Return empty config to use defaults
            return {}
        
        config_path = Path(config_path).expanduser()
        
        if not config_path.exists():
            raise ConfigurationError(f"Configuration file not found: {config_path}")
        
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML in config file: {e}")
        except Exception as e:
            raise ConfigurationError(f"Failed to read config file: {e}")
    
    def _apply_env_overrides(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply environment variable overrides to configuration."""
        # Environment variable mapping
        env_mappings = {
            # Server config
            "MCP_AUTH_SERVER_ENABLED": ("mcp_auth", "server", "enabled"),
            "MCP_AUTH_SERVER_MODE": ("mcp_auth", "server", "mode"),
            "MCP_AUTH_SERVER_PRIVATE_KEY_PATH": ("mcp_auth", "server", "keys", "private_key_path"),
            "MCP_AUTH_SERVER_PUBLIC_KEY_PATH": ("mcp_auth", "server", "keys", "public_key_path"),
            "MCP_AUTH_CLIENT_ALLOWLIST_PATH": ("mcp_auth", "server", "client_allowlist", "path"),
            "MCP_AUTH_CLIENT_DEFAULT_POLICY": ("mcp_auth", "server", "client_allowlist", "default_policy"),
            "MCP_AUTH_MAX_SKEW_SECONDS": ("mcp_auth", "server", "timestamp", "max_skew_seconds"),
            "MCP_AUTH_LOG_PATH": ("mcp_auth", "server", "audit", "log_path"),
            "MCP_AUTH_LOG_LEVEL": ("mcp_auth", "server", "audit", "log_level"),
            
            # Client config
            "MCP_AUTH_CLIENT_ENABLED": ("mcp_auth", "client", "enabled"),
            "MCP_AUTH_CLIENT_PRIVATE_KEY_PATH": ("mcp_auth", "client", "keys", "private_key_path"),
            "MCP_AUTH_CLIENT_PUBLIC_KEY_PATH": ("mcp_auth", "client", "keys", "public_key_path"),
            "MCP_AUTH_SERVER_ALLOWLIST_PATH": ("mcp_auth", "client", "server_allowlist", "path"),
            "MCP_AUTH_PROMPT_ON_UNKNOWN": ("mcp_auth", "client", "prompt_on_unknown"),
        }
        
        # Apply overrides
        for env_var, path in env_mappings.items():
            value = os.environ.get(env_var)
            if value is not None:
                # Navigate/create nested structure
                current = config_data
                for key in path[:-1]:
                    if key not in current:
                        current[key] = {}
                    current = current[key]
                
                # Convert value to appropriate type
                final_key = path[-1]
                if final_key in ["enabled", "log_successes", "log_failures", "prompt_on_unknown"]:
                    # Boolean values
                    current[final_key] = value.lower() in ("true", "1", "yes", "on")
                elif final_key in ["max_skew_seconds"]:
                    # Float values
                    try:
                        current[final_key] = float(value)
                    except ValueError:
                        pass  # Keep original value
                else:
                    # String values
                    current[final_key] = value
        
        return config_data
    
    def save_config(self, config_path: Union[str, Path], config: Optional[MCPAuthConfig] = None) -> None:
        """
        Save configuration to YAML file.
        
        Args:
            config_path: Path to save configuration file
            config: Configuration to save (uses current if None)
        """
        if config is None:
            config = self.get_config()
        
        config_path = Path(config_path).expanduser()
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert to dict for YAML serialization
        config_dict = {"mcp_auth": config.dict(exclude_none=True)}
        
        try:
            with open(config_path, 'w') as f:
                yaml.dump(config_dict, f, default_flow_style=False, indent=2)
        except Exception as e:
            raise ConfigurationError(f"Failed to save configuration: {e}")
    
    def validate_config(self, config_path: Union[str, Path]) -> List[str]:
        """
        Validate configuration file and return any issues.
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            List of validation issues (empty if valid)
        """
        issues = []
        
        try:
            self.load_config(config_path)
            
            # Additional validation checks
            config = self.get_config()
            
            # Check key file paths exist
            if config.server:
                private_key_path = Path(config.server.keys.private_key_path).expanduser()
                if not private_key_path.exists():
                    issues.append(f"Server private key file not found: {private_key_path}")
            
            if config.client:
                private_key_path = Path(config.client.keys.private_key_path).expanduser()
                if not private_key_path.exists():
                    issues.append(f"Client private key file not found: {private_key_path}")
            
        except ConfigurationError as e:
            issues.append(str(e))
        
        return issues