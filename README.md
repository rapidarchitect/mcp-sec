# MCP PKI Authentication System

A mutual authentication system for the Model Context Protocol (MCP) using ed25519 public key infrastructure, enabling bidirectional identity verification between MCP servers and clients.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture) 
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [CLI Usage](#cli-usage)
- [API Reference](#api-reference)
- [Security](#security)
- [Development](#development)
- [Testing](#testing)
- [Contributing](#contributing)

## Overview

The MCP PKI Authentication System provides secure, mutual authentication for MCP connections using ed25519 digital signatures. It implements a 4-message challenge-response protocol that verifies the identity of both clients and servers before establishing communication.

### Key Features

- **Mutual Authentication**: Both clients and servers verify each other's identity
- **ed25519 Cryptography**: Modern, fast elliptic curve signatures
- **Replay Protection**: Timestamp and nonce validation prevent replay attacks
- **Allowlist Management**: Fine-grained access control via public key fingerprints
- **High Performance**: Sub-10ms authentication overhead, stateless server design
- **Audit Logging**: Comprehensive authentication event tracking
- **Multiple Transports**: HTTP/HTTPS and WebSocket support
- **Docker Ready**: Containerized testing and deployment

## Quick Start

### 1. Generate Key Pairs

```bash
# Generate server key pair
mcp-keygen --output-dir ./keys --key-name server

# Generate client key pair  
mcp-keygen --output-dir ./keys --key-name client
```

### 2. Set Up Allowlists

```bash
# Add client's public key to server allowlist
mcp-allowlist add --config server_config.yml \
  --key-file ./keys/client_public.pem \
  --metadata '{"role": "trusted_client", "org": "example_org"}'

# Add server's public key to client allowlist
mcp-allowlist add --config client_config.yml \
  --key-file ./keys/server_public.pem \
  --metadata '{"role": "mcp_server", "endpoint": "api.example.com"}'
```

### 3. Configure Authentication

Create `server_config.yml`:
```yaml
keys:
  private_key_path: "./keys/server_private.pem"
  public_key_path: "./keys/server_public.pem"

acl:
  allowlist_path: "./keys/server_allowlist.json"

auth:
  timestamp_tolerance: 300  # 5 minutes
  nonce_cache_size: 10000

audit:
  enabled: true
  log_file: "./logs/server_audit.jsonl"
  log_level: "INFO"

transport:
  type: "http"
  host: "0.0.0.0"
  port: 8443
  ssl:
    cert_file: "./certs/server.crt"
    key_file: "./certs/server.key"
```

### 4. Test Authentication

```bash
# Start server (in one terminal)
python -m mcp_pki_auth.examples.server --config server_config.yml

# Test from client (in another terminal)
python -m mcp_pki_auth.examples.client \
  --config client_config.yml \
  --server-url https://localhost:8443/auth
```

## Architecture

The system consists of four core components:

```
┌─────────────────┐    ┌─────────────────┐
│   MCP Client    │    │   MCP Server    │
│                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ Key Manager │ │    │ │ Key Manager │ │
│ └─────────────┘ │    │ └─────────────┘ │
│ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ ACL Manager │ │    │ │ ACL Manager │ │
│ └─────────────┘ │    │ └─────────────┘ │
│ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │  Auth Engine│ │◄──►│ │ Auth Engine │ │
│ └─────────────┘ │    │ └─────────────┘ │
│ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │  Transport  │ │    │ │  Transport  │ │
│ └─────────────┘ │    │ └─────────────┘ │
└─────────────────┘    └─────────────────┘
```

### Components

**Key Manager**: Handles ed25519 key pair generation, PEM storage, and SHA-256 fingerprint calculation.

**ACL Manager**: Maintains allowlists using fingerprint-based indexing for O(1) lookups with metadata support.

**Authentication Engine**: Executes the 4-message protocol with signature verification, timestamp validation (±5 minutes), and nonce replay protection.

**Transport Layer**: Provides HTTP/HTTPS and WebSocket connectivity with connection pooling, retries, and SSL/TLS support.

### Protocol Flow

```
Client                    Server
  │                         │
  │ 1. AuthRequest          │
  │ ─────────────────────►  │
  │    {public_key}         │
  │                         │
  │ 2. AuthChallenge        │
  │ ◄─────────────────────  │
  │    {challenge, sig}     │
  │                         │
  │ 3. AuthResponse         │
  │ ─────────────────────►  │
  │    {response, counter}  │
  │                         │
  │ 4. AuthComplete         │
  │ ◄─────────────────────  │
  │    {success, sig}       │
  │                         │
```

## Installation

### Requirements

- Python 3.8+
- Docker (for containerized testing)

### Installation Methods

#### From Source

```bash
git clone https://github.com/your-org/mcp-sec.git
cd mcp-sec
pip install -e .
```

#### Using Docker

```bash
git clone https://github.com/your-org/mcp-sec.git
cd mcp-sec
make setup-test-env
make build
```

### Dependencies

Core dependencies are automatically installed:
- `cryptography>=41.0.0` - ed25519 cryptographic operations
- `pyyaml>=6.0` - Configuration file parsing
- `click>=8.0.0` - CLI framework
- `websockets>=11.0` - WebSocket transport support
- `tabulate>=0.9.0` - CLI table formatting

## Configuration

### Configuration File Structure

```yaml
# Key management
keys:
  private_key_path: "./keys/private.pem"
  public_key_path: "./keys/public.pem"
  auto_generate: false  # Generate keys if not found

# Access control
acl:
  allowlist_path: "./keys/allowlist.json"
  auto_create: true  # Create empty allowlist if not found
  metadata_required: false  # Require metadata for all entries

# Authentication settings
auth:
  timestamp_tolerance: 300  # seconds (±5 minutes)
  nonce_cache_size: 10000   # Max cached nonces
  nonce_cache_ttl: 3600     # Nonce TTL in seconds

# Audit logging
audit:
  enabled: true
  log_file: "./logs/audit.jsonl"  # Use null for stdout
  log_level: "INFO"  # DEBUG, INFO, WARN, ERROR
  max_file_size: "10MB"
  backup_count: 5
  include_performance: true
  filter_events: ["auth_success", "auth_failure", "key_validation"]

# Transport configuration
transport:
  type: "http"  # "http", "https", "ws", "wss"
  host: "localhost"
  port: 8443
  timeout: 30
  max_connections: 100
  retry_attempts: 3
  retry_delay: 1.0
  
  # SSL/TLS settings (for https/wss)
  ssl:
    cert_file: "./certs/server.crt"
    key_file: "./certs/server.key"
    ca_file: "./certs/ca.pem"  # Optional CA bundle
    verify_mode: "required"  # "none", "optional", "required"
```

### Environment Variables

Configuration values can be overridden with environment variables:

```bash
# Key paths
export MCP_PRIVATE_KEY_PATH="./keys/private.pem"
export MCP_PUBLIC_KEY_PATH="./keys/public.pem"

# ACL settings
export MCP_ALLOWLIST_PATH="./keys/allowlist.json"

# Auth settings
export MCP_TIMESTAMP_TOLERANCE=300
export MCP_NONCE_CACHE_SIZE=10000

# Audit settings
export MCP_AUDIT_ENABLED=true
export MCP_AUDIT_LOG_FILE="./logs/audit.jsonl"
export MCP_AUDIT_LOG_LEVEL="INFO"

# Transport settings
export MCP_TRANSPORT_TYPE="https"
export MCP_TRANSPORT_HOST="0.0.0.0"
export MCP_TRANSPORT_PORT=8443
```

## CLI Usage

### Key Management

#### Generate Key Pairs

```bash
# Basic key generation
mcp-keygen --output-dir ./keys --key-name mykey

# Generate with custom parameters
mcp-keygen \
  --output-dir ./keys \
  --key-name server \
  --comment "Production server key - 2024" \
  --format json  # Output key info as JSON

# Show fingerprint of existing key
mcp-keygen --show-fingerprint ./keys/server_public.pem
```

#### Extract Public Key

```bash
# Extract public key from private key
mcp-keygen --extract-public \
  --private-key ./keys/server_private.pem \
  --output-file ./keys/server_public_extracted.pem
```

### Allowlist Management

#### Add Keys

```bash
# Add key with metadata
mcp-allowlist add \
  --config server_config.yml \
  --key-file ./keys/client_public.pem \
  --metadata '{"role": "api_client", "org": "example", "expires": "2024-12-31"}'

# Add key by fingerprint
mcp-allowlist add \
  --config server_config.yml \
  --fingerprint "a1b2c3d4..." \
  --metadata '{"role": "backup_server"}'
```

#### List Keys

```bash
# List all keys
mcp-allowlist list --config server_config.yml

# List with specific format
mcp-allowlist list \
  --config server_config.yml \
  --format table \
  --show-metadata

# Filter by metadata
mcp-allowlist list \
  --config server_config.yml \
  --filter-role "api_client"
```

#### Remove Keys

```bash
# Remove by fingerprint
mcp-allowlist remove \
  --config server_config.yml \
  --fingerprint "a1b2c3d4..."

# Remove multiple keys
mcp-allowlist remove \
  --config server_config.yml \
  --fingerprint "a1b2c3d4..." "e5f6g7h8..."
```

#### Import/Export

```bash
# Export allowlist
mcp-allowlist export \
  --config server_config.yml \
  --output ./backups/allowlist_backup.json

# Import allowlist (merges with existing)
mcp-allowlist import \
  --config server_config.yml \
  --input ./backups/allowlist_backup.json \
  --merge

# Show statistics
mcp-allowlist stats --config server_config.yml
```

### Authentication Testing

#### Test Authentication Flow

```bash
# Test against remote server
mcp-auth-test \
  --config client_config.yml \
  --server-url https://api.example.com:8443/auth \
  --timeout 10

# Test with WebSocket
mcp-auth-test \
  --config client_config.yml \
  --server-url wss://api.example.com:8443/ws \
  --transport websocket

# Performance testing
mcp-auth-test \
  --config client_config.yml \
  --server-url https://localhost:8443/auth \
  --count 100 \
  --concurrent 10
```

#### Configuration Validation

```bash
# Validate configuration file
mcp-config-validate server_config.yml

# Check key file integrity
mcp-config-validate \
  --check-keys \
  --config server_config.yml

# Validate allowlist
mcp-config-validate \
  --check-allowlist \
  --config server_config.yml
```

## API Reference

### Core Classes

#### KeyManager

```python
from mcp_pki_auth.key_manager import KeyManager

# Initialize
key_mgr = KeyManager()

# Generate new key pair
private_key, public_key = key_mgr.generate_key_pair()

# Save keys in PEM format
key_mgr.save_private_key(private_key, "./keys/private.pem")
key_mgr.save_public_key(public_key, "./keys/public.pem")

# Load existing keys
private_key = key_mgr.load_private_key("./keys/private.pem")
public_key = key_mgr.load_public_key("./keys/public.pem")

# Calculate fingerprint
fingerprint = key_mgr.get_fingerprint(public_key)

# Sign data
signature = key_mgr.sign_data(private_key, b"message")

# Verify signature
is_valid = key_mgr.verify_signature(public_key, b"message", signature)
```

#### ACLManager

```python
from mcp_pki_auth.acl_manager import ACLManager

# Initialize
acl_mgr = ACLManager("./keys/allowlist.json")

# Add key to allowlist
metadata = {"role": "client", "org": "example"}
acl_mgr.add_key(public_key, metadata)

# Check if key is allowed
is_allowed, metadata = acl_mgr.is_key_allowed(public_key)

# Remove key
acl_mgr.remove_key(public_key)

# List all keys
keys_info = acl_mgr.list_keys()
```

#### AuthenticationEngine

```python
from mcp_pki_auth.auth_engine import AuthenticationEngine
from mcp_pki_auth.config import Config

# Initialize
config = Config.load_from_file("config.yml")
auth_engine = AuthenticationEngine(config, key_manager, acl_manager)

# Client-side authentication
async def client_auth():
    # Step 1: Create auth request
    request = auth_engine.create_auth_request()
    
    # Step 3: Process server challenge
    response = auth_engine.process_challenge(challenge_msg)
    
    # Verify final response
    success = auth_engine.verify_auth_complete(complete_msg)
    return success

# Server-side authentication  
async def server_auth():
    # Step 2: Process client request and create challenge
    challenge = auth_engine.process_auth_request(request_msg)
    
    # Step 4: Process response and complete auth
    result = auth_engine.process_auth_response(response_msg)
    return result
```

### Transport Layer

#### HTTP Transport

```python
from mcp_pki_auth.transport import HTTPTransport

# Client
transport = HTTPTransport(
    base_url="https://api.example.com:8443",
    ssl_cert_file="./certs/client.crt",
    ssl_key_file="./certs/client.key",
    timeout=30,
    retry_attempts=3
)

# Send authentication request
response = await transport.send_auth_message(auth_request)

# Server
server_transport = HTTPTransport(
    host="0.0.0.0",
    port=8443,
    ssl_cert_file="./certs/server.crt", 
    ssl_key_file="./certs/server.key"
)

# Handle incoming authentication
async def handle_auth(request):
    return await auth_engine.process_auth_request(request)

server_transport.set_auth_handler(handle_auth)
await server_transport.start_server()
```

#### WebSocket Transport

```python
from mcp_pki_auth.transport import WebSocketTransport

# Client WebSocket connection
ws_transport = WebSocketTransport(
    url="wss://api.example.com:8443/ws",
    ssl_cert_file="./certs/client.crt",
    max_connections=10
)

# Persistent connection for multiple auths
async with ws_transport.connect() as connection:
    response = await connection.authenticate(auth_request)

# Server WebSocket handler
ws_server = WebSocketTransport(
    host="0.0.0.0",
    port=8443,
    ssl_cert_file="./certs/server.crt"
)

await ws_server.start_server(auth_handler)
```

### Audit Logging

```python
from mcp_pki_auth.audit import AuditLogger

# Initialize audit logger
audit = AuditLogger(
    log_file="./logs/audit.jsonl",
    log_level="INFO",
    include_performance=True
)

# Log authentication events
audit.log_auth_attempt(
    client_fingerprint="a1b2c3d4...",
    server_fingerprint="e5f6g7h8...",
    success=True,
    duration_ms=8.5,
    metadata={"transport": "https", "endpoint": "/auth"}
)

# Log key validation
audit.log_key_validation(
    fingerprint="a1b2c3d4...",
    valid=True,
    metadata={"source": "allowlist"}
)

# Get performance metrics
metrics = audit.get_performance_metrics()
print(f"Average auth time: {metrics['avg_auth_time_ms']:.2f}ms")
```

## Security

### Cryptographic Details

- **Algorithm**: ed25519 (Curve25519 with SHA-512)
- **Key Size**: 32-byte public keys, 64-byte signatures
- **Hash Function**: SHA-256 for fingerprints, SHA-512 for signatures

### Security Features

#### Replay Protection

- **Timestamps**: All messages include Unix timestamps validated within ±5 minutes
- **Nonces**: Unique random nonces prevent duplicate challenge reuse
- **Signature Coverage**: Signatures include all message fields plus separators

#### Access Control

- **Allowlist-Only**: No implicit trust; all keys must be explicitly allowed
- **Fingerprint-Based**: Uses SHA-256 fingerprints for key identification
- **Metadata Support**: Rich metadata for key management and auditing

#### Transport Security

- **TLS Encryption**: HTTPS/WSS transport with configurable cipher suites
- **Certificate Validation**: Full certificate chain validation
- **Connection Limits**: Configurable connection pooling and rate limiting

### Best Practices

#### Key Management

```bash
# Generate keys with proper permissions
umask 077
mcp-keygen --output-dir ./keys --key-name production

# Store private keys securely
chmod 600 ./keys/*_private.pem
chmod 644 ./keys/*_public.pem

# Regular key rotation (recommended: annually)
mcp-keygen --output-dir ./keys --key-name production_2024
```

#### Configuration Security

```yaml
# Use strong timestamp tolerance (not too permissive)
auth:
  timestamp_tolerance: 300  # 5 minutes max

# Enable comprehensive audit logging
audit:
  enabled: true
  log_level: "INFO"
  include_performance: true
  
# Use TLS with proper certificates
transport:
  type: "https"
  ssl:
    verify_mode: "required"
    cert_file: "/path/to/cert.pem"
    key_file: "/path/to/key.pem"
```

#### Operational Security

- Monitor audit logs for failed authentication attempts
- Regularly rotate keys and certificates
- Use separate key pairs for different environments
- Implement proper backup and recovery procedures
- Monitor performance metrics for anomalies

## Development

### Project Structure

```
mcp-sec/
├── src/mcp_pki_auth/          # Main package
│   ├── __init__.py
│   ├── key_manager.py         # Key generation and management
│   ├── acl_manager.py         # Allowlist management
│   ├── auth_engine.py         # Authentication protocol
│   ├── protocol.py            # Message handling
│   ├── config.py              # Configuration management
│   ├── audit.py               # Audit logging
│   ├── transport.py           # Network transport layer
│   ├── exceptions.py          # Custom exceptions
│   └── cli/                   # CLI tools
│       ├── __init__.py
│       ├── keygen.py          # Key generation CLI
│       ├── allowlist.py       # Allowlist management CLI
│       ├── auth_test.py       # Authentication testing CLI
│       └── config_validate.py # Configuration validation CLI
├── tests/                     # Test suite
│   ├── unit/                  # Unit tests
│   ├── integration/           # Integration tests
│   ├── security/              # Security tests
│   └── performance/           # Performance benchmarks
├── examples/                  # Example implementations
├── docs/                      # Documentation
├── docker/                    # Docker configuration
├── Makefile                   # Build automation
├── pyproject.toml            # Project metadata
├── requirements.txt          # Dependencies
└── README.md                 # This file
```

### Setting Up Development Environment

#### Using Docker (Recommended)

```bash
# Clone and setup
git clone https://github.com/your-org/mcp-sec.git
cd mcp-sec

# Setup test environment
make setup-test-env

# Build development container
make build

# Run tests in container
make test

# Interactive development
make dev-shell
```

#### Local Development

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install in development mode
pip install -e .
pip install -r requirements-dev.txt

# Run tests locally
pytest tests/

# Run linting
make lint
```

### Git Workflow

#### Feature Development

```bash
# Create feature branch
git checkout -b feature/new-transport-layer

# Make changes and test
make test
make lint

# Commit and push
git add .
git commit -m "Add WebSocket transport layer with connection pooling"
git push origin feature/new-transport-layer
```

#### Implementation Branches

```bash
# For language-specific implementations
git checkout -b impl/rust-performance
git checkout -b impl/go-server
git checkout -b impl/nodejs-client

# Use worktrees for parallel development
git worktree add ../mcp-sec-rust impl/rust-performance
cd ../mcp-sec-rust
# Work on Rust implementation
```

### Code Style

- **Python**: Follow PEP 8, use `black` for formatting, `pylint` for linting
- **Type Hints**: Use type annotations for all public APIs
- **Documentation**: Docstrings for all public classes and functions
- **Testing**: Aim for 95%+ test coverage on core authentication paths

## Testing

### Test Categories

#### Unit Tests

```bash
# Run all unit tests
pytest tests/unit/

# Test specific component
pytest tests/unit/test_key_manager.py
pytest tests/unit/test_auth_engine.py

# With coverage
pytest tests/unit/ --cov=mcp_pki_auth --cov-report=html
```

#### Integration Tests

```bash
# Full authentication flow tests
pytest tests/integration/

# Test with Docker environment
make test-integration

# Test specific scenarios
pytest tests/integration/test_full_auth_flow.py -v
```

#### Security Tests

```bash
# Security-focused tests
pytest tests/security/

# Replay attack prevention
pytest tests/security/test_replay_protection.py

# Timing attack resistance
pytest tests/security/test_timing_attacks.py
```

#### Performance Tests

```bash
# Performance benchmarks
pytest tests/performance/ --benchmark-only

# Specific performance metrics
pytest tests/performance/test_auth_performance.py -s

# Memory usage testing
pytest tests/performance/test_memory_usage.py
```

### Docker-Based Testing

```bash
# All tests in clean environment
make test

# Specific test suites
make test-unit
make test-integration
make test-security
make test-performance

# Cross-language integration (when available)
make test-cross-language
```

### Continuous Integration

The project includes GitHub Actions workflows:

- **Unit Tests**: Run on every commit
- **Integration Tests**: Run on PRs to main
- **Security Tests**: Run nightly
- **Performance Tests**: Run on releases

## Contributing

### Getting Started

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

### Development Guidelines

#### Code Quality

- All code must pass `make lint` checks
- New features require tests with >90% coverage
- Public APIs require documentation
- Follow existing code patterns and conventions

#### Pull Request Process

1. **Description**: Clearly describe the changes and motivation
2. **Tests**: Include tests for new functionality
3. **Documentation**: Update relevant documentation
4. **Performance**: Consider performance impact of changes
5. **Security**: Highlight any security implications

#### Issue Reporting

When reporting issues, include:

- Python version and OS
- Complete error messages and stack traces
- Minimal reproduction steps
- Configuration files (sanitized)

### Architecture Decisions

Major architectural changes should be discussed via GitHub issues before implementation. Consider:

- Performance impact
- Security implications  
- Backward compatibility
- Cross-language implementation challenges

### Future Roadmap

- **Multi-language support**: Go, Rust, Node.js implementations
- **Key rotation**: Automated key rotation protocols
- **Federation**: Cross-domain authentication support
- **Hardware Security**: HSM and hardware key support
- **Monitoring**: Prometheus metrics integration

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/your-org/mcp-sec/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/mcp-sec/discussions)
- **Security**: Report security issues to security@example.com

---

**Version**: 1.0.0  
**Last Updated**: January 2024  
**Maintainers**: MCP Security Team
