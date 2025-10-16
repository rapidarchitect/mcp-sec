# MCP PKI Authentication System
## Product Requirements Document (PRD) & Functional Requirements Document (FRD)

**Version:** 1.0  
**Date:** October 15, 2025  
**Status:** Draft

---

## Table of Contents

1. [Product Requirements Document (PRD)](#product-requirements-document-prd)
2. [Functional Requirements Document (FRD)](#functional-requirements-document-frd)
3. [Edge Cases & Error Handling](#edge-cases--error-handling)
4. [Testing Strategy](#testing-strategy)
5. [Performance Considerations](#performance-considerations)

---

# Product Requirements Document (PRD)

## 1. Executive Summary

This document defines a mutual authentication system for the Model Context Protocol (MCP) using ed25519 public key infrastructure. The system enables bidirectional identity verification where both MCP servers and clients can independently authenticate each other and enforce access control policies.

## 2. Background & Problem Statement

### Current State
MCP currently lacks a standardized, cryptographically secure authentication mechanism for mutual identity verification between servers and clients. This creates several challenges:

- No guarantee of server authenticity (clients may connect to malicious servers)
- No cryptographic proof of client identity (servers cannot reliably authorize clients)
- Risk of man-in-the-middle attacks
- Difficulty in implementing fine-grained access control
- No audit trail of authenticated connections

### Problem Statement
Organizations and individuals need a secure, performant, and standardized way to ensure that:
1. Clients can verify they're connecting to legitimate MCP servers
2. Servers can verify and authorize specific clients
3. Both parties can independently enforce access control policies
4. All authentication events are auditable

## 3. Goals & Objectives

### Primary Goals
- **Security**: Implement cryptographically secure mutual authentication using ed25519
- **Bidirectional Control**: Enable both servers and clients to independently allow/disallow connections
- **Performance**: Maintain minimal latency overhead (<10ms per authentication)
- **Auditability**: Provide complete audit trails of authentication attempts
- **Simplicity**: Offer straightforward key management and deployment

### Non-Goals
- Certificate Authority (CA) infrastructure (self-signed keys are acceptable)
- Key rotation automation (manual rotation is acceptable for v1)
- Integration with existing identity providers (future consideration)
- Revocation mechanisms (future consideration)

## 4. User Stories

### Server Operators
- As a server operator, I want to verify client identities so that I can enforce access control policies
- As a server operator, I want to maintain an allowlist of authorized client keys
- As a server operator, I want to log all authentication attempts for security auditing
- As a server operator, I want to reject unknown clients by default

### Client Users
- As a client user, I want to verify server identity so that I don't connect to malicious servers
- As a client user, I want to maintain a list of trusted server keys
- As a client user, I want to be warned when connecting to an unknown server
- As a client user, I want to manage my client identity key pair

### System Administrators
- As a system admin, I want to deploy authentication with minimal configuration
- As a system admin, I want to test authentication without affecting production
- As a system admin, I want clear error messages when authentication fails

## 5. Success Metrics

### Adoption Metrics
- 50% of MCP servers implement PKI authentication within 6 months
- 70% of enterprise deployments use PKI authentication within 1 year

### Performance Metrics
- Authentication overhead: <10ms per connection
- Key verification: <1ms per signature validation
- Memory overhead: <1MB per 10,000 cached keys

### Security Metrics
- Zero successful MITM attacks reported
- 100% of authentication failures properly logged
- <0.1% false positive rate in authentication

### Usability Metrics
- Key generation: <30 seconds for first-time setup
- Configuration: <10 lines of config per deployment
- Error resolution time: <5 minutes for common issues

## 6. Requirements Priority

### P0 (Must Have)
- ed25519 key pair generation
- Signature-based authentication handshake
- Server-side client allowlist
- Client-side server allowlist
- Authentication failure logging
- Basic error messages

### P1 (Should Have)
- Key fingerprint display for verification
- Detailed audit logging
- Configuration validation
- Test mode for authentication
- Performance monitoring

### P2 (Nice to Have)
- Key format conversion utilities
- Integration with key management tools
- Prometheus metrics export
- Authentication success notifications

## 7. Security & Privacy Considerations

### Security Requirements
- All private keys must be stored encrypted at rest
- Private keys must never be transmitted over the network
- Challenge-response must use unique nonces per authentication
- Signatures must include timestamp to prevent replay attacks
- Failed authentication attempts must not leak timing information

### Privacy Requirements
- Public keys are considered non-sensitive
- Authentication logs must not contain private keys
- Client identities can be pseudonymous (no PII required)

## 8. Dependencies & Constraints

### Technical Dependencies
- ed25519 cryptographic library (libsodium, or equivalent)
- Secure random number generator
- System clock synchronization (NTP recommended)

### Constraints
- Must work in offline/air-gapped environments
- Must support multiple concurrent authentication attempts
- Must handle clock skew up to ±5 minutes
- Must work across different programming languages

---

# Functional Requirements Document (FRD)

## 1. System Architecture

### 1.1 Overview

The authentication system consists of four primary components:

```
┌─────────────┐                           ┌─────────────┐
│   Client    │                           │   Server    │
│             │                           │             │
│ ┌─────────┐ │                           │ ┌─────────┐ │
│ │ Key Mgr │ │                           │ │ Key Mgr │ │
│ └─────────┘ │                           │ └─────────┘ │
│ ┌─────────┐ │    Auth Handshake        │ ┌─────────┐ │
│ │Auth Eng │ │◄─────────────────────────►│ │Auth Eng │ │
│ └─────────┘ │                           │ └─────────┘ │
│ ┌─────────┐ │                           │ ┌─────────┐ │
│ │ACL Mgr  │ │                           │ │ACL Mgr  │ │
│ └─────────┘ │                           │ └─────────┘ │
└─────────────┘                           └─────────────┘
```

### 1.2 Component Specifications

#### Key Manager
- **Responsibility**: Generate, store, and load ed25519 key pairs
- **Functions**:
  - `generateKeyPair()`: Create new ed25519 key pair
  - `loadPrivateKey(path)`: Load private key from secure storage
  - `loadPublicKey(path)`: Load public key from file
  - `exportPublicKey()`: Export public key in standard format
  - `getFingerprint()`: Calculate SHA-256 fingerprint of public key

#### Authentication Engine
- **Responsibility**: Execute authentication protocol
- **Functions**:
  - `initiateAuth()`: Start authentication handshake
  - `verifyChallenge()`: Verify challenge signature
  - `signChallenge()`: Sign authentication challenge
  - `validateTimestamp()`: Check timestamp within acceptable range

#### ACL Manager
- **Responsibility**: Manage allowlists and access control
- **Functions**:
  - `addAllowedKey(publicKey, metadata)`: Add key to allowlist
  - `removeAllowedKey(fingerprint)`: Remove key from allowlist
  - `isAllowed(publicKey)`: Check if key is in allowlist
  - `getKeyMetadata(fingerprint)`: Retrieve key metadata

## 2. Authentication Protocol Specification

### 2.1 Protocol Flow

```
Client                                Server
  │                                     │
  │─────(1) Connect Request────────────►│
  │    {client_public_key}              │
  │                                     │
  │◄────(2) Server Challenge───────────│
  │    {server_public_key,              │
  │     challenge_nonce,                │
  │     timestamp,                      │
  │     signature}                      │
  │                                     │
  │─────(3) Client Response────────────►│
  │    {challenge_signature,            │
  │     client_challenge,               │
  │     timestamp}                      │
  │                                     │
  │◄────(4) Server Verification────────│
  │    {client_challenge_signature,     │
  │     auth_result}                    │
  │                                     │
```

### 2.2 Message Specifications

#### Message 1: Connect Request
```json
{
  "type": "auth_connect",
  "version": "1.0",
  "client_public_key": "<base64_encoded_ed25519_public_key>",
  "timestamp": "<ISO8601_UTC_timestamp>"
}
```

#### Message 2: Server Challenge
```json
{
  "type": "auth_challenge",
  "version": "1.0",
  "server_public_key": "<base64_encoded_ed25519_public_key>",
  "challenge_nonce": "<32_byte_random_base64>",
  "timestamp": "<ISO8601_UTC_timestamp>",
  "signature": "<base64_ed25519_signature>"
}
```

**Signature covers**: `server_public_key || challenge_nonce || timestamp`

#### Message 3: Client Response
```json
{
  "type": "auth_response",
  "version": "1.0",
  "challenge_signature": "<base64_ed25519_signature>",
  "client_challenge": "<32_byte_random_base64>",
  "timestamp": "<ISO8601_UTC_timestamp>"
}
```

**challenge_signature covers**: `challenge_nonce || timestamp`

#### Message 4: Server Verification
```json
{
  "type": "auth_result",
  "version": "1.0",
  "client_challenge_signature": "<base64_ed25519_signature>",
  "auth_result": "success|failed",
  "failure_reason": "<optional_error_code>",
  "timestamp": "<ISO8601_UTC_timestamp>"
}
```

**client_challenge_signature covers**: `client_challenge || timestamp`

### 2.3 Cryptographic Specifications

#### Key Format
- **Algorithm**: ed25519 (Curve25519 with Edwards form)
- **Public Key Size**: 32 bytes
- **Private Key Size**: 64 bytes (32-byte seed + 32-byte public key)
- **Signature Size**: 64 bytes
- **Encoding**: Base64 for transmission, PEM for storage

#### Signature Scheme
```
signature = ed25519_sign(private_key, message)
verification = ed25519_verify(public_key, message, signature)
```

#### Message Construction
```
message_to_sign = field1 || separator || field2 || separator || field3
separator = 0x00 (null byte)
```

## 3. Data Models

### 3.1 Key Storage Format

#### Private Key File (PEM format)
```
-----BEGIN MCP PRIVATE KEY-----
<base64_encoded_64_byte_private_key>
-----END MCP PRIVATE KEY-----
```

#### Public Key File (PEM format)
```
-----BEGIN MCP PUBLIC KEY-----
<base64_encoded_32_byte_public_key>
-----END MCP PUBLIC KEY-----
```

### 3.2 Allowlist Data Structure

```json
{
  "version": "1.0",
  "updated_at": "2025-10-15T12:00:00Z",
  "keys": [
    {
      "fingerprint": "<sha256_hash_of_public_key_hex>",
      "public_key": "<base64_encoded_public_key>",
      "added_at": "2025-10-01T10:00:00Z",
      "added_by": "admin@example.com",
      "description": "Production client A",
      "metadata": {
        "client_name": "web-client-prod-01",
        "organization": "ExampleCorp"
      }
    }
  ]
}
```

### 3.3 Audit Log Entry

```json
{
  "timestamp": "2025-10-15T14:30:45.123Z",
  "event_type": "auth_attempt|auth_success|auth_failure",
  "direction": "client_to_server|server_to_client",
  "client_fingerprint": "<sha256_hex>",
  "server_fingerprint": "<sha256_hex>",
  "result": "success|failed",
  "failure_reason": "unknown_key|invalid_signature|timestamp_mismatch|replay_detected",
  "remote_address": "192.168.1.100:45678",
  "duration_ms": 5,
  "metadata": {
    "client_version": "1.2.3",
    "protocol_version": "1.0"
  }
}
```

## 4. Configuration Specification

### 4.1 Server Configuration

```yaml
mcp_auth:
  enabled: true
  mode: "enforced"  # enforced | permissive | disabled
  
  keys:
    private_key_path: "/etc/mcp/server-private-key.pem"
    public_key_path: "/etc/mcp/server-public-key.pem"
  
  client_allowlist:
    path: "/etc/mcp/client-allowlist.json"
    default_policy: "deny"  # deny | allow
    reload_interval: "5m"
  
  timestamp:
    max_skew_seconds: 300  # 5 minutes
    
  audit:
    enabled: true
    log_path: "/var/log/mcp/auth-audit.log"
    log_level: "info"  # debug | info | warn | error
    log_successes: true
    log_failures: true
```

### 4.2 Client Configuration

```yaml
mcp_auth:
  enabled: true
  
  keys:
    private_key_path: "~/.mcp/client-private-key.pem"
    public_key_path: "~/.mcp/client-public-key.pem"
  
  server_allowlist:
    path: "~/.mcp/server-allowlist.json"
    prompt_on_unknown: true  # Prompt user if server not in allowlist
    default_policy: "prompt"  # deny | allow | prompt
  
  timestamp:
    max_skew_seconds: 300
  
  audit:
    enabled: true
    log_path: "~/.mcp/auth-audit.log"
```

## 5. API Specifications

### 5.1 Key Management API

#### Generate Key Pair
```python
def generate_keypair(output_dir: str, name: str = "mcp") -> KeyPair:
    """
    Generate a new ed25519 key pair.
    
    Args:
        output_dir: Directory to store keys
        name: Base name for key files
        
    Returns:
        KeyPair object with public_key and private_key_path
        
    Raises:
        IOError: If unable to write key files
        PermissionError: If insufficient permissions
    """
```

#### Load Key Pair
```python
def load_keypair(private_key_path: str) -> KeyPair:
    """
    Load an existing key pair from disk.
    
    Args:
        private_key_path: Path to private key file
        
    Returns:
        KeyPair object
        
    Raises:
        FileNotFoundError: If key file doesn't exist
        InvalidKeyError: If key format is invalid
    """
```

### 5.2 Authentication API

#### Server-Side Authentication
```python
async def authenticate_client(
    client_public_key: bytes,
    connection: Connection
) -> AuthResult:
    """
    Authenticate an incoming client connection.
    
    Args:
        client_public_key: Client's ed25519 public key
        connection: Active connection object
        
    Returns:
        AuthResult with success status and metadata
        
    Raises:
        AuthenticationError: If authentication fails
        TimeoutError: If handshake times out (default 10s)
    """
```

#### Client-Side Authentication
```python
async def authenticate_server(
    server_address: str,
    expected_public_key: Optional[bytes] = None
) -> AuthResult:
    """
    Authenticate to an MCP server.
    
    Args:
        server_address: Server URL or address
        expected_public_key: Expected server public key (optional)
        
    Returns:
        AuthResult with success status and server public key
        
    Raises:
        AuthenticationError: If authentication fails
        UnknownServerError: If server not in allowlist
        KeyMismatchError: If server key doesn't match expected
    """
```

### 5.3 ACL Management API

#### Add to Allowlist
```python
def add_to_allowlist(
    public_key: bytes,
    description: str,
    metadata: Optional[Dict] = None
) -> bool:
    """
    Add a public key to the allowlist.
    
    Args:
        public_key: ed25519 public key to add
        description: Human-readable description
        metadata: Optional metadata dictionary
        
    Returns:
        True if added successfully
        
    Raises:
        DuplicateKeyError: If key already in allowlist
        ValidationError: If key format invalid
    """
```

#### Remove from Allowlist
```python
def remove_from_allowlist(fingerprint: str) -> bool:
    """
    Remove a key from the allowlist.
    
    Args:
        fingerprint: SHA-256 fingerprint of public key (hex)
        
    Returns:
        True if removed successfully
        
    Raises:
        KeyNotFoundError: If key not in allowlist
    """
```

---

# Edge Cases & Error Handling

## 1. Time-Related Edge Cases

### 1.1 Clock Skew
**Problem**: Client and server clocks are not synchronized

**Scenarios**:
- Skew within tolerance (≤5 minutes): Accept with warning
- Skew beyond tolerance (>5 minutes): Reject with specific error code
- Negative timestamps: Reject immediately

**Implementation**:
```python
def validate_timestamp(timestamp: datetime, max_skew: timedelta) -> bool:
    now = datetime.utcnow()
    skew = abs(now - timestamp)
    
    if skew > max_skew:
        raise TimestampSkewError(
            f"Timestamp skew {skew.total_seconds()}s exceeds maximum {max_skew.total_seconds()}s"
        )
    
    if skew > timedelta(minutes=1):
        logger.warning(f"Clock skew detected: {skew.total_seconds()}s")
    
    return True
```

### 1.2 Replay Attack Prevention
**Problem**: Attacker replays valid authentication messages

**Solution**: 
- Include timestamp in all signed messages
- Maintain sliding window of used nonces (last 10 minutes)
- Reject messages with reused nonces or old timestamps

**Implementation**:
```python
class NonceCache:
    def __init__(self, ttl_seconds: int = 600):
        self.cache = {}  # nonce -> expiry_time
        self.ttl = ttl_seconds
    
    def check_and_add(self, nonce: bytes, timestamp: datetime) -> bool:
        # Clean expired entries
        self._cleanup()
        
        # Check if nonce already used
        if nonce in self.cache:
            raise ReplayAttackError("Nonce reuse detected")
        
        # Add nonce with expiry
        expiry = timestamp + timedelta(seconds=self.ttl)
        self.cache[nonce] = expiry
        return True
```

### 1.3 Daylight Saving Time
**Problem**: DST transitions may affect timestamp comparisons

**Solution**: Always use UTC timestamps (no DST ambiguity)

### 1.4 Leap Seconds
**Problem**: Leap seconds may cause timestamp validation issues

**Solution**: Use TAI or handle 23:59:60 timestamps explicitly

## 2. Cryptographic Edge Cases

### 2.1 Weak Keys
**Problem**: Generated key has weak entropy

**Solution**:
- Use cryptographically secure random source
- ed25519 key space is large enough that weak keys are statistically impossible
- Validate key format but don't test for "weakness"

### 2.2 Key Reuse
**Problem**: Same key pair used across multiple contexts

**Solution**:
- Document recommended practice (separate keys per server)
- Support multiple key pairs per entity
- Allow key metadata to track usage context

### 2.3 Signature Malleability
**Problem**: ed25519 signatures could potentially be malleable

**Solution**: Use RFC 8032 compliant implementation which prevents malleability

## 3. Network Edge Cases

### 3.1 Connection Interruption
**Problem**: Connection drops during authentication handshake

**Scenarios**:
- After message 1: Client retries with exponential backoff
- After message 2: Client retries with same nonce (stateless server)
- After message 3: Server completes auth, client may not receive result
- After message 4: Authentication complete, normal reconnection

**Implementation**:
```python
async def authenticate_with_retry(
    server: str,
    max_retries: int = 3,
    timeout: float = 10.0
) -> AuthResult:
    for attempt in range(max_retries):
        try:
            result = await asyncio.wait_for(
                authenticate_server(server),
                timeout=timeout
            )
            return result
        except (ConnectionError, TimeoutError) as e:
            if attempt == max_retries - 1:
                raise
            await asyncio.sleep(2 ** attempt)  # Exponential backoff
```

### 3.2 Man-in-the-Middle
**Problem**: Attacker intercepts authentication messages

**Solution**: 
- Signatures prevent message tampering
- Challenge-response prevents replay
- Public key pinning prevents impersonation
- TOFU (Trust On First Use) model for unknown keys

### 3.3 Partial Message Delivery
**Problem**: Network delivers incomplete messages

**Solution**:
- Use length-prefixed message framing
- Include message integrity check (signature covers full message)
- Timeout and retry on incomplete messages

## 4. Storage Edge Cases

### 4.1 Corrupted Key Files
**Problem**: Key files corrupted on disk

**Detection**:
```python
def load_key_with_validation(path: str) -> bytes:
    try:
        with open(path, 'rb') as f:
            content = f.read()
        
        # Validate PEM structure
        if not content.startswith(b'-----BEGIN MCP'):
            raise InvalidKeyFormat("Missing PEM header")
        
        # Decode and validate length
        key = base64.b64decode(extract_pem_body(content))
        
        if len(key) not in [32, 64]:  # Public or private key
            raise InvalidKeyFormat(f"Invalid key length: {len(key)}")
        
        return key
    except Exception as e:
        logger.error(f"Key file corrupted: {path}")
        raise KeyCorruptionError(f"Cannot load key: {e}")
```

### 4.2 Allowlist Conflicts
**Problem**: Same public key with different metadata

**Solution**:
- Use fingerprint as primary key (prevents duplicates)
- Update metadata if key already exists
- Log warning on conflict

### 4.3 Concurrent Allowlist Modifications
**Problem**: Multiple processes modify allowlist simultaneously

**Solution**:
- Use file locking for allowlist updates
- Atomic write with rename
- Include version number in allowlist format

```python
import fcntl

def update_allowlist_atomic(path: str, data: dict):
    temp_path = f"{path}.tmp"
    
    # Write to temporary file
    with open(temp_path, 'w') as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        json.dump(data, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    
    # Atomic rename
    os.rename(temp_path, path)
```

## 5. Scale Edge Cases

### 5.1 Large Allowlists
**Problem**: Allowlist with 10,000+ entries

**Solutions**:
- Index by fingerprint hash
- Lazy load allowlist entries
- Use bloom filter for fast negative lookups
- Cache frequently used keys in memory

**Implementation**:
```python
class OptimizedAllowlist:
    def __init__(self, path: str):
        self.path = path
        self.index = {}  # fingerprint -> file_offset
        self.cache = LRUCache(maxsize=1000)
        self.bloom = BloomFilter(size=100000, fp_rate=0.001)
        
    def is_allowed(self, public_key: bytes) -> bool:
        fingerprint = sha256(public_key).hexdigest()
        
        # Fast negative lookup
        if fingerprint not in self.bloom:
            return False
        
        # Check cache
        if fingerprint in self.cache:
            return True
        
        # Load from disk using index
        return self._load_from_disk(fingerprint)
```

### 5.2 High Connection Rate
**Problem**: 1000+ auth requests per second

**Solutions**:
- Connection pooling for repeated clients
- Cache authentication results with TTL
- Parallel signature verification
- Rate limiting by source IP

### 5.3 Memory Exhaustion
**Problem**: Nonce cache grows unbounded

**Solution**: 
- TTL-based eviction of old nonces
- Maximum cache size with LRU eviction
- Periodic cleanup of expired entries

---

# Testing Strategy

## 1. Unit Tests

### 1.1 Cryptographic Operations
```python
class TestCryptography:
    def test_key_generation():
        """Test key pair generation produces valid keys"""
        keypair = generate_keypair("/tmp/test")
        assert len(keypair.public_key) == 32
        assert len(keypair.private_key) == 64
    
    def test_signature_verification():
        """Test signing and verification"""
        keypair = generate_keypair("/tmp/test")
        message = b"test message"
        signature = sign(keypair.private_key, message)
        assert verify(keypair.public_key, message, signature)
    
    def test_invalid_signature():
        """Test rejection of invalid signatures"""
        keypair = generate_keypair("/tmp/test")
        message = b"test message"
        wrong_message = b"wrong message"
        signature = sign(keypair.private_key, message)
        assert not verify(keypair.public_key, wrong_message, signature)
```

### 1.2 Timestamp Validation
```python
class TestTimestamp:
    def test_valid_timestamp():
        """Test acceptance of current timestamp"""
        now = datetime.utcnow()
        assert validate_timestamp(now, max_skew=timedelta(minutes=5))
    
    def test_skewed_timestamp_within_tolerance():
        """Test acceptance of skewed but valid timestamp"""
        skewed = datetime.utcnow() - timedelta(minutes=4)
        assert validate_timestamp(skewed, max_skew=timedelta(minutes=5))
    
    def test_skewed_timestamp_beyond_tolerance():
        """Test rejection of excessive skew"""
        skewed = datetime.utcnow() - timedelta(minutes=6)
        with pytest.raises(TimestampSkewError):
            validate_timestamp(skewed, max_skew=timedelta(minutes=5))
    
    def test_future_timestamp():
        """Test handling of future timestamps"""
        future = datetime.utcnow() + timedelta(minutes=4)
        assert validate_timestamp(future, max_skew=timedelta(minutes=5))
```

### 1.3 Nonce Management
```python
class TestNonceCache:
    def test_nonce_uniqueness():
        """Test detection of duplicate nonces"""
        cache = NonceCache()
        nonce = os.urandom(32)
        timestamp = datetime.utcnow()
        
        cache.check_and_add(nonce, timestamp)
        with pytest.raises(ReplayAttackError):
            cache.check_and_add(nonce, timestamp)
    
    def test_nonce_expiration():
        """Test expiration of old nonces"""
        cache = NonceCache(ttl_seconds=60)
        old_nonce = os.urandom(32)
        old_time = datetime.utcnow() - timedelta(minutes=5)
        
        cache.check_and_add(old_nonce, old_time)
        cache._cleanup()
        
        # Old nonce should be removed, can be reused
        cache.check_and_add(old_nonce, datetime.utcnow())
```

## 2. Integration Tests

### 2.1 Full Authentication Flow
```python
class TestAuthenticationFlow:
    async def test_successful_mutual_auth():
        """Test successful mutual authentication"""
        # Setup
        server = TestMCPServer()
        client = TestMCPClient()
        
        # Add keys to allowlists
        server.add_to_allowlist(client.public_key)
        client.add_to_allowlist(server.public_key)
        
        # Perform authentication
        result = await client.authenticate(server.address)
        
        assert result.success == True
        assert result.server_public_key == server.public_key
    
    async def test_unknown_client_rejection():
        """Test rejection of unknown client"""
        server = TestMCPServer(default_policy="deny")
        client = TestMCPClient()
        
        with pytest.raises(AuthenticationError) as exc:
            await client.authenticate(server.address)
        
        assert "unknown_key" in str(exc.value)
    
    async def test_unknown_server_rejection():
        """Test rejection of unknown server"""
        server = TestMCPServer()
        client = TestMCPClient(default_policy="deny")
        
        with pytest.raises(UnknownServerError):
            await client.authenticate(server.address)
```

### 2.2 Error Scenarios
```python
class TestErrorHandling:
    async def test_network_interruption():
        """Test handling of network interruption"""
        server = TestMCPServer()
        client = TestMCPClient()
        
        # Simulate network failure after challenge
        server.simulate_failure_after_message(2)
        
        with pytest.raises(TimeoutError):
            await client.authenticate(server.address, timeout=2.0)
    
    async def test_invalid_signature():
        """Test rejection of invalid signature"""
        server = TestMCPServer()
        malicious_client = MaliciousClient()
        
        result = await malicious_client.authenticate_with_bad_signature(server)
        
        assert result.success == False
        assert result.failure_reason == "invalid_signature"
```

## 3. Performance Tests

### 3.1 Latency Benchmarks
```python
class TestPerformance:
    def test_authentication_latency():
        """Measure end-to-end authentication latency"""
        server = TestMCPServer()
        client = TestMCPClient()
        
        latencies = []
        for _ in range(1000):
            start = time.perf_counter()
            await client.authenticate(server.address)
            end = time.perf_counter()
            latencies.append((end - start) * 1000)  # Convert to ms
        
        p50 = numpy.percentile(latencies, 50)
        p95 = numpy.percentile(latencies, 95)
        p99 = numpy.percentile(latencies, 99)
        
        assert p50 < 5.0, f"P50 latency {p50}ms exceeds 5ms target"
        assert p95 < 10.0, f"P95 latency {p95}ms exceeds 10ms target"
        assert p99 < 20.0, f"P99 latency {p99}ms exceeds 20ms target"
    
    def test_signature_verification_speed():
        """Measure signature verification performance"""
        keypair = generate_keypair("/tmp/test")
        message = b"test message" * 100
        signature = sign(keypair.private_key, message)
        
        start = time.perf_counter()
        for _ in range(10000):
            verify(keypair.public_key, message, signature)
        end = time.perf_counter()
        
        avg_time_us = (end - start) / 10000 * 1_000_000
        assert avg_time_us < 100, f"Verification took {avg_time_us}µs, expected <100µs"
```

### 3.2 Throughput Tests
```python
class TestThroughput:
    async def test_concurrent_authentications():
        """Test handling of concurrent auth requests"""
        server = TestMCPServer()
        clients = [TestMCPClient() for _ in range(100)]
        
        # Add all clients to allowlist
        for client in clients:
            server.add_to_allowlist(client.public_key)
        
        # Authenticate all clients concurrently
        start = time.perf_counter()
        results = await asyncio.gather(*[
            client.authenticate(server.address)
            for client in clients
        ])
        end = time.perf_counter()
        
        # All should succeed
        assert all(r.success for r in results)
        
        # Should complete in reasonable time
        total_time = end - start
        auths_per_second = len(clients) / total_time
        assert auths_per_second > 50, f"Only {auths_per_second} auth/s, expected >50"
```

### 3.3 Memory Tests
```python
class TestMemory:
    def test_nonce_cache_memory():
        """Test memory usage of nonce cache"""
        cache = NonceCache(ttl_seconds=600)
        
        # Add 10,000 nonces
        for _ in range(10000):
            nonce = os.urandom(32)
            cache.check_and_add(nonce, datetime.utcnow())
        
        # Measure memory usage
        import sys
        memory_bytes = sys.getsizeof(cache.cache)
        memory_mb = memory_bytes / (1024 * 1024)
        
        assert memory_mb < 1.0, f"Cache uses {memory_mb}MB, expected <1MB"
    
    def test_allowlist_memory():
        """Test memory usage of large allowlists"""
        allowlist = OptimizedAllowlist("/tmp/test-allowlist.json")
        
        # Add 10,000 keys
        for i in range(10000):
            key = generate_keypair("/tmp/test").public_key
            allowlist.add(key, f"Client {i}")
        
        # Measure memory
        import sys
        memory_mb = sys.getsizeof(allowlist.index) / (1024 * 1024)
        
        assert memory_mb < 5.0, f"Allowlist uses {memory_mb}MB, expected <5MB"
```

## 4. Security Tests

### 4.1 Replay Attack Tests
```python
class TestSecurity:
    async def test_replay_attack_prevention():
        """Test prevention of replay attacks"""
        server = TestMCPServer()
        client = TestMCPClient()
        
        # Capture authentication messages
        messages = []
        server.on_message = lambda m: messages.append(m)
        
        await client.authenticate(server.address)
        
        # Attempt to replay challenge response
        with pytest.raises(ReplayAttackError):
            await server.process_message(messages[-2])
    
    async def test_mitm_detection():
        """Test detection of MITM attacks"""
        real_server = TestMCPServer()
        mitm = MITMProxy(real_server)
        client = TestMCPClient()
        
        # Client knows real server's key
        client.add_to_allowlist(real_server.public_key)
        
        # Connect through MITM
        with pytest.raises(KeyMismatchError):
            await client.authenticate(mitm.address)
```

### 4.2 Timing Attack Tests
```python
class TestTimingSecurity:
    def test_constant_time_comparison():
        """Test that signature verification is constant time"""
        keypair = generate_keypair("/tmp/test")
        message = b"test message"
        valid_signature = sign(keypair.private_key, message)
        invalid_signature = os.urandom(64)
        
        # Measure verification times
        valid_times = []
        invalid_times = []
        
        for _ in range(10000):
            start = time.perf_counter()
            verify(keypair.public_key, message, valid_signature)
            valid_times.append(time.perf_counter() - start)
            
            start = time.perf_counter()
            try:
                verify(keypair.public_key, message, invalid_signature)
            except:
                pass
            invalid_times.append(time.perf_counter() - start)
        
        # Statistical test for timing differences
        from scipy import stats
        _, p_value = stats.ttest_ind(valid_times, invalid_times)
        
        # High p-value means no significant timing difference
        assert p_value > 0.05, "Timing attack vulnerability detected"
```

## 5. Edge Case Tests

### 5.1 Clock Skew Tests
```python
class TestClockSkew:
    async def test_maximum_skew_acceptance():
        """Test acceptance at maximum clock skew"""
        server = TestMCPServer(max_skew_seconds=300)
        client = TestMCPClient()
        
        # Simulate client clock 4:59 behind
        client.time_offset = timedelta(minutes=-4, seconds=-59)
        
        result = await client.authenticate(server.address)
        assert result.success == True
    
    async def test_excessive_skew_rejection():
        """Test rejection beyond maximum skew"""
        server = TestMCPServer(max_skew_seconds=300)
        client = TestMCPClient()
        
        # Simulate client clock 5:01 behind
        client.time_offset = timedelta(minutes=-5, seconds=-1)
        
        with pytest.raises(TimestampSkewError):
            await client.authenticate(server.address)
```

### 5.2 Concurrent Modification Tests
```python
class TestConcurrency:
    async def test_concurrent_allowlist_updates():
        """Test thread-safety of allowlist modifications"""
        allowlist = OptimizedAllowlist("/tmp/test-allowlist.json")
        
        async def add_keys(start: int, count: int):
            for i in range(start, start + count):
                key = generate_keypair("/tmp/test").public_key
                allowlist.add(key, f"Client {i}")
        
        # Add keys from multiple coroutines
        await asyncio.gather(
            add_keys(0, 1000),
            add_keys(1000, 1000),
            add_keys(2000, 1000)
        )
        
        # Verify all keys were added
        assert len(allowlist.keys) == 3000
```

---

# Performance Considerations

## 1. Optimization Strategies

### 1.1 Signature Verification
**Target**: <1ms per verification

**Optimizations**:
- Use optimized ed25519 library (libsodium)
- Batch verify multiple signatures when possible
- Cache verification results for repeated keys
- Use hardware acceleration (AVX2/NEON) when available

**Benchmark**:
```
Single signature verification: ~50µs
Batch verification (100 sigs): ~40µs per signature
Hardware-accelerated: ~30µs per signature
```

### 1.2 Connection Pooling
**Problem**: Authentication overhead for repeated connections

**Solution**:
```python
class AuthenticatedConnectionPool:
    def __init__(self, max_size: int = 100):
        self.pool = {}  # server_fingerprint -> Connection
        self.max_size = max_size
        self.ttl = timedelta(hours=1)
    
    async def get_connection(self, server: str) -> Connection:
        fingerprint = get_server_fingerprint(server)
        
        # Check for existing authenticated connection
        if fingerprint in self.pool:
            conn = self.pool[fingerprint]
            if conn.is_alive() and not conn.is_expired():
                return conn
        
        # Create new authenticated connection
        conn = await authenticate_and_connect(server)
        self.pool[fingerprint] = conn
        return conn
```

### 1.3 Allowlist Indexing
**Target**: O(1) lookup for allowlist checks

**Implementation**:
```python
class IndexedAllowlist:
    def __init__(self):
        self.by_fingerprint = {}  # SHA-256 fingerprint -> key data
        self.by_prefix = {}       # First 8 bytes -> list of keys
        self.bloom = BloomFilter(size=100000, fp_rate=0.001)
    
    def is_allowed(self, public_key: bytes) -> bool:
        fingerprint = sha256(public_key).digest()
        
        # Fast negative lookup (O(1))
        if fingerprint not in self.bloom:
            return False
        
        # Definitive lookup (O(1))
        return fingerprint in self.by_fingerprint
```

## 2. Scalability Considerations

### 2.1 Horizontal Scaling
**Challenge**: Shared authentication state across servers

**Solutions**:
- Stateless authentication (no session state)
- Distributed allowlist synchronization
- Redis-backed nonce cache for shared state

**Architecture**:
```
              Load Balancer
                    │
        ┌───────────┼───────────┐
        │           │           │
    Server 1    Server 2    Server 3
        │           │           │
        └───────────┼───────────┘
                    │
              Redis Cluster
            (Shared Nonce Cache)
```

### 2.2 Rate Limiting
**Target**: Prevent DoS while allowing legitimate traffic

**Implementation**:
```python
class RateLimiter:
    def __init__(self, max_attempts: int = 10, window_seconds: int = 60):
        self.max_attempts = max_attempts
        self.window = window_seconds
        self.attempts = {}  # IP address -> list of timestamps
    
    def check_rate_limit(self, remote_addr: str) -> bool:
        now = time.time()
        
        # Clean old attempts
        if remote_addr in self.attempts:
            self.attempts[remote_addr] = [
                t for t in self.attempts[remote_addr]
                if now - t < self.window
            ]
        else:
            self.attempts[remote_addr] = []
        
        # Check rate limit
        if len(self.attempts[remote_addr]) >= self.max_attempts:
            raise RateLimitExceeded(
                f"Too many auth attempts from {remote_addr}"
            )
        
        self.attempts[remote_addr].append(now)
        return True
```

### 2.3 Memory Management
**Targets**:
- Nonce cache: <1MB per 10,000 entries
- Allowlist index: <5MB per 10,000 keys
- Total memory overhead: <100MB

**Strategies**:
- TTL-based eviction
- LRU caching for hot keys
- Lazy loading of allowlist
- Periodic garbage collection

## 3. Performance Monitoring

### 3.1 Key Metrics
```python
class AuthMetrics:
    # Latency metrics
    auth_latency_histogram = Histogram(
        'mcp_auth_duration_seconds',
        'Authentication duration',
        buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
    )
    
    # Throughput metrics
    auth_total = Counter(
        'mcp_auth_total',
        'Total authentication attempts',
        ['result', 'direction']
    )
    
    # Error metrics
    auth_errors = Counter(
        'mcp_auth_errors_total',
        'Authentication errors',
        ['error_type']
    )
    
    # Resource metrics
    nonce_cache_size = Gauge(
        'mcp_nonce_cache_size',
        'Number of entries in nonce cache'
    )
```

### 3.2 Performance Alerts
```yaml
alerts:
  - name: HighAuthLatency
    condition: p95(auth_latency) > 50ms
    severity: warning
    
  - name: AuthFailureRate
    condition: rate(auth_errors) > 0.1
    severity: critical
    
  - name: NonceCacheExhaustion
    condition: nonce_cache_size > 100000
    severity: warning
```

## 4. Optimization Checklist

### Pre-deployment
- [ ] Benchmark key operations on target hardware
- [ ] Profile memory usage under load
- [ ] Test with production-scale allowlists
- [ ] Verify signature verification performance
- [ ] Test connection pool behavior
- [ ] Validate rate limiting effectiveness

### Post-deployment
- [ ] Monitor P95/P99 latency
- [ ] Track authentication success/failure rates
- [ ] Monitor memory usage over time
- [ ] Analyze slow authentication requests
- [ ] Review cache hit rates
- [ ] Check for memory leaks

## 5. Hardware Requirements

### Minimum Requirements
- **CPU**: 2 cores, 2.0 GHz
- **RAM**: 1GB available
- **Storage**: 100MB for keys and logs
- **Network**: 10 Mbps

### Recommended for Production
- **CPU**: 4+ cores, 3.0+ GHz with AES-NI
- **RAM**: 4GB+ available
- **Storage**: 10GB SSD for logs and allowlists
- **Network**: 1 Gbps

### Performance Expectations
| Hardware | Auth/Second | P95 Latency | Max Allowlist |
|----------|-------------|-------------|---------------|
| Minimum | 100 | 20ms | 1,000 |
| Recommended | 1,000 | 5ms | 100,000 |
| High-end | 10,000+ | 2ms | 1,000,000+ |

---

## Appendix A: Security Considerations

### Threat Model
1. **Network Attacker**: Can intercept, modify, replay traffic
2. **Malicious Client**: Attempts unauthorized access
3. **Malicious Server**: Attempts to impersonate legitimate server
4. **Insider Threat**: Has access to some but not all keys

### Security Guarantees
- **Authentication**: Both parties prove identity
- **Integrity**: Messages cannot be tampered with
- **Replay Protection**: Old messages cannot be reused
- **Forward Secrecy**: Compromise of session doesn't affect others

### Non-Guarantees
- **Anonymity**: Public keys are visible
- **Revocation**: No real-time key revocation in v1
- **Key Rotation**: No automated rotation in v1

## Appendix B: Compatibility Matrix

| Component | Version | Compatible |
|-----------|---------|------------|
| Protocol Version | 1.0 | ✓ |
| ed25519 (RFC 8032) | All | ✓ |
| Python | 3.8+ | ✓ |
| Node.js | 16+ | ✓ |
| Go | 1.18+ | ✓ |
| Rust | 1.60+ | ✓ |

## Appendix C: Migration Guide

### From No Authentication
1. Generate server and client key pairs
2. Deploy in permissive mode (log but don't enforce)
3. Build allowlists from logs
4. Switch to enforced mode
5. Monitor for issues

### Key Distribution
- Out-of-band exchange (email, Slack, etc.)
- Central key registry (future enhancement)
- Trust-on-first-use (TOFU) with confirmation

---

**Document End**

*This PRD/FRD is a living document and should be updated as requirements evolve.*