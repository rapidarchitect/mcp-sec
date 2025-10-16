# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Repository Purpose

This repository contains the Product Requirements Document (PRD) and Functional Requirements Document (FRD) for an MCP PKI Authentication System. It defines a mutual authentication system for the Model Context Protocol (MCP) using ed25519 public key infrastructure, enabling bidirectional identity verification between MCP servers and clients.

## System Architecture Overview

The MCP PKI Authentication System consists of four core components working together:

**Key Manager**: Handles ed25519 key pair generation, storage, and loading. Manages both public and private keys with PEM format storage and SHA-256 fingerprint calculation for key identification.

**Authentication Engine**: Executes the 4-message authentication protocol flow. Performs challenge-response authentication with signature verification, timestamp validation (±5 minutes clock skew tolerance), and nonce management to prevent replay attacks.

**ACL Manager**: Maintains allowlists for both servers and clients. Uses fingerprint-based indexing for O(1) lookups and supports metadata association with keys for organizational tracking.

**Protocol Flow**: Client initiates with public key → Server responds with signed challenge → Client signs challenge and sends counter-challenge → Server verifies and completes mutual authentication.

Key design decisions include using ed25519 for signatures (32-byte public keys, 64-byte signatures), stateless server design for scalability, and comprehensive audit logging for security compliance.

## Development Commands

*Note: This repository currently contains specification documents only. Implementation is pending.*

### Docker-Based Testing

All testing should be containerized to ensure consistent environments across development machines and CI/CD:

```bash
# Build test environment
docker build -t mcp-pki-test -f Dockerfile.test .

# Run all tests
docker run --rm mcp-pki-test

# Run specific test suite
docker run --rm mcp-pki-test pytest tests/test_crypto.py

# Interactive development container
docker run --rm -it -v $(pwd):/workspace mcp-pki-test bash

# Performance benchmarks
docker run --rm mcp-pki-test pytest tests/performance/ --benchmark-only

# Security tests
docker run --rm mcp-pki-test pytest tests/security/ -v
```

### Multi-Language Implementation Commands

When implementation begins, expected commands will include:

```bash
# Python implementation
docker run --rm mcp-pki-test pytest tests/
docker run --rm mcp-pki-test pytest tests/test_crypto.py::TestKeyGeneration

# Go implementation  
docker run --rm mcp-pki-test go test ./...
docker run --rm mcp-pki-test go test -run TestAuthenticationFlow ./pkg/auth

# Node.js implementation
docker run --rm mcp-pki-test npm test
docker run --rm mcp-pki-test npm run test:crypto

# Cross-language integration tests
docker-compose -f docker-compose.test.yml up --abort-on-container-exit
```

### Linting and Formatting

```bash
# Language-agnostic linting in containers
docker run --rm mcp-pki-test make lint
docker run --rm mcp-pki-test make format
docker run --rm mcp-pki-test make security-scan
```

## Git Workflow for Multi-Agent Development

### Feature Branch Strategy

Use feature branches or worktrees to enable multiple AI agents or workstreams to work simultaneously without conflicts:

```bash
# Create feature branch for specific component
git checkout -b feature/key-manager
git checkout -b feature/auth-engine
git checkout -b feature/acl-manager
git checkout -b feature/protocol-handler

# Create implementation-specific branches
git checkout -b impl/python-crypto
git checkout -b impl/go-server
git checkout -b impl/nodejs-client
git checkout -b impl/rust-performance
```

### Git Worktrees for Parallel Development

Use worktrees to work on multiple implementations simultaneously:

```bash
# Create worktrees for different implementations
git worktree add ../mcp-sec-python impl/python-crypto
git worktree add ../mcp-sec-go impl/go-server  
git worktree add ../mcp-sec-nodejs impl/nodejs-client
git worktree add ../mcp-sec-rust impl/rust-performance

# List active worktrees
git worktree list

# Remove completed worktree
git worktree remove ../mcp-sec-python
```

### Branch Naming Conventions

- `feature/<component>`: Core system components
- `impl/<language>-<focus>`: Language-specific implementations  
- `test/<test-type>`: Specialized testing (performance, security, integration)
- `docs/<topic>`: Documentation improvements
- `fix/<issue>`: Bug fixes and patches

### Integration Strategy

```bash
# Merge feature branches through PRs
git checkout main
git pull origin main
git merge --no-ff feature/key-manager

# Rebase implementation branches regularly
git checkout impl/python-crypto
git rebase main

# Create integration branch for testing multiple components
git checkout -b integration/auth-flow
git merge feature/key-manager
git merge feature/auth-engine
# Run integration tests in Docker
docker-compose -f docker-compose.integration.yml up
```

## Important Requirements

**Cryptographic Specifications**:
- All implementations MUST use ed25519 (RFC 8032 compliant)
- Private keys MUST be stored encrypted at rest
- Signatures MUST include timestamps to prevent replay attacks
- Nonce cache MUST prevent duplicate challenge reuse

**Performance Targets**:
- Authentication overhead: <10ms per connection
- Signature verification: <1ms per operation
- Memory overhead: <1MB per 10,000 cached keys

**Security Requirements**:
- Challenge-response MUST use unique nonces per authentication
- Timestamp validation MUST handle clock skew up to ±5 minutes
- Failed authentication attempts MUST NOT leak timing information
- Audit logging MUST capture all authentication attempts

**Message Format**:
All authentication messages use JSON with base64-encoded binary data. Message signatures cover concatenated fields separated by null bytes (0x00).

## Implementation Status

**Current State**: Specification phase complete
**Next Steps**: 
1. Choose implementation language(s) - candidates include Python, Go, Node.js, Rust
2. Create project structure with package/module organization
3. Implement core cryptographic operations with test coverage
4. Build authentication protocol handlers
5. Add configuration management and audit logging
6. Create CLI tools for key management

**Key Files**:
- `mcp_pki_auth_prd_frd.md`: Complete specification document with protocol details, API specifications, testing strategy, and performance considerations
- `Dockerfile.test.example`: Multi-stage Docker configuration for testing across languages
- `docker-compose.test.yml.example`: Orchestration for integration testing, performance benchmarks, and security tests
- `Makefile.example`: Comprehensive build and test automation with Git workflow helpers

**Getting Started with Implementation**:
1. Copy example files: `make setup-test-env`
2. Build test environment: `make build` 
3. Generate test keys: `make generate-test-keys`
4. Run tests: `make test` or `make test-integration`

## Testing Strategy

The specification defines comprehensive testing including:
- Unit tests for cryptographic operations
- Integration tests for full authentication flows  
- Performance benchmarks for latency and throughput
- Security tests for replay attack prevention and timing attacks
- Edge case testing for clock skew, network interruption, and concurrent operations

Target test coverage: 95%+ for cryptographic and authentication code paths.