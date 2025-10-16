# Makefile for MCP PKI Authentication System
# This is an example - adapt based on chosen implementation language(s)

.PHONY: help build test test-all test-python test-go test-nodejs test-integration \
        test-performance test-security lint format clean setup-test-env \
        docker-build docker-test docker-clean

# Default target
help:
	@echo "MCP PKI Authentication System - Development Commands"
	@echo ""
	@echo "Docker-based testing:"
	@echo "  build                Build test Docker image"
	@echo "  test                 Run all tests in Docker"
	@echo "  test-python          Run Python tests only"
	@echo "  test-go              Run Go tests only"
	@echo "  test-nodejs          Run Node.js tests only"
	@echo "  test-integration     Run cross-language integration tests"
	@echo "  test-performance     Run performance benchmarks"
	@echo "  test-security        Run security tests"
	@echo ""
	@echo "Code quality:"
	@echo "  lint                 Run all linters"
	@echo "  format               Format all code"
	@echo ""
	@echo "Utilities:"
	@echo "  setup-test-env       Set up test environment"
	@echo "  clean                Clean up test artifacts"
	@echo ""

# Docker image building
build:
	@echo "Building test Docker image..."
	docker build -t mcp-pki-test -f Dockerfile.test .

docker-build: build

# Core testing targets
test: build
	@echo "Running all tests in Docker..."
	docker run --rm -v $(PWD):/workspace mcp-pki-test make test-all

test-all:
	@echo "Running comprehensive test suite..."
	@if command -v pytest >/dev/null 2>&1; then \
		pytest tests/ -v --tb=short --durations=10; \
	fi
	@if command -v go >/dev/null 2>&1 && [ -f go.mod ]; then \
		go test -v ./... -race -coverprofile=coverage.out; \
	fi
	@if command -v npm >/dev/null 2>&1 && [ -f package.json ]; then \
		npm test; \
	fi
	@if command -v cargo >/dev/null 2>&1 && [ -f Cargo.toml ]; then \
		cargo test --all-features; \
	fi

# Language-specific testing
test-python: build
	@echo "Running Python tests..."
	docker run --rm -v $(PWD):/workspace mcp-pki-test pytest tests/python/ -v

test-go: build
	@echo "Running Go tests..."
	docker run --rm -v $(PWD):/workspace mcp-pki-test go test ./pkg/... -v -race

test-nodejs: build
	@echo "Running Node.js tests..."
	docker run --rm -v $(PWD):/workspace mcp-pki-test npm test

test-rust: build
	@echo "Running Rust tests..."
	docker run --rm -v $(PWD):/workspace mcp-pki-test cargo test --all-features

# Specialized testing
test-integration: build
	@echo "Running integration tests with docker-compose..."
	docker-compose -f docker-compose.test.yml up --build --abort-on-container-exit integration-tests
	docker-compose -f docker-compose.test.yml down

test-performance: build
	@echo "Running performance benchmarks..."
	docker-compose -f docker-compose.test.yml up --build --abort-on-container-exit performance-tests
	docker-compose -f docker-compose.test.yml down

test-security: build
	@echo "Running security tests..."
	docker-compose -f docker-compose.test.yml up --build --abort-on-container-exit security-tests
	docker-compose -f docker-compose.test.yml down

# Individual test suites
test-crypto:
	docker run --rm -v $(PWD):/workspace mcp-pki-test pytest tests/test_crypto.py -v

test-auth:
	docker run --rm -v $(PWD):/workspace mcp-pki-test pytest tests/test_auth.py -v

test-acl:
	docker run --rm -v $(PWD):/workspace mcp-pki-test pytest tests/test_acl.py -v

# Code quality
lint: build
	@echo "Running linters..."
	docker run --rm -v $(PWD):/workspace mcp-pki-test sh -c '\
		if command -v flake8 >/dev/null 2>&1; then flake8 src/ tests/; fi && \
		if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run; fi && \
		if command -v eslint >/dev/null 2>&1; then eslint src/ tests/; fi && \
		if command -v cargo >/dev/null 2>&1; then cargo clippy --all-targets --all-features; fi \
	'

format: build
	@echo "Formatting code..."
	docker run --rm -v $(PWD):/workspace mcp-pki-test sh -c '\
		if command -v black >/dev/null 2>&1; then black src/ tests/; fi && \
		if command -v gofmt >/dev/null 2>&1; then gofmt -w .; fi && \
		if command -v prettier >/dev/null 2>&1; then prettier --write src/ tests/; fi && \
		if command -v cargo >/dev/null 2>&1; then cargo fmt; fi \
	'

security-scan: build
	@echo "Running security scans..."
	docker run --rm -v $(PWD):/workspace mcp-pki-test sh -c '\
		if command -v bandit >/dev/null 2>&1; then bandit -r src/; fi && \
		if command -v gosec >/dev/null 2>&1; then gosec ./...; fi && \
		if command -v npm >/dev/null 2>&1; then npm audit; fi && \
		if command -v cargo >/dev/null 2>&1; then cargo audit; fi \
	'

# Environment setup
setup-test-env:
	@echo "Setting up test environment..."
	@mkdir -p test-results test-keys logs
	@if [ ! -f docker-compose.test.yml ]; then \
		cp docker-compose.test.yml.example docker-compose.test.yml; \
		echo "Created docker-compose.test.yml from example"; \
	fi
	@if [ ! -f Dockerfile.test ]; then \
		cp Dockerfile.test.example Dockerfile.test; \
		echo "Created Dockerfile.test from example"; \
	fi

# Key generation for testing
generate-test-keys: build
	@echo "Generating test key pairs..."
	@mkdir -p test-keys
	docker run --rm -v $(PWD)/test-keys:/keys mcp-pki-test sh -c '\
		python3 -c "import os; from cryptography.hazmat.primitives import serialization; from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey; \
		server_key = Ed25519PrivateKey.generate(); \
		client_key = Ed25519PrivateKey.generate(); \
		open(\"/keys/server-private.pem\", \"wb\").write(server_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())); \
		open(\"/keys/server-public.pem\", \"wb\").write(server_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)); \
		open(\"/keys/client-private.pem\", \"wb\").write(client_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())); \
		open(\"/keys/client-public.pem\", \"wb\").write(client_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))" \
	'
	@echo "Test keys generated in test-keys/"

# Cleanup
clean:
	@echo "Cleaning up test artifacts..."
	docker-compose -f docker-compose.test.yml down -v 2>/dev/null || true
	docker system prune -f
	rm -rf test-results/ .pytest_cache/ .coverage htmlcov/
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

docker-clean: clean
	@echo "Cleaning up Docker images..."
	docker rmi mcp-pki-test 2>/dev/null || true
	docker image prune -f

# Continuous Integration helpers
ci-test: setup-test-env build test-all

# Development helpers
dev-shell: build
	@echo "Starting development shell in Docker..."
	docker run --rm -it -v $(PWD):/workspace mcp-pki-test bash

watch-tests: build
	@echo "Watching tests (requires entr)..."
	find src/ tests/ -name "*.py" -o -name "*.go" -o -name "*.js" -o -name "*.rs" | \
		entr -c make test

# Git workflow helpers
create-feature-branch:
	@read -p "Enter feature name: " feature && \
	git checkout -b feature/$$feature && \
	echo "Created feature branch: feature/$$feature"

create-impl-branch:
	@read -p "Enter language-focus (e.g., python-crypto): " impl && \
	git checkout -b impl/$$impl && \
	echo "Created implementation branch: impl/$$impl"

create-worktree:
	@read -p "Enter worktree name and branch (e.g., ../mcp-sec-python impl/python-crypto): " worktree branch && \
	git worktree add $$worktree $$branch && \
	echo "Created worktree: $$worktree -> $$branch"