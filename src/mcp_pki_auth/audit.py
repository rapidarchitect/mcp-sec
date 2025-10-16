"""
Audit logging system for MCP PKI Authentication System.

Provides structured JSON logging for authentication events, performance metrics,
and security monitoring with configurable outputs and filtering.
"""

import json
import time
import threading
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, Any, Optional, List, Union, TextIO
from dataclasses import dataclass, asdict

import structlog


class EventType(str, Enum):
    """Audit event types."""
    AUTH_ATTEMPT = "auth_attempt"
    AUTH_SUCCESS = "auth_success" 
    AUTH_FAILURE = "auth_failure"
    KEY_GENERATED = "key_generated"
    KEY_LOADED = "key_loaded"
    ALLOWLIST_UPDATED = "allowlist_updated"
    CONFIG_LOADED = "config_loaded"
    REPLAY_ATTACK_BLOCKED = "replay_attack_blocked"
    TIMESTAMP_ERROR = "timestamp_error"
    RATE_LIMIT_HIT = "rate_limit_hit"
    PERFORMANCE_METRIC = "performance_metric"


class LogLevel(str, Enum):
    """Log levels."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class AuditEvent:
    """Structured audit event."""
    timestamp: str
    event_type: EventType
    level: LogLevel
    message: str
    component: str
    session_id: Optional[str] = None
    client_fingerprint: Optional[str] = None
    server_fingerprint: Optional[str] = None
    remote_address: Optional[str] = None
    duration_ms: Optional[float] = None
    result: Optional[str] = None
    failure_reason: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = asdict(self)
        # Remove None values
        return {k: v for k, v in data.items() if v is not None}


@dataclass
class PerformanceMetric:
    """Performance measurement."""
    operation: str
    duration_ms: float
    count: int = 1
    success_rate: Optional[float] = None
    metadata: Optional[Dict[str, Any]] = None


class AuditLogger:
    """Thread-safe audit logger with multiple output destinations."""
    
    def __init__(
        self,
        enabled: bool = True,
        log_level: LogLevel = LogLevel.INFO,
        log_file_path: Optional[Union[str, Path]] = None,
        log_successes: bool = True,
        log_failures: bool = True,
        max_file_size_mb: int = 100,
        backup_count: int = 5,
        console_output: bool = False
    ):
        """
        Initialize audit logger.
        
        Args:
            enabled: Enable audit logging
            log_level: Minimum log level to record
            log_file_path: Path to log file (None for no file logging)
            log_successes: Log successful authentications
            log_failures: Log failed authentications
            max_file_size_mb: Maximum log file size before rotation
            backup_count: Number of backup files to keep
            console_output: Also output to console
        """
        self.enabled = enabled
        self.log_level = log_level
        self.log_file_path = Path(log_file_path) if log_file_path else None
        self.log_successes = log_successes
        self.log_failures = log_failures
        self.console_output = console_output
        
        # Thread safety
        self._lock = threading.Lock()
        
        # Performance tracking
        self._metrics: Dict[str, List[float]] = {}
        self._event_counts: Dict[EventType, int] = {event: 0 for event in EventType}
        
        # File handling
        self._log_file: Optional[TextIO] = None
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        self.backup_count = backup_count
        
        # Setup structured logger
        self._setup_structured_logger()
        
        # Open log file if specified
        if self.log_file_path and self.enabled:
            self._setup_log_file()
    
    def _setup_structured_logger(self) -> None:
        """Setup structlog configuration."""
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.JSONRenderer()
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        
        self._logger = structlog.get_logger("mcp_pki_auth.audit")
    
    def _setup_log_file(self) -> None:
        """Setup log file with rotation."""
        if self.log_file_path:
            # Ensure parent directory exists
            self.log_file_path.parent.mkdir(parents=True, exist_ok=True)
            
            try:
                self._log_file = open(self.log_file_path, 'a', encoding='utf-8')
            except Exception as e:
                print(f"Warning: Failed to open audit log file {self.log_file_path}: {e}")
                self._log_file = None
    
    def _rotate_log_file(self) -> None:
        """Rotate log file if it exceeds size limit."""
        if not self._log_file or not self.log_file_path:
            return
        
        try:
            if self.log_file_path.stat().st_size > self.max_file_size_bytes:
                self._log_file.close()
                
                # Rotate existing backup files
                for i in range(self.backup_count - 1, 0, -1):
                    old_backup = self.log_file_path.with_suffix(f'.{i}')
                    new_backup = self.log_file_path.with_suffix(f'.{i+1}')
                    if old_backup.exists():
                        if new_backup.exists():
                            new_backup.unlink()
                        old_backup.rename(new_backup)
                
                # Move current log to .1
                backup_path = self.log_file_path.with_suffix('.1')
                if backup_path.exists():
                    backup_path.unlink()
                self.log_file_path.rename(backup_path)
                
                # Open new log file
                self._log_file = open(self.log_file_path, 'w', encoding='utf-8')
                
        except Exception as e:
            print(f"Warning: Log rotation failed: {e}")
    
    def _should_log_event(self, event_type: EventType, level: LogLevel) -> bool:
        """Check if event should be logged based on configuration."""
        if not self.enabled:
            return False
        
        # Check log level
        level_order = [LogLevel.DEBUG, LogLevel.INFO, LogLevel.WARNING, LogLevel.ERROR, LogLevel.CRITICAL]
        if level_order.index(level) < level_order.index(self.log_level):
            return False
        
        # Check event type filtering
        if event_type == EventType.AUTH_SUCCESS and not self.log_successes:
            return False
        
        if event_type == EventType.AUTH_FAILURE and not self.log_failures:
            return False
        
        return True
    
    def log_event(self, event: AuditEvent) -> None:
        """Log an audit event."""
        if not self._should_log_event(event.event_type, event.level):
            return
        
        with self._lock:
            # Update counters
            self._event_counts[event.event_type] += 1
            
            # Convert to JSON
            event_dict = event.to_dict()
            event_json = json.dumps(event_dict, default=str)
            
            # Log to file
            if self._log_file:
                try:
                    self._log_file.write(event_json + '\n')
                    self._log_file.flush()
                    self._rotate_log_file()
                except Exception as e:
                    print(f"Warning: Failed to write to audit log: {e}")
            
            # Log to console if enabled
            if self.console_output:
                print(f"AUDIT: {event_json}")
            
            # Log via structlog
            self._logger.info("audit_event", **event_dict)
    
    def log_auth_attempt(
        self,
        client_fingerprint: Optional[str] = None,
        server_fingerprint: Optional[str] = None,
        remote_address: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log authentication attempt."""
        event = AuditEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=EventType.AUTH_ATTEMPT,
            level=LogLevel.INFO,
            message="Authentication attempt started",
            component="auth_engine",
            client_fingerprint=client_fingerprint,
            server_fingerprint=server_fingerprint,
            remote_address=remote_address,
            session_id=session_id,
            metadata=metadata
        )
        self.log_event(event)
    
    def log_auth_success(
        self,
        client_fingerprint: str,
        server_fingerprint: str,
        duration_ms: float,
        remote_address: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log successful authentication."""
        event = AuditEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=EventType.AUTH_SUCCESS,
            level=LogLevel.INFO,
            message="Authentication successful",
            component="auth_engine",
            client_fingerprint=client_fingerprint,
            server_fingerprint=server_fingerprint,
            remote_address=remote_address,
            session_id=session_id,
            duration_ms=duration_ms,
            result="success",
            metadata=metadata
        )
        self.log_event(event)
    
    def log_auth_failure(
        self,
        failure_reason: str,
        client_fingerprint: Optional[str] = None,
        server_fingerprint: Optional[str] = None,
        duration_ms: Optional[float] = None,
        remote_address: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log authentication failure."""
        event = AuditEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=EventType.AUTH_FAILURE,
            level=LogLevel.WARNING,
            message=f"Authentication failed: {failure_reason}",
            component="auth_engine",
            client_fingerprint=client_fingerprint,
            server_fingerprint=server_fingerprint,
            remote_address=remote_address,
            session_id=session_id,
            duration_ms=duration_ms,
            result="failed",
            failure_reason=failure_reason,
            metadata=metadata
        )
        self.log_event(event)
    
    def log_security_event(
        self,
        event_type: EventType,
        message: str,
        level: LogLevel = LogLevel.WARNING,
        client_fingerprint: Optional[str] = None,
        remote_address: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log security-related events."""
        event = AuditEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            level=level,
            message=message,
            component="security",
            client_fingerprint=client_fingerprint,
            remote_address=remote_address,
            metadata=metadata
        )
        self.log_event(event)
    
    def log_performance_metric(
        self,
        operation: str,
        duration_ms: float,
        success_rate: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log performance metric."""
        with self._lock:
            if operation not in self._metrics:
                self._metrics[operation] = []
            self._metrics[operation].append(duration_ms)
        
        event = AuditEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=EventType.PERFORMANCE_METRIC,
            level=LogLevel.DEBUG,
            message=f"Performance metric: {operation}",
            component="performance",
            duration_ms=duration_ms,
            metadata={
                "operation": operation,
                "success_rate": success_rate,
                **(metadata or {})
            }
        )
        self.log_event(event)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get audit logging statistics."""
        with self._lock:
            # Calculate performance stats
            perf_stats = {}
            for operation, durations in self._metrics.items():
                if durations:
                    perf_stats[operation] = {
                        "count": len(durations),
                        "avg_ms": sum(durations) / len(durations),
                        "min_ms": min(durations),
                        "max_ms": max(durations),
                        "p95_ms": sorted(durations)[int(len(durations) * 0.95)] if len(durations) > 20 else None
                    }
            
            return {
                "enabled": self.enabled,
                "log_level": self.log_level,
                "log_file_path": str(self.log_file_path) if self.log_file_path else None,
                "event_counts": dict(self._event_counts),
                "performance_metrics": perf_stats,
                "total_events": sum(self._event_counts.values())
            }
    
    def close(self) -> None:
        """Close audit logger and cleanup resources."""
        with self._lock:
            if self._log_file:
                self._log_file.close()
                self._log_file = None
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


class AuditContext:
    """Context manager for tracking operations with automatic performance logging."""
    
    def __init__(
        self, 
        audit_logger: AuditLogger,
        operation: str,
        session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.audit_logger = audit_logger
        self.operation = operation
        self.session_id = session_id
        self.metadata = metadata or {}
        self.start_time = 0.0
        self.success = False
    
    def __enter__(self):
        """Start timing operation."""
        self.start_time = time.perf_counter()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Log operation completion."""
        duration_ms = (time.perf_counter() - self.start_time) * 1000
        self.success = exc_type is None
        
        self.audit_logger.log_performance_metric(
            operation=self.operation,
            duration_ms=duration_ms,
            success_rate=1.0 if self.success else 0.0,
            metadata={
                "session_id": self.session_id,
                "success": self.success,
                **self.metadata
            }
        )


# Global audit logger instance
_global_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> Optional[AuditLogger]:
    """Get the global audit logger instance."""
    return _global_audit_logger


def setup_audit_logger(
    enabled: bool = True,
    log_level: LogLevel = LogLevel.INFO,
    log_file_path: Optional[Union[str, Path]] = None,
    **kwargs
) -> AuditLogger:
    """Setup and configure the global audit logger."""
    global _global_audit_logger
    
    if _global_audit_logger:
        _global_audit_logger.close()
    
    _global_audit_logger = AuditLogger(
        enabled=enabled,
        log_level=log_level,
        log_file_path=log_file_path,
        **kwargs
    )
    
    return _global_audit_logger


def audit_operation(
    operation: str,
    session_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
):
    """Decorator/context manager for auditing operations."""
    logger = get_audit_logger()
    if not logger:
        # Return a no-op context manager if no logger
        class NoOpContext:
            def __enter__(self): return self
            def __exit__(self, *args): pass
        return NoOpContext()
    
    return AuditContext(logger, operation, session_id, metadata)