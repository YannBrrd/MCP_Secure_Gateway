"""Structured audit logging for MCP gateway operations."""

from __future__ import annotations

import contextlib
import sys
import time
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import structlog

from mcp_gateway.config import get_settings


class AuditEventType(str, Enum):
    """Types of audit events."""

    TOOL_INVOCATION = "tool_invocation"
    QUERY_EXECUTED = "query_executed"
    PII_DETECTED = "pii_detected"
    POLICY_APPLIED = "policy_applied"
    ACCESS_DENIED = "access_denied"
    BACKEND_CALL = "backend_call"
    ERROR = "error"
    SESSION_START = "session_start"
    SESSION_END = "session_end"


class PIIPolicyAction(str, Enum):
    """PII policy actions."""

    MASK = "mask"
    HASH = "hash"
    DENY = "deny"
    PASS = "pass"  # No PII detected


class AuditLogger:
    """
    Structured audit logger for security and compliance.

    Logs all gateway operations in a structured JSON format suitable
    for SIEM ingestion and compliance reporting. Never logs raw PII
    values or SQL strings.
    """

    def __init__(self) -> None:
        """Initialize the audit logger with configuration."""
        self._settings = get_settings()
        self._log_file_handle: Any = None  # Track file handle for cleanup
        self._logger = self._configure_logger()
        self._session_id: str | None = None

    def _configure_logger(self) -> structlog.BoundLogger:
        """Configure structlog with appropriate processors."""
        processors: list[Any] = [
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
        ]

        # Add JSON renderer for structured output
        processors.append(structlog.processors.JSONRenderer())

        structlog.configure(
            processors=processors,
            wrapper_class=structlog.make_filtering_bound_logger(
                getattr(
                    structlog.stdlib,
                    self._settings.audit.log_level,
                    20,  # INFO level
                )
            ),
            context_class=dict,
            logger_factory=structlog.PrintLoggerFactory(
                file=self._get_log_output()
            ),
            cache_logger_on_first_use=True,
        )

        return structlog.get_logger("mcp_gateway.audit")

    def _get_log_output(self) -> Any:
        """Get the appropriate log output target."""
        if self._settings.audit.log_path:
            log_path = Path(self._settings.audit.log_path)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            self._log_file_handle = open(log_path, "a", encoding="utf-8")
            return self._log_file_handle
        return sys.stderr

    def close(self) -> None:
        """Close the audit logger and release resources."""
        if self._log_file_handle is not None:
            with contextlib.suppress(Exception):
                self._log_file_handle.close()
            self._log_file_handle = None

    def __del__(self) -> None:
        """Ensure file handle is closed on garbage collection."""
        self.close()

    def set_session_id(self, session_id: str) -> None:
        """Set the current session ID for log correlation."""
        self._session_id = session_id

    def _base_context(self) -> dict[str, Any]:
        """Get base context for all log entries."""
        return {
            "service": "mcp_secure_gateway",
            "version": self._settings.version,
            "session_id": self._session_id,
        }

    def log_tool_invocation(
        self,
        tool_name: str,
        backend: str,
        intent: str,
        pii_policy: str,
        filter_keys: list[str] | None = None,
    ) -> str:
        """
        Log an MCP tool invocation.

        Args:
            tool_name: Name of the invoked tool.
            backend: Target backend name.
            intent: Business intent string.
            pii_policy: Applied PII policy.
            filter_keys: Keys used in filters (NOT values).

        Returns:
            Generated invocation ID for correlation.
        """
        invocation_id = f"inv_{int(time.time() * 1000)}"

        self._logger.info(
            "tool_invocation",
            **self._base_context(),
            event_type=AuditEventType.TOOL_INVOCATION.value,
            invocation_id=invocation_id,
            tool_name=tool_name,
            backend=backend,
            intent=intent,
            pii_policy=pii_policy,
            filter_keys=filter_keys or [],
        )

        return invocation_id

    def log_pii_detection(
        self,
        invocation_id: str,
        detected_types: list[str],
        affected_columns: list[str],
        row_count: int,
    ) -> None:
        """
        Log PII detection results.

        Never logs actual PII values, only types and affected columns.

        Args:
            invocation_id: Correlation ID from tool invocation.
            detected_types: Types of PII detected (e.g., ["email", "phone"]).
            affected_columns: Column names containing PII.
            row_count: Number of rows scanned.
        """
        self._logger.info(
            "pii_detected",
            **self._base_context(),
            event_type=AuditEventType.PII_DETECTED.value,
            invocation_id=invocation_id,
            detected_pii_types=detected_types,
            affected_columns=affected_columns,
            rows_scanned=row_count,
        )

    def log_policy_applied(
        self,
        invocation_id: str,
        policy: PIIPolicyAction,
        columns_affected: list[str],
        action_taken: str,
    ) -> None:
        """
        Log PII policy enforcement.

        Args:
            invocation_id: Correlation ID.
            policy: The policy that was applied.
            columns_affected: Columns that were modified.
            action_taken: Description of action taken.
        """
        self._logger.info(
            "policy_applied",
            **self._base_context(),
            event_type=AuditEventType.POLICY_APPLIED.value,
            invocation_id=invocation_id,
            policy=policy.value,
            columns_affected=columns_affected,
            action_taken=action_taken,
        )

    def log_backend_call(
        self,
        invocation_id: str,
        backend: str,
        operation: str,
        duration_ms: float,
        row_count: int | None = None,
        success: bool = True,
    ) -> None:
        """
        Log a backend operation.

        Args:
            invocation_id: Correlation ID.
            backend: Backend name.
            operation: Type of operation performed.
            duration_ms: Operation duration in milliseconds.
            row_count: Number of rows returned (if applicable).
            success: Whether the operation succeeded.
        """
        self._logger.info(
            "backend_call",
            **self._base_context(),
            event_type=AuditEventType.BACKEND_CALL.value,
            invocation_id=invocation_id,
            backend=backend,
            operation=operation,
            duration_ms=round(duration_ms, 2),
            row_count=row_count,
            success=success,
        )

    def log_access_denied(
        self,
        invocation_id: str,
        reason: str,
        backend: str | None = None,
        detected_pii_types: list[str] | None = None,
    ) -> None:
        """
        Log an access denial.

        Args:
            invocation_id: Correlation ID.
            reason: Reason for denial.
            backend: Backend that was targeted.
            detected_pii_types: PII types that caused denial.
        """
        self._logger.warning(
            "access_denied",
            **self._base_context(),
            event_type=AuditEventType.ACCESS_DENIED.value,
            invocation_id=invocation_id,
            reason=reason,
            backend=backend,
            detected_pii_types=detected_pii_types or [],
        )

    def log_error(
        self,
        invocation_id: str | None,
        error_type: str,
        error_message: str,
        backend: str | None = None,
    ) -> None:
        """
        Log an error (with PII-safe message).

        The error_message should already be sanitized of PII.

        Args:
            invocation_id: Correlation ID (if available).
            error_type: Type/class of error.
            error_message: PII-safe error message.
            backend: Backend involved (if applicable).
        """
        self._logger.error(
            "error",
            **self._base_context(),
            event_type=AuditEventType.ERROR.value,
            invocation_id=invocation_id,
            error_type=error_type,
            error_message=error_message,
            backend=backend,
        )

    def log_session_start(self) -> str:
        """
        Log session start.

        Returns:
            Generated session ID.
        """
        session_id = f"sess_{int(time.time() * 1000)}"
        self._session_id = session_id

        self._logger.info(
            "session_start",
            **self._base_context(),
            event_type=AuditEventType.SESSION_START.value,
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        return session_id

    def log_session_end(self, total_invocations: int) -> None:
        """
        Log session end.

        Args:
            total_invocations: Total tool invocations in session.
        """
        self._logger.info(
            "session_end",
            **self._base_context(),
            event_type=AuditEventType.SESSION_END.value,
            ended_at=datetime.now(timezone.utc).isoformat(),
            total_invocations=total_invocations,
        )

    @contextmanager
    def timed_operation(
        self,
        invocation_id: str,
        backend: str,
        operation: str,
    ) -> Generator[None, None, None]:
        """
        Context manager for timing backend operations.

        Args:
            invocation_id: Correlation ID.
            backend: Backend name.
            operation: Operation type.

        Yields:
            None. Logs timing on exit.
        """
        start = time.perf_counter()
        success = True
        try:
            yield
        except Exception:
            success = False
            raise
        finally:
            duration_ms = (time.perf_counter() - start) * 1000
            self.log_backend_call(
                invocation_id=invocation_id,
                backend=backend,
                operation=operation,
                duration_ms=duration_ms,
                success=success,
            )


# Global audit logger instance
_audit_logger: AuditLogger | None = None


def get_audit_logger() -> AuditLogger:
    """Get the global audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger
