"""
Structured Logging for LADON Platform

Provides structured logging following the format specified in CLAUDE.md:
{
    "timestamp": "2026-01-01T12:00:00Z",
    "severity": "INFO",
    "service": "detection",
    "trace_id": "abc123",
    "message": "Detection created",
    "detection_id": "det_123",
    "severity_level": "CRITICAL",
    "ioc_value": "malicious.com"
}

Usage:
    from ladon_common.structured_logging import get_logger

    logger = get_logger("storage-service")
    logger.info("IOC stored", extra={
        "ioc_value": "evil.com",
        "ioc_type": "domain",
        "confidence": 0.95
    })
"""

import contextvars
import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# Context variable for trace_id
trace_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "trace_id", default=None
)


class StructuredFormatter(logging.Formatter):
    """
    Custom formatter that outputs structured JSON logs.

    Follows LADON structured logging format with:
    - ISO 8601 timestamp
    - Standard severity levels
    - Service name
    - Trace ID (from context)
    - Message
    - Additional context fields
    """

    def __init__(self, service_name: str):
        """
        Initialize structured formatter.

        Args:
            service_name: Name of the service (e.g., "storage", "detection")
        """
        super().__init__()
        self.service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record as structured JSON.

        Args:
            record: Log record to format

        Returns:
            JSON string with structured log data
        """
        # Base structured log
        log_data: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "severity": record.levelname,
            "service": self.service_name,
            "trace_id": trace_id_var.get(),
            "message": record.getMessage(),
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add stack info if present
        if record.stack_info:
            log_data["stack_info"] = record.stack_info

        # Add extra fields from logger.info(..., extra={...})
        if hasattr(record, "extra_fields"):
            log_data.update(record.extra_fields)

        # Add standard log record attributes that might be useful
        log_data["logger_name"] = record.name
        log_data["filename"] = record.filename
        log_data["line_number"] = record.lineno
        log_data["function_name"] = record.funcName

        return json.dumps(log_data)


class StructuredAdapter(logging.LoggerAdapter):
    """
    Logging adapter that automatically includes trace_id and supports extra fields.

    This adapter wraps the standard logger to:
    1. Automatically add trace_id from context
    2. Support extra fields in a structured way
    3. Maintain compatibility with standard logging
    """

    def process(
        self, msg: str, kwargs: Dict[str, Any]
    ) -> tuple[str, Dict[str, Any]]:
        """
        Process log message and kwargs to add extra fields.

        Args:
            msg: Log message
            kwargs: Logging kwargs

        Returns:
            Tuple of (message, modified_kwargs)
        """
        # Extract extra fields and store them in a structured way
        if "extra" not in kwargs:
            kwargs["extra"] = {}

        # Store all extra fields in a single dict for the formatter
        if "extra_fields" not in kwargs["extra"]:
            kwargs["extra"]["extra_fields"] = {}

        # Merge any additional extra fields
        extra_data = kwargs.get("extra", {}).copy()
        if "extra_fields" in extra_data:
            # Already has extra_fields, merge with it
            extra_fields = extra_data.pop("extra_fields")
        else:
            extra_fields = {}

        # Add remaining extra data to extra_fields
        for key, value in extra_data.items():
            if key not in ["extra_fields"]:
                extra_fields[key] = value

        kwargs["extra"] = {"extra_fields": extra_fields}

        return msg, kwargs


def get_logger(
    service_name: str,
    level: str = "INFO",
    structured: bool = True,
    output_stream: Any = None,
) -> logging.LoggerAdapter:
    """
    Get a structured logger for a service.

    Args:
        service_name: Name of the service (e.g., "storage", "detection")
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        structured: If True, use JSON structured logging. If False, use standard logging.
        output_stream: Output stream (default: sys.stdout)

    Returns:
        Configured LoggerAdapter with structured logging

    Example:
        >>> logger = get_logger("storage-service")
        >>> logger.info("IOC stored", extra={"ioc_value": "evil.com", "ioc_type": "domain"})
        {"timestamp":"2026-01-05T12:00:00Z","severity":"INFO","service":"storage-service",
         "trace_id":"abc123","message":"IOC stored","ioc_value":"evil.com","ioc_type":"domain"}
    """
    if output_stream is None:
        output_stream = sys.stdout

    # Create logger
    logger = logging.getLogger(service_name)
    logger.setLevel(getattr(logging, level.upper()))
    logger.handlers = []  # Clear existing handlers

    # Create handler
    handler = logging.StreamHandler(output_stream)
    handler.setLevel(getattr(logging, level.upper()))

    # Set formatter
    if structured:
        formatter = StructuredFormatter(service_name)
    else:
        # Standard logging format
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Wrap in adapter for automatic trace_id and extra field handling
    adapter = StructuredAdapter(logger, {})
    return adapter


def set_trace_id(trace_id: Optional[str] = None) -> str:
    """
    Set trace ID for current context.

    If no trace_id is provided, generates a new one.

    Args:
        trace_id: Trace ID to set (optional)

    Returns:
        The trace ID that was set

    Example:
        >>> trace_id = set_trace_id()
        >>> logger.info("Processing request")  # Will include trace_id in log
    """
    if trace_id is None:
        trace_id = str(uuid.uuid4())

    trace_id_var.set(trace_id)
    return trace_id


def get_trace_id() -> Optional[str]:
    """
    Get current trace ID from context.

    Returns:
        Current trace ID or None if not set
    """
    return trace_id_var.get()


def clear_trace_id() -> None:
    """Clear trace ID from current context."""
    trace_id_var.set(None)


# Context manager for scoped trace ID
class trace_context:
    """
    Context manager for scoped trace ID.

    Example:
        >>> with trace_context("req-123"):
        ...     logger.info("Processing")  # Will have trace_id="req-123"
        >>> logger.info("Done")  # trace_id cleared
    """

    def __init__(self, trace_id: Optional[str] = None):
        """
        Initialize trace context.

        Args:
            trace_id: Trace ID to use (generates new one if None)
        """
        self.trace_id = trace_id or str(uuid.uuid4())
        self.previous_trace_id: Optional[str] = None

    def __enter__(self) -> str:
        """Enter trace context."""
        self.previous_trace_id = get_trace_id()
        set_trace_id(self.trace_id)
        return self.trace_id

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit trace context and restore previous trace ID."""
        if self.previous_trace_id is not None:
            set_trace_id(self.previous_trace_id)
        else:
            clear_trace_id()


# Helper function for FastAPI middleware
def extract_trace_id_from_headers(headers: Dict[str, str]) -> Optional[str]:
    """
    Extract trace ID from HTTP headers.

    Checks for trace ID in common headers:
    - X-Trace-Id
    - X-Request-Id
    - X-Correlation-Id

    Args:
        headers: HTTP headers dict

    Returns:
        Trace ID from headers or None
    """
    trace_headers = ["x-trace-id", "x-request-id", "x-correlation-id"]

    for header in trace_headers:
        if header in headers:
            return headers[header]

    return None
