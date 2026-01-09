"""LADON Common Utilities.

Shared utilities for LADON services including:
- Circuit breaker pattern for resilient service communication
- Structured logging with trace_id support
- Prometheus metrics instrumentation
- Error handling
"""

from ladon_common.circuit_breaker import CircuitBreaker
from ladon_common.metrics import (
    CollectionMetrics,
    DetectionMetrics,
    EnrichmentMetrics,
    IOCMetrics,
    NormalizationMetrics,
    ServiceMetrics,
    ThreatMetrics,
    get_metrics_registry,
    setup_metrics_endpoint,
    timer,
)
from ladon_common.structured_logging import (
    clear_trace_id,
    extract_trace_id_from_headers,
    get_logger,
    get_trace_id,
    set_trace_id,
    trace_context,
)

__all__ = [
    # Circuit breaker
    "CircuitBreaker",
    # Structured logging
    "get_logger",
    "set_trace_id",
    "get_trace_id",
    "clear_trace_id",
    "trace_context",
    "extract_trace_id_from_headers",
    # Metrics
    "ServiceMetrics",
    "CollectionMetrics",
    "IOCMetrics",
    "ThreatMetrics",
    "DetectionMetrics",
    "EnrichmentMetrics",
    "NormalizationMetrics",
    "get_metrics_registry",
    "setup_metrics_endpoint",
    "timer",
]
__version__ = "0.1.0"
