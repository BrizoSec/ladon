"""LADON Common Utilities.

Shared utilities for LADON services including:
- Circuit breaker pattern for resilient service communication
- Logging configuration
- Metrics instrumentation
- Error handling
"""

from ladon_common.circuit_breaker import CircuitBreaker

__all__ = ["CircuitBreaker"]
__version__ = "0.1.0"
