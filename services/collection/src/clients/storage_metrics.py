"""Prometheus metrics for Storage Service client."""

from prometheus_client import Counter, Gauge, Histogram

# Request metrics
storage_client_requests_total = Counter(
    "storage_client_requests_total",
    "Total number of Storage Service requests",
    ["method", "status", "error_type"],
)

# Circuit breaker metrics
storage_client_circuit_breaker_state = Gauge(
    "storage_client_circuit_breaker_state",
    "Circuit breaker state (0=closed, 1=open, 2=half_open)",
)

# Latency metrics
storage_client_latency_seconds = Histogram(
    "storage_client_latency_seconds",
    "Storage Service request latency in seconds",
    ["method"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

# Connection pool metrics
storage_client_connections_active = Gauge(
    "storage_client_connections_active",
    "Number of active connections in the pool",
)

storage_client_connections_idle = Gauge(
    "storage_client_connections_idle",
    "Number of idle connections in the pool",
)


def get_circuit_breaker_state_value(state: str) -> int:
    """Convert circuit breaker state to numeric value for Prometheus.

    Args:
        state: Circuit breaker state (closed, open, half_open)

    Returns:
        Numeric value: 0=closed, 1=open, 2=half_open
    """
    state_map = {
        "closed": 0,
        "open": 1,
        "half_open": 2,
    }
    return state_map.get(state, -1)
