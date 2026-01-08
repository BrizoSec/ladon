"""
Prometheus Metrics for LADON Threat XDR Platform

Provides standardized Prometheus metrics following CLAUDE.md specifications:
- Collection metrics: collection_events_per_second, collection_errors_total, collection_latency_seconds
- Detection metrics: detections_created_total, detection_latency_seconds, false_positive_rate
- Enrichment metrics: enrichment_api_calls_total, enrichment_cache_hit_rate, enrichment_latency_seconds
- Threat metrics: threats_stored_total, threat_extraction_latency_seconds

Usage:
    from ladon_common.metrics import (
        get_metrics_registry,
        IOCMetrics,
        ThreatMetrics,
        DetectionMetrics
    )

    # In FastAPI app
    app = FastAPI()
    setup_metrics(app, service_name="storage")

    # Record metrics
    metrics = ThreatMetrics()
    metrics.threats_stored.inc()
    metrics.threat_extraction_latency.observe(0.5)
"""

import time
from typing import Optional

try:
    from prometheus_client import (
        Counter,
        Gauge,
        Histogram,
        Info,
        CollectorRegistry,
        generate_latest,
        CONTENT_TYPE_LATEST,
    )

    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    # Create dummy classes if prometheus_client not available
    class Counter:
        def __init__(self, *args, **kwargs):
            pass

        def inc(self, amount=1):
            pass

        def labels(self, **labels):
            return self

    class Gauge:
        def __init__(self, *args, **kwargs):
            pass

        def set(self, value):
            pass

        def inc(self, amount=1):
            pass

        def dec(self, amount=1):
            pass

        def labels(self, **labels):
            return self

    class Histogram:
        def __init__(self, *args, **kwargs):
            pass

        def observe(self, value):
            pass

        def time(self):
            return _DummyTimer()

        def labels(self, **labels):
            return self

    class Info:
        def __init__(self, *args, **kwargs):
            pass

        def info(self, data):
            pass

    class CollectorRegistry:
        pass

    class _DummyTimer:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    def generate_latest(registry):
        return b""

    CONTENT_TYPE_LATEST = "text/plain"


# Global registry
_registry: Optional[CollectorRegistry] = None


def get_metrics_registry() -> CollectorRegistry:
    """
    Get the global Prometheus metrics registry.

    Returns:
        CollectorRegistry instance
    """
    global _registry
    if _registry is None:
        if PROMETHEUS_AVAILABLE:
            _registry = CollectorRegistry()
        else:
            _registry = CollectorRegistry()
    return _registry


class ServiceMetrics:
    """Base metrics available for all services."""

    def __init__(self, service_name: str, registry: Optional[CollectorRegistry] = None):
        """
        Initialize base service metrics.

        Args:
            service_name: Name of the service
            registry: Prometheus registry (uses global if None)
        """
        self.service_name = service_name
        self.registry = registry or get_metrics_registry()

        # Service info
        self.service_info = Info(
            "service_info",
            "Service information",
            registry=self.registry,
        )
        self.service_info.info({"service": service_name})

        # Request metrics
        self.requests_total = Counter(
            "requests_total",
            "Total number of requests",
            ["service", "endpoint", "method", "status"],
            registry=self.registry,
        )

        self.request_duration_seconds = Histogram(
            "request_duration_seconds",
            "Request duration in seconds",
            ["service", "endpoint", "method"],
            registry=self.registry,
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
        )

        # Error metrics
        self.errors_total = Counter(
            "errors_total",
            "Total number of errors",
            ["service", "error_type"],
            registry=self.registry,
        )


class CollectionMetrics(ServiceMetrics):
    """Metrics for Collection Service."""

    def __init__(self, service_name: str = "collection", registry: Optional[CollectorRegistry] = None):
        """Initialize collection metrics."""
        super().__init__(service_name, registry)

        # Collection-specific metrics
        self.collection_events_per_second = Gauge(
            "collection_events_per_second",
            "Collection throughput in events per second",
            ["service", "source"],
            registry=self.registry,
        )

        self.collection_errors_total = Counter(
            "collection_errors_total",
            "Total collection errors",
            ["service", "source", "error_type"],
            registry=self.registry,
        )

        self.collection_latency_seconds = Histogram(
            "collection_latency_seconds",
            "Collection latency in seconds",
            ["service", "source"],
            registry=self.registry,
            buckets=(0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0),
        )

        self.watermark_timestamp = Gauge(
            "watermark_timestamp",
            "Current watermark timestamp",
            ["service", "source"],
            registry=self.registry,
        )


class IOCMetrics(ServiceMetrics):
    """Metrics for IOC operations."""

    def __init__(self, service_name: str = "storage", registry: Optional[CollectorRegistry] = None):
        """Initialize IOC metrics."""
        super().__init__(service_name, registry)

        # IOC storage metrics
        self.iocs_stored_total = Counter(
            "iocs_stored_total",
            "Total IOCs stored",
            ["service", "source", "ioc_type"],
            registry=self.registry,
        )

        self.iocs_cache_hits_total = Counter(
            "iocs_cache_hits_total",
            "Total IOC cache hits",
            ["service"],
            registry=self.registry,
        )

        self.iocs_cache_misses_total = Counter(
            "iocs_cache_misses_total",
            "Total IOC cache misses",
            ["service"],
            registry=self.registry,
        )

        self.iocs_active_count = Gauge(
            "iocs_active_count",
            "Number of active IOCs",
            ["service", "source"],
            registry=self.registry,
        )

        self.ioc_storage_latency_seconds = Histogram(
            "ioc_storage_latency_seconds",
            "IOC storage latency in seconds",
            ["service", "operation"],
            registry=self.registry,
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
        )


class ThreatMetrics(ServiceMetrics):
    """Metrics for Threat operations."""

    def __init__(self, service_name: str = "storage", registry: Optional[CollectorRegistry] = None):
        """Initialize threat metrics."""
        super().__init__(service_name, registry)

        # Threat storage metrics
        self.threats_stored_total = Counter(
            "threats_stored_total",
            "Total threats stored",
            ["service", "source", "threat_category"],
            registry=self.registry,
        )

        self.threat_extraction_latency_seconds = Histogram(
            "threat_extraction_latency_seconds",
            "Threat extraction latency in seconds",
            ["service", "source"],
            registry=self.registry,
            buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
        )

        self.threats_active_count = Gauge(
            "threats_active_count",
            "Number of active threats",
            ["service", "threat_category"],
            registry=self.registry,
        )

        self.threat_ioc_associations_total = Counter(
            "threat_ioc_associations_total",
            "Total threat-IOC associations created",
            ["service", "source"],
            registry=self.registry,
        )

        self.mitre_techniques_total = Counter(
            "mitre_techniques_total",
            "Total MITRE ATT&CK techniques extracted",
            ["service", "tactic"],
            registry=self.registry,
        )


class DetectionMetrics(ServiceMetrics):
    """Metrics for Detection Service."""

    def __init__(self, service_name: str = "detection", registry: Optional[CollectorRegistry] = None):
        """Initialize detection metrics."""
        super().__init__(service_name, registry)

        # Detection metrics
        self.detections_created_total = Counter(
            "detections_created_total",
            "Total detections created",
            ["service", "severity", "ioc_type"],
            registry=self.registry,
        )

        self.detection_latency_seconds = Histogram(
            "detection_latency_seconds",
            "Detection latency in seconds",
            ["service"],
            registry=self.registry,
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
        )

        self.false_positive_rate = Gauge(
            "false_positive_rate",
            "False positive rate (0.0-1.0)",
            ["service"],
            registry=self.registry,
        )

        self.ioc_matches_total = Counter(
            "ioc_matches_total",
            "Total IOC matches",
            ["service", "ioc_type", "activity_source"],
            registry=self.registry,
        )


class EnrichmentMetrics(ServiceMetrics):
    """Metrics for Enrichment Service."""

    def __init__(self, service_name: str = "enrichment", registry: Optional[CollectorRegistry] = None):
        """Initialize enrichment metrics."""
        super().__init__(service_name, registry)

        # Enrichment metrics
        self.enrichment_api_calls_total = Counter(
            "enrichment_api_calls_total",
            "Total enrichment API calls",
            ["service", "provider", "status"],
            registry=self.registry,
        )

        self.enrichment_cache_hit_rate = Gauge(
            "enrichment_cache_hit_rate",
            "Enrichment cache hit rate (0.0-1.0)",
            ["service", "provider"],
            registry=self.registry,
        )

        self.enrichment_latency_seconds = Histogram(
            "enrichment_latency_seconds",
            "Enrichment latency in seconds",
            ["service", "provider"],
            registry=self.registry,
            buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
        )

        self.enrichment_rate_limit_hits_total = Counter(
            "enrichment_rate_limit_hits_total",
            "Total rate limit hits",
            ["service", "provider"],
            registry=self.registry,
        )


class NormalizationMetrics(ServiceMetrics):
    """Metrics for Normalization Service."""

    def __init__(self, service_name: str = "normalization", registry: Optional[CollectorRegistry] = None):
        """Initialize normalization metrics."""
        super().__init__(service_name, registry)

        # Normalization metrics
        self.events_normalized_total = Counter(
            "events_normalized_total",
            "Total events normalized",
            ["service", "source", "event_type"],
            registry=self.registry,
        )

        self.normalization_errors_total = Counter(
            "normalization_errors_total",
            "Total normalization errors",
            ["service", "source", "error_type"],
            registry=self.registry,
        )

        self.normalization_latency_seconds = Histogram(
            "normalization_latency_seconds",
            "Normalization latency in seconds",
            ["service", "source"],
            registry=self.registry,
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25),
        )

        self.invalid_events_total = Counter(
            "invalid_events_total",
            "Total invalid events skipped",
            ["service", "source", "reason"],
            registry=self.registry,
        )


# Context manager for timing operations
class timer:
    """
    Context manager for timing operations and recording to histogram.

    Example:
        >>> metrics = ThreatMetrics()
        >>> with timer(metrics.threat_extraction_latency_seconds.labels(service="storage", source="alienvault")):
        ...     extract_threats()
    """

    def __init__(self, histogram):
        """
        Initialize timer.

        Args:
            histogram: Prometheus histogram to record duration
        """
        self.histogram = histogram
        self.start_time = None

    def __enter__(self):
        """Start timer."""
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop timer and record duration."""
        if self.start_time is not None:
            duration = time.time() - self.start_time
            self.histogram.observe(duration)


def setup_metrics_endpoint(app, registry: Optional[CollectorRegistry] = None):
    """
    Set up /metrics endpoint for FastAPI app.

    Args:
        app: FastAPI application
        registry: Prometheus registry (uses global if None)

    Example:
        >>> from fastapi import FastAPI
        >>> app = FastAPI()
        >>> setup_metrics_endpoint(app)
    """
    if not PROMETHEUS_AVAILABLE:
        return

    registry = registry or get_metrics_registry()

    @app.get("/metrics")
    async def metrics():
        """Prometheus metrics endpoint."""
        from fastapi.responses import Response

        return Response(
            content=generate_latest(registry), media_type=CONTENT_TYPE_LATEST
        )
