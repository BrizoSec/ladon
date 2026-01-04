"""Prometheus metrics for Detection Service."""

from prometheus_client import Counter, Gauge, Histogram

# Detection metrics
detection_correlations_total = Counter(
    "detection_correlations_total",
    "Total number of activity events correlated",
)

detections_created_total = Counter(
    "detections_created_total",
    "Total number of detections created",
)

detection_latency_seconds = Histogram(
    "detection_latency_seconds",
    "Time to correlate a batch of events",
    buckets=(0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0),
)

# Cache metrics
ioc_cache_hits_total = Counter(
    "ioc_cache_hits_total",
    "Total number of IOC cache hits",
)

ioc_cache_misses_total = Counter(
    "ioc_cache_misses_total",
    "Total number of IOC cache misses",
)

ioc_cache_size = Gauge(
    "ioc_cache_size",
    "Number of IOCs in cache",
)

# Detection by severity
detections_by_severity = Counter(
    "detections_by_severity",
    "Detections grouped by severity",
    ["severity"],
)

# Detection by threat type
detections_by_threat_type = Counter(
    "detections_by_threat_type",
    "Detections grouped by threat type",
    ["threat_type"],
)

# Detection by source
detections_by_source = Counter(
    "detections_by_source",
    "Detections grouped by activity source",
    ["source"],
)
