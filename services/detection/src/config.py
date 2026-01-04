"""Configuration for Detection Service."""

import os
from typing import Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Detection Service settings."""

    # Service Configuration
    service_name: str = "detection"
    environment: str = os.getenv("ENVIRONMENT", "development")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")

    # Redis Configuration (IOC Cache)
    redis_host: str = os.getenv("REDIS_HOST", "localhost")
    redis_port: int = int(os.getenv("REDIS_PORT", "6379"))
    redis_db: int = int(os.getenv("REDIS_DB", "0"))
    redis_password: Optional[str] = os.getenv("REDIS_PASSWORD")
    redis_ssl: bool = os.getenv("REDIS_SSL", "false").lower() == "true"

    # Redis Cache Settings
    ioc_cache_ttl: int = int(os.getenv("IOC_CACHE_TTL", str(24 * 60 * 60)))  # 24 hours
    ioc_cache_key_prefix: str = "ioc"

    # Pub/Sub Configuration
    pubsub_project_id: str = os.getenv("PUBSUB_PROJECT_ID", "ladon-dev")
    pubsub_activity_events_subscription: str = os.getenv(
        "PUBSUB_ACTIVITY_EVENTS_SUBSCRIPTION",
        "normalized-activity-events-sub"
    )
    pubsub_detections_topic: str = os.getenv(
        "PUBSUB_DETECTIONS_TOPIC",
        "detections"
    )

    # Detection Configuration
    batch_size: int = int(os.getenv("DETECTION_BATCH_SIZE", "1000"))
    correlation_timeout_ms: int = int(os.getenv("CORRELATION_TIMEOUT_MS", "100"))

    # Severity Thresholds (confidence to severity mapping)
    severity_critical_threshold: float = float(os.getenv("SEVERITY_CRITICAL_THRESHOLD", "0.9"))
    severity_high_threshold: float = float(os.getenv("SEVERITY_HIGH_THRESHOLD", "0.75"))
    severity_medium_threshold: float = float(os.getenv("SEVERITY_MEDIUM_THRESHOLD", "0.5"))

    # Matching Configuration
    enable_subdomain_matching: bool = os.getenv("ENABLE_SUBDOMAIN_MATCHING", "true").lower() == "true"
    enable_cidr_matching: bool = os.getenv("ENABLE_CIDR_MATCHING", "true").lower() == "true"
    enable_url_domain_extraction: bool = os.getenv("ENABLE_URL_DOMAIN_EXTRACTION", "true").lower() == "true"

    # Performance Settings
    max_concurrent_correlations: int = int(os.getenv("MAX_CONCURRENT_CORRELATIONS", "10"))

    class Config:
        """Pydantic config."""
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()
