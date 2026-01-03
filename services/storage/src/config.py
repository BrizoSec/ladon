"""
Configuration for Storage Service.

Loads configuration from environment variables with sensible defaults.
"""

from typing import Optional

from pydantic_settings import BaseSettings


class BigQueryConfig(BaseSettings):
    """BigQuery configuration."""

    project_id: str
    dataset: str = "threat_xdr"
    location: str = "US"

    # Table names
    iocs_table: str = "iocs"
    activity_logs_table: str = "activity_logs"
    detections_table: str = "detections"

    # Performance settings
    max_results_per_page: int = 1000
    query_timeout_seconds: int = 30
    streaming_buffer_rows: int = 500

    # Cost controls
    max_bytes_billed_per_query: Optional[int] = 10_000_000_000  # 10GB limit

    class Config:
        env_prefix = "BIGQUERY_"


class RedisConfig(BaseSettings):
    """Redis cache configuration."""

    host: str = "localhost"
    port: int = 6379
    password: Optional[str] = None
    db: int = 0

    # Connection pool settings
    max_connections: int = 50
    socket_timeout: int = 5
    socket_connect_timeout: int = 5

    # Cache settings
    ioc_cache_ttl: int = 86400  # 24 hours
    hot_ioc_threshold_hours: int = 48
    hot_ioc_min_confidence: float = 0.7

    # Key prefixes
    ioc_key_prefix: str = "ioc"
    stats_key_prefix: str = "stats"

    class Config:
        env_prefix = "REDIS_"


class FirestoreConfig(BaseSettings):
    """Firestore configuration."""

    project_id: str
    database: str = "(default)"

    # Collection names
    watermarks_collection: str = "watermarks"
    config_collection: str = "config"
    metadata_collection: str = "metadata"

    # Timeout settings
    timeout_seconds: int = 10

    class Config:
        env_prefix = "FIRESTORE_"


class StorageConfig(BaseSettings):
    """Overall storage service configuration."""

    # Environment
    environment: str = "development"
    log_level: str = "INFO"

    # Feature flags
    enable_bigquery: bool = True
    enable_redis: bool = True
    enable_firestore: bool = True

    # Retry configuration
    max_retries: int = 3
    retry_delay_seconds: int = 1
    retry_backoff_multiplier: float = 2.0

    # Component configs
    bigquery: BigQueryConfig
    redis: RedisConfig
    firestore: FirestoreConfig

    class Config:
        env_prefix = "STORAGE_"

    @classmethod
    def from_env(cls) -> "StorageConfig":
        """Load configuration from environment variables."""
        return cls(
            bigquery=BigQueryConfig(),
            redis=RedisConfig(),
            firestore=FirestoreConfig(),
        )
