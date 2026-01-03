"""
Configuration for Collection Service.

Defines settings for all data sources (IOC feeds and activity logs).
"""

from enum import Enum
from typing import Dict, List, Optional

from pydantic import Field
from pydantic_settings import BaseSettings


class SourceType(str, Enum):
    """Type of data source."""

    IOC_FEED = "ioc_feed"
    ACTIVITY_LOG = "activity_log"


class CollectorType(str, Enum):
    """Type of collector implementation."""

    ALIENVAULT_OTX = "alienvault_otx"
    ABUSE_CH = "abuse_ch"
    MISP = "misp"
    TRINO = "trino"
    BIGQUERY = "bigquery"


class DataSourceConfig(BaseSettings):
    """Configuration for a single data source."""

    # Identification
    id: str
    name: str
    source_type: SourceType
    collector_type: CollectorType
    enabled: bool = True

    # Collection schedule
    collection_interval_minutes: int = Field(
        30, description="How often to collect data"
    )

    # Source-specific connection details
    connection: Dict = Field(
        default_factory=dict, description="Connection parameters (API keys, endpoints, etc.)"
    )

    # Query/collection parameters
    query_config: Dict = Field(
        default_factory=dict,
        description="Source-specific query configuration",
    )

    # Performance settings
    batch_size: int = Field(10000, description="Number of records per batch")
    max_concurrent_requests: int = Field(5, description="Max parallel requests")
    timeout_seconds: int = Field(30, description="Request timeout")

    # Retry settings
    max_retries: int = 3
    retry_delay_seconds: int = 5
    retry_backoff_multiplier: float = 2.0

    # Pub/Sub settings
    pubsub_topic: str = Field(..., description="Pub/Sub topic for raw events")

    class Config:
        extra = "allow"


class AlienVaultOTXConfig(DataSourceConfig):
    """AlienVault OTX feed configuration."""

    collector_type: CollectorType = CollectorType.ALIENVAULT_OTX
    source_type: SourceType = SourceType.IOC_FEED

    # API settings
    api_key: str = Field(..., description="OTX API key")
    api_endpoint: str = "https://otx.alienvault.com/api/v1"

    # Collection settings
    collection_interval_minutes: int = 30
    pulses_limit: int = 100


class AbuseCHConfig(DataSourceConfig):
    """abuse.ch feed configuration."""

    collector_type: CollectorType = CollectorType.ABUSE_CH
    source_type: SourceType = SourceType.IOC_FEED

    # Feed URLs
    threatfox_url: str = "https://threatfox-api.abuse.ch/api/v1/"
    urlhaus_url: str = "https://urlhaus-api.abuse.ch/v1/"
    malware_bazaar_url: str = "https://mb-api.abuse.ch/api/v1/"

    # API key (optional for some endpoints)
    api_key: Optional[str] = None

    collection_interval_minutes: int = 15


class MISPConfig(DataSourceConfig):
    """MISP feed configuration."""

    collector_type: CollectorType = CollectorType.MISP
    source_type: SourceType = SourceType.IOC_FEED

    # MISP instance details
    url: str = Field(..., description="MISP instance URL")
    api_key: str = Field(..., description="MISP API key")
    verify_ssl: bool = True

    # Filter settings
    published: bool = True  # Only published events
    to_ids: bool = True  # Only IOCs marked for IDS
    tags: List[str] = Field(default_factory=list, description="Filter by tags")

    collection_interval_minutes: int = 30


class TrinoConfig(DataSourceConfig):
    """Trino data source configuration."""

    collector_type: CollectorType = CollectorType.TRINO
    source_type: SourceType = SourceType.ACTIVITY_LOG

    # Trino connection
    host: str = Field(..., description="Trino host")
    port: int = 8080
    catalog: str = Field(..., description="Trino catalog")
    schema: str = Field(..., description="Trino schema")
    user: str = "ladon"

    # Table and query config
    table: str = Field(..., description="Source table name")
    timestamp_column: str = Field(
        "timestamp", description="Column to use for watermarking"
    )
    order_by_column: str = Field("timestamp", description="Column to order results")

    # Collection settings
    collection_interval_minutes: int = 3
    batch_size: int = 100000  # Large batches for high-volume logs


class BigQuerySourceConfig(DataSourceConfig):
    """BigQuery data source configuration."""

    collector_type: CollectorType = CollectorType.BIGQUERY
    source_type: SourceType = SourceType.ACTIVITY_LOG

    # BigQuery settings
    project_id: str
    dataset: str
    table: str

    # Query config
    timestamp_column: str = "timestamp"
    partition_field: str = "timestamp"

    collection_interval_minutes: int = 3
    batch_size: int = 50000


class PubSubConfig(BaseSettings):
    """Pub/Sub publisher configuration."""

    project_id: str

    # Topic names
    raw_ioc_events_topic: str = "raw-ioc-events"
    raw_activity_events_topic: str = "raw-activity-events"

    # Publishing settings
    max_messages_per_batch: int = 1000
    max_batch_size_bytes: int = 10_000_000  # 10 MB
    timeout_seconds: float = 10.0

    class Config:
        env_prefix = "PUBSUB_"


class CollectionConfig(BaseSettings):
    """Overall collection service configuration."""

    # Environment
    environment: str = "development"
    log_level: str = "INFO"

    # Service settings
    max_concurrent_collectors: int = 10
    health_check_interval_seconds: int = 60

    # Storage integration (for watermarks)
    storage_service_url: Optional[str] = None

    # Pub/Sub settings
    pubsub: PubSubConfig

    # Data sources (loaded from config file or environment)
    data_sources: List[DataSourceConfig] = Field(default_factory=list)

    class Config:
        env_prefix = "COLLECTION_"

    def get_source_by_id(self, source_id: str) -> Optional[DataSourceConfig]:
        """Get data source config by ID."""
        for source in self.data_sources:
            if source.id == source_id:
                return source
        return None

    def get_enabled_sources(self) -> List[DataSourceConfig]:
        """Get all enabled data sources."""
        return [source for source in self.data_sources if source.enabled]

    def get_sources_by_type(
        self, source_type: SourceType
    ) -> List[DataSourceConfig]:
        """Get all sources of a specific type."""
        return [
            source
            for source in self.data_sources
            if source.source_type == source_type and source.enabled
        ]
