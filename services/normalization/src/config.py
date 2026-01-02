"""Configuration for Normalization Service."""

from enum import Enum
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings


class SourceType(str, Enum):
    """Type of data source."""

    IOC_FEED = "ioc_feed"
    ACTIVITY_LOG = "activity_log"


class PubSubConfig(BaseSettings):
    """Pub/Sub configuration."""

    project_id: str

    # Input topics (raw events)
    raw_ioc_events_topic: str = "raw-ioc-events"
    raw_activity_events_topic: str = "raw-activity-events"

    # Output topics (normalized events)
    normalized_ioc_events_topic: str = "normalized-ioc-events"
    normalized_activity_events_topic: str = "normalized-activity-events"

    # Dead letter topics
    dlq_ioc_events_topic: str = "dlq-ioc-events"
    dlq_activity_events_topic: str = "dlq-activity-events"

    # Subscriptions
    ioc_subscription: str = "normalization-ioc-sub"
    activity_subscription: str = "normalization-activity-sub"

    # Processing settings
    max_messages_per_pull: int = Field(100, description="Max messages per pull")
    ack_deadline_seconds: int = Field(60, description="Message ack deadline")
    max_workers: int = Field(10, description="Max concurrent message processors")

    class Config:
        env_prefix = "PUBSUB_"


class NormalizationConfig(BaseSettings):
    """Overall normalization service configuration."""

    # Environment
    environment: str = "development"
    log_level: str = "INFO"

    # Pub/Sub settings
    pubsub: PubSubConfig

    # Validation settings
    strict_validation: bool = Field(
        True, description="Fail on validation errors vs log and continue"
    )
    skip_invalid_iocs: bool = Field(
        True, description="Skip invalid IOCs instead of failing entire batch"
    )

    # Performance settings
    batch_size: int = Field(100, description="Batch size for publishing")
    max_retries: int = Field(3, description="Max retries for failed messages")

    # Dead letter queue settings
    dlq_max_delivery_attempts: int = Field(
        5, description="Max delivery attempts before sending to DLQ"
    )

    class Config:
        env_prefix = "NORMALIZATION_"


class SourceMappingConfig(BaseSettings):
    """Configuration for source-specific field mappings.

    Different sources (AlienVault, abuse.ch, Trino, etc.) have different
    field names and formats. This config defines how to map them.
    """

    # IOC source mappings
    ioc_source_mappings: dict = Field(
        default_factory=lambda: {
            "alienvault_otx": {
                "ioc_value_field": "ioc_value",
                "ioc_type_field": "ioc_type",
                "threat_type_field": "threat_type",
                "confidence_field": "confidence",
                "source_field": "source",
                "first_seen_field": "first_seen",
                "last_seen_field": "last_seen",
                "tags_field": "tags",
                "metadata_field": "metadata",
            },
            "abuse_ch_threatfox": {
                "ioc_value_field": "ioc_value",
                "ioc_type_field": "ioc_type",
                "threat_type_field": "threat_type",
                "confidence_field": "confidence",
                "source_field": "source",
                "first_seen_field": "first_seen",
                "last_seen_field": "last_seen",
                "tags_field": "tags",
                "metadata_field": "metadata",
            },
            "misp": {
                "ioc_value_field": "ioc_value",
                "ioc_type_field": "ioc_type",
                "threat_type_field": "threat_type",
                "confidence_field": "confidence",
                "source_field": "source",
                "first_seen_field": "first_seen",
                "last_seen_field": "last_seen",
                "tags_field": "tags",
                "metadata_field": "metadata",
            },
        }
    )

    # Activity source mappings
    activity_source_mappings: dict = Field(
        default_factory=lambda: {
            "dns": {
                "event_id_field": "event_id",
                "timestamp_field": "timestamp",
                "source_field": "source",
                "event_type_field": "event_type",
                "domain_field": "domain",
                "src_ip_field": "src_ip",
                "dst_ip_field": "dst_ip",
            },
            "proxy": {
                "event_id_field": "event_id",
                "timestamp_field": "timestamp",
                "source_field": "source",
                "event_type_field": "event_type",
                "url_field": "url",
                "src_ip_field": "src_ip",
                "dst_ip_field": "dst_ip",
                "user_field": "user",
            },
            "mde": {
                "event_id_field": "event_id",
                "timestamp_field": "timestamp",
                "source_field": "source",
                "event_type_field": "event_type",
                "hostname_field": "hostname",
                "process_name_field": "process_name",
                "file_hash_field": "file_hash",
                "user_field": "user",
            },
        }
    )
