"""
Configuration Loader for LADON Collection Service.

Demonstrates how to load configuration from YAML files and environment variables.
This module provides helper functions to build complete configurations from
various sources with proper precedence.
"""

import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

import yaml
from pydantic import ValidationError

# Add src directory to path for absolute imports
src_dir = Path(__file__).parent.parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from config import (
    AbuseCHConfig,
    AlienVaultOTXConfig,
    BigQuerySourceConfig,
    CollectionConfig,
    DataSourceConfig,
    MISPConfig,
    PubSubConfig,
    TrinoConfig,
)


def load_config_from_yaml(config_path: str) -> Dict:
    """
    Load configuration from YAML file.

    Args:
        config_path: Path to YAML config file

    Returns:
        Dictionary with configuration data

    Raises:
        FileNotFoundError: If config file doesn't exist
        yaml.YAMLError: If YAML is invalid
    """
    config_file = Path(config_path)

    if not config_file.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_file, "r") as f:
        config_data = yaml.safe_load(f)

    return config_data


def build_pubsub_config(config_data: Dict) -> PubSubConfig:
    """
    Build PubSubConfig from configuration data.

    Environment variables override YAML values.

    Args:
        config_data: Configuration dictionary

    Returns:
        PubSubConfig instance
    """
    pubsub_data = config_data.get("pubsub", {})

    # Environment variables override
    return PubSubConfig(
        project_id=os.getenv("PUBSUB_PROJECT_ID", pubsub_data.get("project_id")),
        raw_ioc_events_topic=os.getenv(
            "PUBSUB_RAW_IOC_EVENTS_TOPIC",
            pubsub_data.get("raw_ioc_events_topic", "raw-ioc-events"),
        ),
        raw_activity_events_topic=os.getenv(
            "PUBSUB_RAW_ACTIVITY_EVENTS_TOPIC",
            pubsub_data.get("raw_activity_events_topic", "raw-activity-events"),
        ),
        raw_threat_events_topic=os.getenv(
            "PUBSUB_RAW_THREAT_EVENTS_TOPIC",
            pubsub_data.get("raw_threat_events_topic", "raw-threat-events"),
        ),
        normalized_threat_events_topic=os.getenv(
            "PUBSUB_NORMALIZED_THREAT_EVENTS_TOPIC",
            pubsub_data.get("normalized_threat_events_topic", "normalized-threat-events"),
        ),
        max_messages_per_batch=int(
            os.getenv(
                "PUBSUB_MAX_MESSAGES_PER_BATCH",
                pubsub_data.get("max_messages_per_batch", 1000),
            )
        ),
        max_batch_size_bytes=int(
            os.getenv(
                "PUBSUB_MAX_BATCH_SIZE_BYTES",
                pubsub_data.get("max_batch_size_bytes", 10_000_000),
            )
        ),
        timeout_seconds=float(
            os.getenv(
                "PUBSUB_TIMEOUT_SECONDS",
                pubsub_data.get("timeout_seconds", 10.0),
            )
        ),
    )


def build_alienvault_config(source_config: Dict) -> AlienVaultOTXConfig:
    """
    Build AlienVaultOTXConfig from source configuration.

    Args:
        source_config: Source configuration dictionary

    Returns:
        AlienVaultOTXConfig instance
    """
    # Environment variables override YAML
    return AlienVaultOTXConfig(
        id=source_config["id"],
        name=source_config["name"],
        enabled=source_config.get("enabled", True),
        collection_interval_minutes=int(
            os.getenv(
                "ALIENVAULT_COLLECTION_INTERVAL_MINUTES",
                source_config.get("collection_interval_minutes", 30),
            )
        ),
        api_key=os.getenv("ALIENVAULT_API_KEY", source_config.get("api_key")),
        api_endpoint=os.getenv(
            "ALIENVAULT_API_ENDPOINT",
            source_config.get("api_endpoint", "https://otx.alienvault.com/api/v1"),
        ),
        pulses_limit=int(
            os.getenv("ALIENVAULT_PULSES_LIMIT", source_config.get("pulses_limit", 100))
        ),
        pubsub_topic=source_config.get("pubsub_topic", "raw-ioc-events"),
        batch_size=source_config.get("batch_size", 1000),
        max_concurrent_requests=source_config.get("max_concurrent_requests", 3),
        timeout_seconds=source_config.get("timeout_seconds", 30),
        max_retries=source_config.get("max_retries", 3),
        query_config=source_config.get("query_config", {}),
    )


def build_abusech_config(source_config: Dict) -> AbuseCHConfig:
    """
    Build AbuseCHConfig from source configuration.

    Args:
        source_config: Source configuration dictionary

    Returns:
        AbuseCHConfig instance
    """
    return AbuseCHConfig(
        id=source_config["id"],
        name=source_config["name"],
        enabled=source_config.get("enabled", True),
        collection_interval_minutes=int(
            os.getenv(
                "ABUSECH_COLLECTION_INTERVAL_MINUTES",
                source_config.get("collection_interval_minutes", 15),
            )
        ),
        threatfox_url=os.getenv(
            "ABUSECH_THREATFOX_URL",
            source_config.get("threatfox_url", "https://threatfox-api.abuse.ch/api/v1/"),
        ),
        urlhaus_url=os.getenv(
            "ABUSECH_URLHAUS_URL",
            source_config.get("urlhaus_url", "https://urlhaus-api.abuse.ch/v1/"),
        ),
        malware_bazaar_url=os.getenv(
            "ABUSECH_MALWARE_BAZAAR_URL",
            source_config.get("malware_bazaar_url", "https://mb-api.abuse.ch/api/v1/"),
        ),
        api_key=os.getenv("ABUSECH_API_KEY", source_config.get("api_key")),
        pubsub_topic=source_config.get("pubsub_topic", "raw-ioc-events"),
        batch_size=source_config.get("batch_size", 5000),
        max_concurrent_requests=source_config.get("max_concurrent_requests", 2),
        timeout_seconds=source_config.get("timeout_seconds", 30),
        query_config=source_config.get("query_config", {}),
    )


def build_misp_config(source_config: Dict) -> MISPConfig:
    """
    Build MISPConfig from source configuration.

    Args:
        source_config: Source configuration dictionary

    Returns:
        MISPConfig instance
    """
    return MISPConfig(
        id=source_config["id"],
        name=source_config["name"],
        enabled=source_config.get("enabled", False),
        collection_interval_minutes=int(
            os.getenv(
                "MISP_COLLECTION_INTERVAL_MINUTES",
                source_config.get("collection_interval_minutes", 30),
            )
        ),
        url=os.getenv("MISP_URL", source_config.get("url")),
        api_key=os.getenv("MISP_API_KEY", source_config.get("api_key")),
        verify_ssl=bool(
            os.getenv("MISP_VERIFY_SSL", str(source_config.get("verify_ssl", True))).lower()
            == "true"
        ),
        published=source_config.get("published", True),
        to_ids=source_config.get("to_ids", True),
        tags=source_config.get("tags", []),
        pubsub_topic=source_config.get("pubsub_topic", "raw-ioc-events"),
        batch_size=source_config.get("batch_size", 1000),
        timeout_seconds=source_config.get("timeout_seconds", 60),
    )


def build_trino_config(source_config: Dict) -> TrinoConfig:
    """
    Build TrinoConfig from source configuration.

    Args:
        source_config: Source configuration dictionary

    Returns:
        TrinoConfig instance
    """
    source_id = source_config["id"]
    env_prefix = source_id.upper().replace("-", "_")

    return TrinoConfig(
        id=source_config["id"],
        name=source_config["name"],
        enabled=source_config.get("enabled", True),
        collection_interval_minutes=int(
            os.getenv(
                f"{env_prefix}_COLLECTION_INTERVAL_MINUTES",
                source_config.get("collection_interval_minutes", 3),
            )
        ),
        host=os.getenv(f"{env_prefix}_HOST", source_config.get("host")),
        port=int(os.getenv(f"{env_prefix}_PORT", source_config.get("port", 8080))),
        catalog=os.getenv(f"{env_prefix}_CATALOG", source_config.get("catalog")),
        schema=os.getenv(f"{env_prefix}_SCHEMA", source_config.get("schema")),
        table=os.getenv(f"{env_prefix}_TABLE", source_config.get("table")),
        user=os.getenv(f"{env_prefix}_USER", source_config.get("user", "ladon")),
        timestamp_column=source_config.get("timestamp_column", "timestamp"),
        order_by_column=source_config.get("order_by_column", "timestamp"),
        pubsub_topic=source_config.get("pubsub_topic", "raw-activity-events"),
        batch_size=source_config.get("batch_size", 100000),
        timeout_seconds=source_config.get("timeout_seconds", 300),
        query_config=source_config.get("query_config", {}),
    )


def build_bigquery_config(source_config: Dict) -> BigQuerySourceConfig:
    """
    Build BigQuerySourceConfig from source configuration.

    Args:
        source_config: Source configuration dictionary

    Returns:
        BigQuerySourceConfig instance
    """
    source_id = source_config["id"]
    env_prefix = source_id.upper().replace("-", "_")

    return BigQuerySourceConfig(
        id=source_config["id"],
        name=source_config["name"],
        enabled=source_config.get("enabled", True),
        collection_interval_minutes=int(
            os.getenv(
                f"{env_prefix}_COLLECTION_INTERVAL_MINUTES",
                source_config.get("collection_interval_minutes", 3),
            )
        ),
        project_id=os.getenv(f"{env_prefix}_PROJECT_ID", source_config.get("project_id")),
        dataset=os.getenv(f"{env_prefix}_DATASET", source_config.get("dataset")),
        table=os.getenv(f"{env_prefix}_TABLE", source_config.get("table")),
        timestamp_column=source_config.get("timestamp_column", "timestamp"),
        partition_field=source_config.get("partition_field", "timestamp"),
        pubsub_topic=source_config.get("pubsub_topic", "raw-activity-events"),
        batch_size=source_config.get("batch_size", 50000),
        timeout_seconds=source_config.get("timeout_seconds", 120),
        query_config=source_config.get("query_config", {}),
    )


def build_data_sources(config_data: Dict) -> List[DataSourceConfig]:
    """
    Build list of DataSourceConfig from configuration data.

    Args:
        config_data: Configuration dictionary with ioc_feeds and activity_logs

    Returns:
        List of DataSourceConfig instances
    """
    data_sources = []

    # Build IOC feed configs
    for source_config in config_data.get("ioc_feeds", []):
        collector_type = source_config["collector_type"]

        try:
            if collector_type == "alienvault_otx":
                data_sources.append(build_alienvault_config(source_config))
            elif collector_type == "abuse_ch":
                data_sources.append(build_abusech_config(source_config))
            elif collector_type == "misp":
                data_sources.append(build_misp_config(source_config))
            else:
                print(f"WARNING: Unknown IOC collector type: {collector_type}")
        except ValidationError as e:
            print(f"ERROR: Invalid config for {source_config['id']}: {e}")

    # Build activity log configs
    for source_config in config_data.get("activity_logs", []):
        collector_type = source_config["collector_type"]

        try:
            if collector_type == "trino":
                data_sources.append(build_trino_config(source_config))
            elif collector_type == "bigquery":
                data_sources.append(build_bigquery_config(source_config))
            else:
                print(f"WARNING: Unknown activity collector type: {collector_type}")
        except ValidationError as e:
            print(f"ERROR: Invalid config for {source_config['id']}: {e}")

    return data_sources


def load_collection_config(config_path: Optional[str] = None) -> CollectionConfig:
    """
    Load complete CollectionConfig from YAML file and environment variables.

    This is the main entry point for loading configuration. It:
    1. Loads YAML config file (if provided)
    2. Overrides with environment variables
    3. Validates all configurations
    4. Returns CollectionConfig ready to use

    Args:
        config_path: Path to YAML config file (optional)
                    If not provided, uses COLLECTION_CONFIG_FILE env var

    Returns:
        CollectionConfig instance

    Raises:
        FileNotFoundError: If config file not found
        ValidationError: If configuration is invalid

    Example:
        >>> config = load_collection_config("config/config.yaml")
        >>> print(f"Loaded {len(config.data_sources)} data sources")
        >>> print(f"Environment: {config.environment}")
    """
    # Determine config file path
    if config_path is None:
        config_path = os.getenv("COLLECTION_CONFIG_FILE")

    # Load from YAML if path provided
    if config_path:
        print(f"Loading configuration from: {config_path}")
        config_data = load_config_from_yaml(config_path)
    else:
        print("No config file provided - using environment variables only")
        config_data = {}

    # Build Pub/Sub config
    pubsub_config = build_pubsub_config(config_data)

    # Build data sources
    data_sources = build_data_sources(config_data)

    # Build service config
    service_data = config_data.get("service", {})

    collection_config = CollectionConfig(
        environment=os.getenv(
            "COLLECTION_ENVIRONMENT", service_data.get("environment", "development")
        ),
        log_level=os.getenv("COLLECTION_LOG_LEVEL", service_data.get("log_level", "INFO")),
        max_concurrent_collectors=int(
            os.getenv(
                "COLLECTION_MAX_CONCURRENT_COLLECTORS",
                service_data.get("max_concurrent_collectors", 10),
            )
        ),
        health_check_interval_seconds=int(
            os.getenv(
                "COLLECTION_HEALTH_CHECK_INTERVAL_SECONDS",
                service_data.get("health_check_interval_seconds", 60),
            )
        ),
        storage_service_url=os.getenv(
            "COLLECTION_STORAGE_SERVICE_URL", service_data.get("storage_service_url")
        ),
        pubsub=pubsub_config,
        data_sources=data_sources,
    )

    print(f"Configuration loaded successfully:")
    print(f"  - Environment: {collection_config.environment}")
    print(f"  - Data sources: {len(collection_config.data_sources)}")
    print(f"  - Enabled sources: {len(collection_config.get_enabled_sources())}")
    print(f"  - Pub/Sub project: {collection_config.pubsub.project_id}")

    return collection_config


# Example usage
if __name__ == "__main__":
    import sys

    # Load config
    config_file = sys.argv[1] if len(sys.argv) > 1 else "config/config.example.yaml"

    try:
        config = load_collection_config(config_file)

        print("\n" + "=" * 80)
        print("Configuration Summary")
        print("=" * 80)

        print(f"\nService: {config.environment}")
        print(f"Log Level: {config.log_level}")
        print(f"Storage Service: {config.storage_service_url or 'Mock (Development)'}")

        print(f"\nPub/Sub:")
        print(f"  Project: {config.pubsub.project_id}")
        print(f"  IOC Topic: {config.pubsub.raw_ioc_events_topic}")
        print(f"  Activity Topic: {config.pubsub.raw_activity_events_topic}")

        print(f"\nData Sources ({len(config.data_sources)} total):")
        for source in config.data_sources:
            status = "ENABLED" if source.enabled else "DISABLED"
            print(
                f"  [{status}] {source.name} ({source.collector_type.value}) "
                f"- every {source.collection_interval_minutes} min"
            )

    except Exception as e:
        print(f"ERROR: Failed to load configuration: {e}")
        sys.exit(1)
