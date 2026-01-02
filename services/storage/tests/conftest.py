"""
Pytest configuration and fixtures for storage service tests.

Provides mock objects and test data for all storage repositories.
"""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest
from ladon_models import (
    ActivityEventType,
    ActivitySource,
    Detection,
    DetectionStatus,
    IOCSource,
    IOCType,
    NormalizedActivity,
    NormalizedIOC,
    Severity,
    ThreatType,
)

from storage_service import BigQueryConfig, FirestoreConfig, RedisConfig, StorageConfig


# ============================================================================
# Configuration Fixtures
# ============================================================================


@pytest.fixture
def bigquery_config():
    """BigQuery test configuration."""
    return BigQueryConfig(
        project_id="test-project",
        dataset="test_dataset",
        iocs_table="iocs",
        activity_logs_table="activity_logs",
        detections_table="detections",
    )


@pytest.fixture
def redis_config():
    """Redis test configuration."""
    return RedisConfig(
        host="localhost",
        port=6379,
        db=0,
        ioc_cache_ttl=3600,
        hot_ioc_threshold_hours=48,
        hot_ioc_min_confidence=0.7,
    )


@pytest.fixture
def firestore_config():
    """Firestore test configuration."""
    return FirestoreConfig(
        project_id="test-project",
        watermarks_collection="watermarks",
        config_collection="config",
    )


@pytest.fixture
def storage_config(bigquery_config, redis_config, firestore_config):
    """Complete storage service configuration."""
    return StorageConfig(
        bigquery=bigquery_config,
        redis=redis_config,
        firestore=firestore_config,
        enable_bigquery=True,
        enable_redis=True,
        enable_firestore=True,
    )


# ============================================================================
# Test Data Fixtures
# ============================================================================


@pytest.fixture
def sample_ioc():
    """Sample normalized IOC for testing."""
    return NormalizedIOC(
        ioc_value="evil.com",
        ioc_type=IOCType.DOMAIN,
        threat_type=ThreatType.C2,
        confidence=0.95,
        source=IOCSource.ALIENVAULT_OTX,
        first_seen=datetime.utcnow() - timedelta(hours=24),
        last_seen=datetime.utcnow(),
        tags=["apt", "cobalt-strike"],
        is_active=True,
    )


@pytest.fixture
def sample_ioc_low_confidence():
    """Sample IOC with low confidence (shouldn't be cached)."""
    return NormalizedIOC(
        ioc_value="suspicious.com",
        ioc_type=IOCType.DOMAIN,
        threat_type=ThreatType.SUSPICIOUS,
        confidence=0.3,
        source=IOCSource.CUSTOM,
        first_seen=datetime.utcnow() - timedelta(days=100),
        last_seen=datetime.utcnow() - timedelta(days=90),
        tags=["low-confidence"],
        is_active=True,
    )


@pytest.fixture
def sample_iocs(sample_ioc):
    """List of sample IOCs for batch testing."""
    iocs = []
    for i in range(5):
        ioc = NormalizedIOC(
            ioc_value=f"evil{i}.com",
            ioc_type=IOCType.DOMAIN,
            threat_type=ThreatType.C2,
            confidence=0.8 + (i * 0.02),
            source=IOCSource.ALIENVAULT_OTX,
            first_seen=datetime.utcnow() - timedelta(hours=24),
            last_seen=datetime.utcnow(),
            tags=["test"],
            is_active=True,
        )
        iocs.append(ioc)
    return iocs


@pytest.fixture
def sample_activity():
    """Sample normalized activity event."""
    return NormalizedActivity(
        event_id="evt_12345",
        timestamp=datetime.utcnow(),
        source=ActivitySource.DNS,
        event_type=ActivityEventType.DNS_QUERY,
        src_ip="10.0.1.100",
        domain="evil.com",
    )


@pytest.fixture
def sample_detection(sample_ioc):
    """Sample detection."""
    return Detection(
        detection_id="det_12345",
        timestamp=datetime.utcnow(),
        ioc_value=sample_ioc.ioc_value,
        ioc_type=sample_ioc.ioc_type.value,
        activity_event_id="evt_12345",
        activity_source=ActivitySource.DNS,
        severity=Severity.HIGH,
        confidence=0.95,
        status=DetectionStatus.NEW,
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
    )


# ============================================================================
# Mock Fixtures
# ============================================================================


@pytest.fixture
def mock_bigquery_client():
    """Mock BigQuery client."""
    client = MagicMock()

    # Mock insert_rows_json to return no errors (success)
    client.insert_rows_json.return_value = []

    # Mock query results
    query_job = MagicMock()
    query_job.result.return_value = []
    client.query.return_value = query_job

    return client


@pytest.fixture
def mock_redis_client():
    """Mock async Redis client."""
    client = AsyncMock()

    # Mock basic operations
    client.ping.return_value = True
    client.setex.return_value = True
    client.get.return_value = None
    client.delete.return_value = 1
    client.close.return_value = None

    # Mock info and stats
    client.info.return_value = {
        "keyspace_hits": 100,
        "keyspace_misses": 10,
        "used_memory_human": "1.5M",
        "connected_clients": 5,
    }

    client.scan.return_value = (0, [])

    return client


@pytest.fixture
def mock_firestore_client():
    """Mock Firestore client."""
    client = MagicMock()

    # Mock collection and document operations
    mock_doc = MagicMock()
    mock_doc.get.return_value.exists = False
    mock_doc.get.return_value.to_dict.return_value = {}

    mock_collection = MagicMock()
    mock_collection.document.return_value = mock_doc
    mock_collection.stream.return_value = []

    client.collection.return_value = mock_collection

    return client


# ============================================================================
# Helper Functions
# ============================================================================


def create_bigquery_row_from_ioc(ioc: NormalizedIOC) -> dict:
    """Convert IOC to BigQuery row format for testing."""
    return {
        "ioc_value": ioc.ioc_value,
        "ioc_type": ioc.ioc_type.value,
        "threat_type": ioc.threat_type.value,
        "confidence": ioc.confidence,
        "source": ioc.source.value,
        "first_seen": ioc.first_seen,
        "last_seen": ioc.last_seen,
        "tags": ioc.tags,
        "is_active": ioc.is_active,
    }


def create_redis_ioc_data(ioc: NormalizedIOC) -> dict:
    """Convert IOC to Redis cached format for testing."""
    return {
        "ioc_value": ioc.ioc_value,
        "ioc_type": ioc.ioc_type.value,
        "threat_type": ioc.threat_type.value,
        "confidence": ioc.confidence,
        "source": ioc.source.value,
        "first_seen": ioc.first_seen.isoformat(),
        "last_seen": ioc.last_seen.isoformat(),
        "tags": ioc.tags,
        "metadata": {},
    }
