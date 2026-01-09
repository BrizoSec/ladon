"""Test fixtures for Collection Service tests."""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest


@pytest.fixture
def mock_storage_client():
    """Mock storage service client."""
    client = AsyncMock()

    # Mock watermark methods
    client.get_watermark = AsyncMock(return_value=None)
    client.update_watermark = AsyncMock(return_value=True)

    return client


@pytest.fixture
def mock_publisher():
    """Mock Pub/Sub publisher."""
    publisher = AsyncMock()
    publisher.publish_batch = AsyncMock(return_value=["msg-1", "msg-2"])
    publisher.publish_ioc_batch = AsyncMock(return_value=["msg-1"])
    publisher.publish_activity_batch = AsyncMock(return_value=["msg-1"])
    return publisher


@pytest.fixture
def sample_ioc_data():
    """Sample IOC data for testing."""
    return {
        "ioc_value": "evil.com",
        "ioc_type": "domain",
        "threat_type": "malware",
        "confidence": 0.85,
        "source": "test_source",
        "first_seen": datetime.utcnow().isoformat(),
        "last_seen": datetime.utcnow().isoformat(),
        "tags": ["malware", "c2"],
        "metadata": {"test": "data"},
    }


@pytest.fixture
def sample_activity_data():
    """Sample activity event data for testing."""
    return {
        "event_id": "evt_123",
        "timestamp": datetime.utcnow().isoformat(),
        "source": "dns",
        "event_type": "dns_query",
        "domain": "test.com",
        "src_ip": "192.0.2.1",
        "dst_ip": "8.8.8.8",
    }


@pytest.fixture
def sample_alienvault_pulse():
    """Sample AlienVault OTX pulse for threat extraction testing."""
    return {
        "id": "test_pulse_123",
        "name": "APT29 Campaign - 2024",
        "description": "APT29 phishing campaign targeting government agencies",
        "author_name": "analyst@otx.alienvault.com",
        "created": "2024-01-01T00:00:00",
        "modified": "2024-01-02T00:00:00",
        "adversary": "APT29",
        "malware_families": ["Cobalt Strike", "MiniDuke"],
        "attack_ids": ["T1566.001", "T1059.001", "T1071.001"],
        "tags": ["apt", "russia", "government", "phishing"],
        "targeted_countries": ["US", "UK", "EU"],
        "industries": ["government", "defense"],
        "references": ["https://example.com/report1"],
        "indicators": [
            {
                "indicator": "evil.com",
                "type": "domain",
                "created": "2024-01-01T00:00:00",
            },
            {
                "indicator": "192.0.2.1",
                "type": "IPv4",
                "created": "2024-01-01T00:00:00",
            },
        ],
    }


@pytest.fixture
def sample_abusech_entry():
    """Sample abuse.ch entry for threat extraction testing."""
    return {
        "id": "12345",
        "dateadded": "2024-01-01 00:00:00 UTC",
        "ioc": "evil.com",
        "threat_type": "malware_download",
        "ioc_type": "domain",
        "malware": "win.asyncrat",
        "malware_printable": "AsyncRAT",
        "malware_alias": "AsyncRAT",
        "malware_malpedia": "https://malpedia.caad.fkie.fraunhofer.de/details/win.asyncrat",
        "confidence_level": 90,
        "tags": ["rat", "trojan", "windows"],
        "reference": "https://threatfox.abuse.ch/ioc/12345/",
    }


@pytest.fixture
def sample_misp_event():
    """Sample MISP event for threat extraction testing."""
    return {
        "Event": {
            "id": "123",
            "info": "APT29 Infrastructure",
            "date": "2024-01-01",
            "threat_level_id": "1",
            "analysis": "2",
            "Attribute": [
                {
                    "type": "domain",
                    "value": "evil.com",
                    "category": "Network activity",
                    "to_ids": True,
                },
            ],
            "Tag": [
                {"name": "apt:APT29"},
                {"name": "misp-galaxy:threat-actor=\"APT29\""},
                {"name": "misp-galaxy:mitre-attack-pattern=\"Phishing - T1566\""},
            ],
            "Galaxy": [
                {
                    "name": "Threat Actor",
                    "type": "threat-actor",
                    "GalaxyCluster": [
                        {
                            "value": "APT29",
                            "description": "APT29 is a threat group",
                            "meta": {
                                "synonyms": ["Cozy Bear", "The Dukes"],
                                "country": ["RU"],
                            },
                        }
                    ],
                }
            ],
        }
    }


@pytest.fixture
def alienvault_otx_config():
    """AlienVault OTX configuration for testing."""
    import sys
    from pathlib import Path

    # Add src directory to path
    src_path = Path(__file__).parent.parent / "src"
    sys.path.insert(0, str(src_path))

    from config import AlienVaultOTXConfig

    return AlienVaultOTXConfig(
        id="otx_test",
        name="AlienVault OTX Test",
        api_key="test-api-key",
        pubsub_topic="raw-ioc-events",
    )


@pytest.fixture
def abuse_ch_config():
    """abuse.ch configuration for testing."""
    import sys
    from pathlib import Path

    src_path = Path(__file__).parent.parent / "src"
    sys.path.insert(0, str(src_path))

    from config import AbuseCHConfig

    return AbuseCHConfig(
        id="abuse_ch_test",
        name="abuse.ch Test",
        pubsub_topic="raw-ioc-events",
    )


@pytest.fixture
def misp_config():
    """MISP configuration for testing."""
    import sys
    from pathlib import Path

    src_path = Path(__file__).parent.parent / "src"
    sys.path.insert(0, str(src_path))

    from config import MISPConfig

    return MISPConfig(
        id="misp_test",
        name="MISP Test",
        url="https://misp.test",
        api_key="test-api-key",
        pubsub_topic="raw-ioc-events",
    )


@pytest.fixture
def trino_config():
    """Trino configuration for testing."""
    import sys
    from pathlib import Path

    src_path = Path(__file__).parent.parent / "src"
    sys.path.insert(0, str(src_path))

    from config import TrinoConfig

    return TrinoConfig(
        id="trino_test",
        name="Trino Test",
        host="trino.test",
        catalog="test_catalog",
        schema="test_schema",
        table="test_table",
        pubsub_topic="raw-activity-events",
    )


@pytest.fixture
def bigquery_config():
    """BigQuery configuration for testing."""
    import sys
    from pathlib import Path

    src_path = Path(__file__).parent.parent / "src"
    sys.path.insert(0, str(src_path))

    from config import BigQuerySourceConfig

    return BigQuerySourceConfig(
        id="bigquery_test",
        name="BigQuery Test",
        project_id="test-project",
        dataset="test_dataset",
        table="test_table",
        pubsub_topic="raw-activity-events",
    )


@pytest.fixture
def collection_config(alienvault_otx_config, trino_config):
    """Collection service configuration for testing."""
    import sys
    from pathlib import Path

    src_path = Path(__file__).parent.parent / "src"
    sys.path.insert(0, str(src_path))

    from config import CollectionConfig, PubSubConfig

    pubsub_config = PubSubConfig(project_id="test-project")

    return CollectionConfig(
        environment="testing",
        log_level="DEBUG",
        pubsub=pubsub_config,
        data_sources=[alienvault_otx_config, trino_config],
    )


@pytest.fixture
def mock_http_session():
    """Mock aiohttp ClientSession."""
    session = MagicMock()

    # Mock response
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value={"results": []})
    mock_response.raise_for_status = MagicMock()
    mock_response.__aenter__ = AsyncMock(return_value=mock_response)
    mock_response.__aexit__ = AsyncMock(return_value=None)

    # Mock session.get and session.post
    session.get = MagicMock(return_value=mock_response)
    session.post = MagicMock(return_value=mock_response)
    session.close = AsyncMock()

    return session


@pytest.fixture
def mock_trino_connection():
    """Mock Trino connection."""
    connection = MagicMock()

    # Mock cursor
    cursor = MagicMock()
    cursor.execute = MagicMock()
    cursor.fetchone = MagicMock(return_value=[1])
    cursor.fetchall = MagicMock(return_value=[])
    cursor.description = [("column1",), ("column2",)]
    cursor.close = MagicMock()

    connection.cursor = MagicMock(return_value=cursor)
    connection.close = MagicMock()

    return connection


@pytest.fixture
def mock_bigquery_client():
    """Mock BigQuery client."""
    client = MagicMock()

    # Mock query job
    query_job = MagicMock()
    query_job.result = MagicMock(return_value=[])
    query_job.total_bytes_processed = 1024
    query_job.total_rows = 0

    client.query = MagicMock(return_value=query_job)
    client.close = MagicMock()

    return client
