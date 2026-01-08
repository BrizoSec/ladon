"""Test fixtures for Normalization Service tests."""

from datetime import datetime

import pytest


@pytest.fixture
def sample_raw_ioc():
    """Sample raw IOC data."""
    return {
        "ioc_value": "evil.com",
        "ioc_type": "domain",
        "threat_type": "malware",
        "confidence": 0.85,
        "source": "alienvault_otx",
        "first_seen": "2024-01-01T00:00:00Z",
        "last_seen": "2024-01-02T00:00:00Z",
        "tags": ["malware", "c2"],
        "metadata": {"pulse_id": "123"},
    }


@pytest.fixture
def sample_raw_dns_event():
    """Sample raw DNS event."""
    return {
        "event_id": "dns_123",
        "timestamp": "2024-01-01T12:00:00Z",
        "query_name": "test.com",
        "client_ip": "192.0.2.1",
        "server_ip": "8.8.8.8",
        "source": "dns",
        "event_type": "dns_query",
    }


@pytest.fixture
def sample_raw_proxy_event():
    """Sample raw proxy event."""
    return {
        "event_id": "proxy_123",
        "timestamp": "2024-01-01T12:00:00Z",
        "url": "https://example.com/path",
        "client_ip": "192.0.2.1",
        "server_ip": "93.184.216.34",
        "username": "user@example.com",
        "source": "proxy",
        "event_type": "http_request",
    }


@pytest.fixture
def sample_raw_mde_event():
    """Sample raw MDE event."""
    return {
        "event_id": "mde_123",
        "timestamp": "2024-01-01T12:00:00Z",
        "action_type": "ProcessCreated",
        "device_name": "workstation-001",
        "account_name": "DOMAIN\\user",
        "process_command_line": "powershell.exe -enc base64data",
        "sha256": "abc123def456",
        "local_ip": "10.0.0.100",
        "remote_ip": "192.0.2.50",
        "source": "mde",
    }


@pytest.fixture
def normalization_config():
    """Normalization service configuration for testing."""
    import sys
    from pathlib import Path

    # Add src directory to path
    src_path = Path(__file__).parent.parent / "src"
    sys.path.insert(0, str(src_path))

    from config import NormalizationConfig, PubSubConfig

    pubsub_config = PubSubConfig(project_id="test-project")

    return NormalizationConfig(
        environment="testing",
        log_level="DEBUG",
        pubsub=pubsub_config,
        strict_validation=False,
        skip_invalid_iocs=True,
    )


@pytest.fixture
def mock_subscriber():
    """Mock Pub/Sub subscriber."""
    import sys
    from pathlib import Path

    src_path = Path(__file__).parent.parent / "src"
    sys.path.insert(0, str(src_path))

    from subscribers.pubsub_subscriber import MockPubSubSubscriber

    return MockPubSubSubscriber(
        project_id="test-project",
        subscription_name="test-sub",
    )


@pytest.fixture
def sample_raw_threat():
    """Sample raw threat data."""
    return {
        "threat_id": "threat_apt29",
        "name": "APT29",
        "aliases": ["Cozy Bear", "The Dukes"],
        "threat_category": "actor",
        "threat_type": "c2",
        "description": "Advanced persistent threat group attributed to Russia",
        "severity": "critical",
        "confidence": 0.95,
        "techniques": [
            {
                "technique_id": "T1059.001",
                "technique_name": "PowerShell",
                "tactic": "Execution",
                "sub_technique": "Command and Scripting Interpreter: PowerShell",
                "detection_methods": ["Monitor PowerShell execution"],
                "mitigations": ["Execution Prevention"],
                "reference_url": "https://attack.mitre.org/techniques/T1059/001/",
            }
        ],
        "tactics": ["Execution", "Persistence"],
        "sophistication": "advanced",
        "actor_type": "nation_state",
        "first_seen": "2024-01-01T00:00:00Z",
        "last_seen": "2024-12-01T00:00:00Z",
        "sources": ["misp", "alienvault_otx"],
        "reference_urls": ["https://attack.mitre.org/groups/G0016/"],
        "tags": ["apt", "russia", "nation-state"],
        "is_active": True,
    }


@pytest.fixture
def sample_raw_malware_threat():
    """Sample raw malware family threat data."""
    return {
        "threat_id": "threat_asyncrat",
        "name": "AsyncRAT",
        "aliases": ["AsyncRAT"],
        "threat_category": "malware_family",
        "threat_type": "malware",
        "description": "Remote Access Trojan targeting Windows systems",
        "severity": "high",
        "confidence": 0.90,
        "techniques": [],
        "tactics": ["Command and Control"],
        "first_seen": "2024-06-01T00:00:00Z",
        "last_seen": "2024-12-01T00:00:00Z",
        "sources": ["abuse_ch"],
        "reference_urls": [],
        "tags": ["rat", "trojan", "windows"],
        "is_active": True,
    }


@pytest.fixture
def sample_raw_threat_ioc_association():
    """Sample raw threat-IOC association data."""
    return {
        "threat_id": "threat_apt29",
        "ioc_value": "evil.com",
        "ioc_type": "domain",
        "relationship_type": "uses",
        "confidence": 0.95,
        "first_seen": "2024-01-01T00:00:00Z",
        "last_seen": "2024-01-02T00:00:00Z",
        "observation_count": 5,
        "sources": ["alienvault_otx", "misp"],
        "reference_urls": ["https://example.com/report"],
        "notes": "APT29 C2 infrastructure",
        "tags": ["c2", "infrastructure"],
    }
