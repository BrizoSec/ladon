"""Tests for AlienVault OTX collector."""

import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Add src directory to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from collectors.alienvault_otx import AlienVaultOTXCollector
from collectors.base import WatermarkManager


class TestAlienVaultOTXCollector:
    """Tests for AlienVault OTX collector."""

    @pytest.fixture
    def collector(self, alienvault_otx_config, mock_storage_client, mock_publisher):
        """Create AlienVault OTX collector instance."""
        watermark_manager = WatermarkManager(mock_storage_client)
        return AlienVaultOTXCollector(
            config=alienvault_otx_config,
            watermark_manager=watermark_manager,
            publisher=mock_publisher,
        )

    @pytest.mark.asyncio
    async def test_validate_connection_success(
        self, collector, mock_http_session
    ):
        """Test successful connection validation."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_http_session.get = MagicMock(return_value=mock_response)
        collector.session = mock_http_session

        is_valid = await collector.validate_connection()

        assert is_valid is True

    @pytest.mark.asyncio
    async def test_validate_connection_failure(
        self, collector, mock_http_session
    ):
        """Test failed connection validation."""
        mock_response = MagicMock()
        mock_response.status = 403
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_http_session.get = MagicMock(return_value=mock_response)
        collector.session = mock_http_session

        is_valid = await collector.validate_connection()

        assert is_valid is False

    @pytest.mark.asyncio
    async def test_fetch_pulses(self, collector, mock_http_session):
        """Test fetching pulses from OTX API."""
        mock_pulse = {
            "id": "pulse_123",
            "name": "Malware Campaign",
            "tags": ["malware", "c2"],
            "created": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
            "indicators": [],
        }

        mock_response = MagicMock()
        mock_response.json = AsyncMock(return_value={"results": [mock_pulse]})
        mock_response.raise_for_status = MagicMock()
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_http_session.get = MagicMock(return_value=mock_response)
        collector.session = mock_http_session

        pulses = await collector._fetch_pulses(datetime.utcnow())

        assert len(pulses) == 1
        assert pulses[0]["id"] == "pulse_123"

    def test_extract_iocs_from_pulse(self, collector):
        """Test extracting IOCs from a pulse."""
        pulse = {
            "id": "pulse_123",
            "name": "Ransomware Campaign",
            "tags": ["ransomware", "crypto"],
            "created": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
            "indicators": [
                {
                    "type": "domain",
                    "indicator": "evil.com",
                    "description": "C2 domain",
                    "role": "C2",
                },
                {
                    "type": "IPv4",
                    "indicator": "192.0.2.1",
                    "description": "Malicious IP",
                },
            ],
        }

        iocs = collector._extract_iocs_from_pulse(pulse)

        assert len(iocs) == 2

        # Check domain IOC
        domain_ioc = iocs[0]
        assert domain_ioc["ioc_value"] == "evil.com"
        assert domain_ioc["ioc_type"] == "domain"
        assert domain_ioc["threat_type"] == "ransomware"
        assert domain_ioc["source"] == "alienvault_otx"

        # Check IP IOC
        ip_ioc = iocs[1]
        assert ip_ioc["ioc_value"] == "192.0.2.1"
        assert ip_ioc["ioc_type"] == "ip"

    def test_infer_threat_type_ransomware(self, collector):
        """Test inferring ransomware threat type."""
        threat_type = collector._infer_threat_type(
            tags=["ransomware", "crypto"],
            pulse_name="WannaCry Campaign",
        )

        assert threat_type == "ransomware"

    def test_infer_threat_type_c2(self, collector):
        """Test inferring C2 threat type."""
        threat_type = collector._infer_threat_type(
            tags=["c2", "malware"],
            pulse_name="Command and Control Infrastructure",
        )

        assert threat_type == "c2"

    def test_infer_threat_type_default(self, collector):
        """Test default threat type inference."""
        threat_type = collector._infer_threat_type(
            tags=["suspicious"],
            pulse_name="Unknown activity",
        )

        assert threat_type == "malware"

    @pytest.mark.asyncio
    async def test_collect_success(
        self, collector, mock_http_session, mock_storage_client, mock_publisher
    ):
        """Test successful collection."""
        # Mock pulses with indicators
        mock_pulse = {
            "id": "pulse_123",
            "name": "Malware Campaign",
            "tags": ["malware"],
            "created": "2024-01-01T00:00:00Z",
            "modified": "2024-01-02T00:00:00Z",
            "indicators": [
                {
                    "type": "domain",
                    "indicator": "evil.com",
                    "description": "Malicious domain",
                }
            ],
        }

        mock_response = MagicMock()
        mock_response.json = AsyncMock(return_value={"results": [mock_pulse]})
        mock_response.raise_for_status = MagicMock()
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_http_session.get = MagicMock(return_value=mock_response)
        collector.session = mock_http_session

        metrics = await collector.collect()

        assert metrics["events_collected"] == 1
        assert metrics["events_failed"] == 0
        assert mock_publisher.publish_batch.called

    @pytest.mark.asyncio
    async def test_collect_no_pulses(
        self, collector, mock_http_session, mock_storage_client
    ):
        """Test collection when no pulses are returned."""
        mock_response = MagicMock()
        mock_response.json = AsyncMock(return_value={"results": []})
        mock_response.raise_for_status = MagicMock()
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_http_session.get = MagicMock(return_value=mock_response)
        collector.session = mock_http_session

        metrics = await collector.collect()

        assert metrics["events_collected"] == 0
        assert mock_storage_client.update_watermark.called
