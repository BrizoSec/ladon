"""Tests for Normalization Service."""

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Add src directory to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from normalization_service import NormalizationService


class TestNormalizationService:
    """Tests for Normalization Service."""

    @pytest.fixture
    def service(self, normalization_config):
        """Create normalization service instance."""
        service = NormalizationService(normalization_config)
        return service

    def test_process_ioc_message_success(
        self, service, sample_raw_ioc, mock_subscriber
    ):
        """Test successfully processing an IOC message."""
        message = {
            "data": sample_raw_ioc,
            "attributes": {"source": "alienvault_otx"},
            "ack_id": "ack-123",
            "message_id": "msg-123",
        }

        result = service.process_ioc_message(message)

        assert result is True

    def test_process_ioc_message_invalid(self, service, mock_subscriber):
        """Test processing invalid IOC message."""
        invalid_ioc = {"ioc_value": "test.com"}  # Missing required fields

        message = {
            "data": invalid_ioc,
            "attributes": {"source": "alienvault_otx"},
            "ack_id": "ack-123",
            "message_id": "msg-123",
        }

        result = service.process_ioc_message(message)

        # Should return False but not crash (skip_invalid=True)
        assert result is False

    def test_process_activity_message_success(
        self, service, sample_raw_dns_event, mock_subscriber
    ):
        """Test successfully processing an activity message."""
        message = {
            "data": sample_raw_dns_event,
            "attributes": {"source": "dns"},
            "ack_id": "ack-123",
            "message_id": "msg-123",
        }

        result = service.process_activity_message(message)

        assert result is True

    def test_process_activity_message_invalid(self, service, mock_subscriber):
        """Test processing invalid activity message."""
        invalid_event = {"event_id": "test"}  # Missing required fields

        message = {
            "data": invalid_event,
            "attributes": {"source": "dns"},
            "ack_id": "ack-123",
            "message_id": "msg-123",
        }

        result = service.process_activity_message(message)

        # Should return False but not crash (skip_invalid=True)
        assert result is False

    @pytest.mark.asyncio
    async def test_process_ioc_batch(
        self, service, sample_raw_ioc, mock_subscriber
    ):
        """Test processing a batch of IOC messages."""
        # Setup mock subscriber with messages
        service.ioc_subscriber = mock_subscriber
        mock_subscriber.add_message(
            data=sample_raw_ioc, attributes={"source": "alienvault_otx"}
        )

        stats = await service.process_ioc_batch()

        assert stats["total"] == 1
        assert stats["success"] == 1
        assert stats["failed"] == 0

    @pytest.mark.asyncio
    async def test_process_activity_batch(
        self, service, sample_raw_dns_event, mock_subscriber
    ):
        """Test processing a batch of activity messages."""
        # Setup mock subscriber with messages
        service.activity_subscriber = mock_subscriber
        mock_subscriber.add_message(
            data=sample_raw_dns_event, attributes={"source": "dns"}
        )

        stats = await service.process_activity_batch()

        assert stats["total"] == 1
        assert stats["success"] == 1
        assert stats["failed"] == 0

    @pytest.mark.asyncio
    async def test_get_status(self, service):
        """Test getting service status."""
        status = await service.get_status()

        assert status["service"] == "normalization"
        assert "running" in status
        assert "config" in status
