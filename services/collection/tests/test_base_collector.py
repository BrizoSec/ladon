"""Tests for base collector and watermark manager."""

import sys
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

# Add src directory to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from collectors.base import CollectionMetrics, WatermarkManager


class TestWatermarkManager:
    """Tests for WatermarkManager."""

    @pytest.mark.asyncio
    async def test_get_watermark_no_storage(self):
        """Test getting watermark with no storage client."""
        manager = WatermarkManager()
        watermark = await manager.get_watermark("test_source")

        assert watermark is None

    @pytest.mark.asyncio
    async def test_get_watermark_from_storage(self, mock_storage_client):
        """Test getting watermark from storage."""
        expected_watermark = {
            "source_id": "test_source",
            "last_successful_timestamp": datetime.utcnow(),
            "status": "success",
        }
        mock_storage_client.get_watermark.return_value = expected_watermark

        manager = WatermarkManager(mock_storage_client)
        watermark = await manager.get_watermark("test_source")

        assert watermark == expected_watermark
        mock_storage_client.get_watermark.assert_called_once_with("test_source")

    @pytest.mark.asyncio
    async def test_get_watermark_caching(self, mock_storage_client):
        """Test that watermarks are cached in memory."""
        expected_watermark = {
            "source_id": "test_source",
            "last_successful_timestamp": datetime.utcnow(),
            "status": "success",
        }
        mock_storage_client.get_watermark.return_value = expected_watermark

        manager = WatermarkManager(mock_storage_client)

        # First call - fetch from storage
        watermark1 = await manager.get_watermark("test_source")
        # Second call - should use cache
        watermark2 = await manager.get_watermark("test_source")

        assert watermark1 == watermark2
        # Storage should only be called once
        assert mock_storage_client.get_watermark.call_count == 1

    @pytest.mark.asyncio
    async def test_update_watermark_success(self, mock_storage_client):
        """Test updating watermark with success status."""
        manager = WatermarkManager(mock_storage_client)
        timestamp = datetime.utcnow()

        result = await manager.update_watermark(
            source_id="test_source",
            timestamp=timestamp,
            status="success",
            records_collected=100,
        )

        assert result is True
        mock_storage_client.update_watermark.assert_called_once()

        # Verify watermark is cached
        watermark = await manager.get_watermark("test_source")
        assert watermark["source_id"] == "test_source"
        assert watermark["last_successful_timestamp"] == timestamp
        assert watermark["status"] == "success"
        assert watermark["records_collected"] == 100

    @pytest.mark.asyncio
    async def test_update_watermark_failed(self, mock_storage_client):
        """Test updating watermark with failed status."""
        manager = WatermarkManager(mock_storage_client)
        timestamp = datetime.utcnow()

        result = await manager.update_watermark(
            source_id="test_source",
            timestamp=timestamp,
            status="failed",
            error_message="Connection timeout",
        )

        assert result is True

        # Verify watermark is cached
        watermark = await manager.get_watermark("test_source")
        assert watermark["status"] == "failed"
        assert watermark["error_message"] == "Connection timeout"
        # Should NOT update last_successful_timestamp on failure
        assert "last_successful_timestamp" not in watermark

    def test_get_starting_timestamp_with_watermark(self, mock_storage_client):
        """Test getting starting timestamp when watermark exists."""
        past_timestamp = datetime.utcnow() - timedelta(hours=2)
        watermark = {
            "source_id": "test_source",
            "last_successful_timestamp": past_timestamp,
            "status": "success",
        }

        manager = WatermarkManager(mock_storage_client)
        manager._watermarks["test_source"] = watermark

        starting_timestamp = manager.get_starting_timestamp("test_source")

        assert starting_timestamp == past_timestamp

    def test_get_starting_timestamp_no_watermark(self):
        """Test getting starting timestamp when no watermark exists."""
        manager = WatermarkManager()

        starting_timestamp = manager.get_starting_timestamp(
            "test_source", default_lookback_hours=12
        )

        # Should be approximately 12 hours ago
        expected = datetime.utcnow() - timedelta(hours=12)
        diff = abs((starting_timestamp - expected).total_seconds())
        assert diff < 60  # Within 1 minute


class TestCollectionMetrics:
    """Tests for CollectionMetrics."""

    def test_start_and_end(self):
        """Test starting and ending metrics collection."""
        metrics = CollectionMetrics()
        metrics.start()

        assert metrics.start_time is not None

        metrics.end()
        assert metrics.end_time is not None
        assert metrics.end_time >= metrics.start_time

    def test_add_success(self):
        """Test adding successful events."""
        metrics = CollectionMetrics()
        metrics.add_success(10)
        metrics.add_success(5)

        assert metrics.events_collected == 15

    def test_add_failure(self):
        """Test adding failed events."""
        metrics = CollectionMetrics()
        metrics.add_failure(3, "Error 1")
        metrics.add_failure(2, "Error 2")

        assert metrics.events_failed == 5
        assert len(metrics.collection_errors) == 2

    def test_increment_batch(self):
        """Test incrementing batch counter."""
        metrics = CollectionMetrics()
        metrics.increment_batch()
        metrics.increment_batch()

        assert metrics.batches_processed == 2

    def test_get_duration_seconds(self):
        """Test getting collection duration."""
        metrics = CollectionMetrics()
        metrics.start_time = datetime.utcnow() - timedelta(seconds=10)
        metrics.end_time = datetime.utcnow()

        duration = metrics.get_duration_seconds()

        assert duration is not None
        assert 9 <= duration <= 11  # Approximately 10 seconds

    def test_get_duration_not_started(self):
        """Test getting duration when not started."""
        metrics = CollectionMetrics()

        duration = metrics.get_duration_seconds()

        assert duration is None

    def test_to_dict(self):
        """Test converting metrics to dictionary."""
        metrics = CollectionMetrics()
        metrics.start()
        metrics.add_success(100)
        metrics.add_failure(5, "Error")
        metrics.increment_batch()
        metrics.end()

        result = metrics.to_dict()

        assert result["events_collected"] == 100
        assert result["events_failed"] == 5
        assert result["batches_processed"] == 1
        assert result["duration_seconds"] is not None
        assert result["start_time"] is not None
        assert result["end_time"] is not None
