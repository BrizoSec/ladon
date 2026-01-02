"""Integration tests for Collection Service."""

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Add src directory to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from collection_service import CollectionService
from config import CollectorType


class TestCollectionService:
    """Integration tests for Collection Service."""

    @pytest.fixture
    async def service(self, collection_config, mock_storage_client):
        """Create Collection Service instance."""
        service = CollectionService(collection_config, mock_storage_client)
        return service

    @pytest.mark.asyncio
    async def test_initialize(self, service):
        """Test service initialization."""
        # Mock validate_connection for all collectors
        with patch(
            "collectors.alienvault_otx.AlienVaultOTXCollector.validate_connection",
            new_callable=AsyncMock,
            return_value=True,
        ), patch(
            "collectors.trino.TrinoCollector.validate_connection",
            new_callable=AsyncMock,
            return_value=True,
        ):
            await service.initialize()

            # Verify collectors were created
            assert len(service.collectors) == 2

    @pytest.mark.asyncio
    async def test_create_collector_alienvault(
        self, service, alienvault_otx_config
    ):
        """Test creating AlienVault OTX collector."""
        collector = service._create_collector(alienvault_otx_config)

        from collectors.alienvault_otx import AlienVaultOTXCollector

        assert isinstance(collector, AlienVaultOTXCollector)

    @pytest.mark.asyncio
    async def test_create_collector_trino(self, service, trino_config):
        """Test creating Trino collector."""
        collector = service._create_collector(trino_config)

        from collectors.trino import TrinoCollector

        assert isinstance(collector, TrinoCollector)

    @pytest.mark.asyncio
    async def test_create_collector_unknown_type(self, service):
        """Test creating collector with unknown type."""
        from config import DataSourceConfig, SourceType

        invalid_config = DataSourceConfig(
            id="invalid",
            name="Invalid",
            source_type=SourceType.IOC_FEED,
            collector_type="unknown",
            pubsub_topic="test-topic",
        )

        with pytest.raises(ValueError):
            service._create_collector(invalid_config)

    @pytest.mark.asyncio
    async def test_collect_once(self, service, alienvault_otx_config):
        """Test one-time collection for a specific source."""
        # Create mock collector
        mock_collector = AsyncMock()
        mock_collector.collect = AsyncMock(
            return_value={
                "events_collected": 10,
                "events_failed": 0,
                "batches_processed": 1,
                "duration_seconds": 5.0,
            }
        )

        service.collectors[alienvault_otx_config.id] = mock_collector

        metrics = await service.collect_once(alienvault_otx_config.id)

        assert metrics["events_collected"] == 10
        mock_collector.collect.assert_called_once()

    @pytest.mark.asyncio
    async def test_collect_once_not_found(self, service):
        """Test one-time collection for non-existent source."""
        with pytest.raises(KeyError):
            await service.collect_once("nonexistent_source")

    @pytest.mark.asyncio
    async def test_collect_all_once(
        self, service, alienvault_otx_config, trino_config
    ):
        """Test one-time collection for all sources."""
        # Create mock collectors
        mock_collector1 = AsyncMock()
        mock_collector1.collect = AsyncMock(
            return_value={
                "events_collected": 10,
                "events_failed": 0,
                "batches_processed": 1,
                "duration_seconds": 5.0,
            }
        )

        mock_collector2 = AsyncMock()
        mock_collector2.collect = AsyncMock(
            return_value={
                "events_collected": 20,
                "events_failed": 0,
                "batches_processed": 2,
                "duration_seconds": 8.0,
            }
        )

        service.collectors[alienvault_otx_config.id] = mock_collector1
        service.collectors[trino_config.id] = mock_collector2

        results = await service.collect_all_once()

        assert len(results) == 2
        assert results[alienvault_otx_config.id]["events_collected"] == 10
        assert results[trino_config.id]["events_collected"] == 20

    @pytest.mark.asyncio
    async def test_get_status(
        self, service, alienvault_otx_config, mock_storage_client
    ):
        """Test getting service status."""
        # Mock watermark
        mock_storage_client.get_watermark.return_value = {
            "source_id": alienvault_otx_config.id,
            "last_successful_timestamp": "2024-01-01T00:00:00Z",
            "status": "success",
        }

        # Add mock collector
        mock_collector = AsyncMock()
        service.collectors[alienvault_otx_config.id] = mock_collector

        status = await service.get_status()

        assert status["service"] == "collection"
        assert status["total_collectors"] == 1
        assert alienvault_otx_config.id in status["collectors"]

    @pytest.mark.asyncio
    async def test_health_check(self, service, alienvault_otx_config):
        """Test health check."""
        # Create mock collector
        mock_collector = AsyncMock()
        mock_collector.validate_connection = AsyncMock(return_value=True)

        service.collectors[alienvault_otx_config.id] = mock_collector

        health = await service.health_check()

        assert health[alienvault_otx_config.id] is True

    @pytest.mark.asyncio
    async def test_health_check_failure(self, service, alienvault_otx_config):
        """Test health check with failed collector."""
        # Create mock collector that fails validation
        mock_collector = AsyncMock()
        mock_collector.validate_connection = AsyncMock(
            side_effect=Exception("Connection failed")
        )

        service.collectors[alienvault_otx_config.id] = mock_collector

        health = await service.health_check()

        assert health[alienvault_otx_config.id] is False

    @pytest.mark.asyncio
    async def test_start_and_stop(self, service, alienvault_otx_config):
        """Test starting and stopping the service."""
        # Create mock collector
        mock_collector = AsyncMock()
        mock_collector.collect = AsyncMock(
            return_value={
                "events_collected": 10,
                "events_failed": 0,
                "batches_processed": 1,
                "duration_seconds": 5.0,
            }
        )

        service.collectors[alienvault_otx_config.id] = mock_collector

        # Start service (with short interval for testing)
        await service.start()

        # Verify tasks were created
        assert len(service.collection_tasks) == 1
        assert alienvault_otx_config.id in service.collection_tasks

        # Stop service
        await service.stop()

        # Verify tasks were cancelled
        assert len(service.collection_tasks) == 0
