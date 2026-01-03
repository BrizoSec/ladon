"""Integration tests for the unified Storage Service."""

import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from storage_service import StorageService


class TestStorageServiceIntegration:
    """Integration tests for the unified Storage Service."""

    @pytest.fixture
    def mock_all_clients(self, mock_bigquery_client, mock_redis_client, mock_firestore_client):
        """Mock all storage backend clients."""
        with patch("storage_service.repositories.bigquery_repository.bigquery.Client") as mock_bq, \
             patch("storage_service.repositories.redis_repository.redis.Redis") as mock_redis, \
             patch("storage_service.repositories.firestore_repository.firestore.Client") as mock_fs:

            mock_bq.return_value = mock_bigquery_client
            mock_redis.return_value = mock_redis_client
            mock_fs.return_value = mock_firestore_client

            yield {
                "bigquery": mock_bigquery_client,
                "redis": mock_redis_client,
                "firestore": mock_firestore_client,
            }

    @pytest.fixture
    async def storage_service(self, storage_config, mock_all_clients):
        """Create initialized storage service with mocked backends."""
        service = StorageService(storage_config)
        await service.initialize()
        return service

    # ========================================================================
    # IOC Operations
    # ========================================================================

    @pytest.mark.asyncio
    async def test_store_ioc_with_caching(
        self, storage_service, sample_ioc, mock_all_clients
    ):
        """Test storing IOC with automatic caching."""
        mock_all_clients["bigquery"].insert_rows_json.return_value = []
        mock_all_clients["redis"].setex.return_value = True

        result = await storage_service.store_ioc(sample_ioc, cache=True)

        assert result is True
        # Verify BigQuery insert was called
        mock_all_clients["bigquery"].insert_rows_json.assert_called_once()
        # Verify Redis cache was called (hot IOC)
        mock_all_clients["redis"].setex.assert_called_once()

    @pytest.mark.asyncio
    async def test_store_ioc_low_confidence_no_cache(
        self, storage_service, sample_ioc_low_confidence, mock_all_clients
    ):
        """Test that low confidence IOCs aren't cached."""
        mock_all_clients["bigquery"].insert_rows_json.return_value = []

        result = await storage_service.store_ioc(sample_ioc_low_confidence, cache=True)

        assert result is True
        # Verify BigQuery insert was called
        mock_all_clients["bigquery"].insert_rows_json.assert_called_once()
        # Verify Redis cache was NOT called (low confidence)
        mock_all_clients["redis"].setex.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_ioc_cache_hit(self, storage_service, sample_ioc, mock_all_clients):
        """Test cache-first IOC lookup with cache hit."""
        # Mock Redis cache hit
        cached_data = {
            "ioc_value": sample_ioc.ioc_value,
            "ioc_type": sample_ioc.ioc_type.value,
            "threat_type": sample_ioc.threat_type.value,
            "confidence": sample_ioc.confidence,
            "source": sample_ioc.source.value,
            "first_seen": sample_ioc.first_seen.isoformat(),
            "last_seen": sample_ioc.last_seen.isoformat(),
            "tags": sample_ioc.tags,
            "metadata": {},
        }
        mock_all_clients["redis"].get.return_value = json.dumps(cached_data)

        result = await storage_service.get_ioc(
            sample_ioc.ioc_value, sample_ioc.ioc_type.value, use_cache=True
        )

        assert result is not None
        assert result.ioc_value == sample_ioc.ioc_value
        # Verify Redis was checked
        mock_all_clients["redis"].get.assert_called_once()
        # Verify BigQuery was NOT queried (cache hit)
        mock_all_clients["bigquery"].query.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_ioc_cache_miss_bigquery_hit(
        self, storage_service, sample_ioc, mock_all_clients
    ):
        """Test cache miss followed by BigQuery lookup."""
        # Mock Redis cache miss
        mock_all_clients["redis"].get.return_value = None

        # Mock BigQuery hit
        mock_row = MagicMock()
        mock_row.__iter__ = lambda self: iter([
            ("ioc_value", sample_ioc.ioc_value),
            ("ioc_type", sample_ioc.ioc_type.value),
            ("threat_type", sample_ioc.threat_type.value),
            ("confidence", sample_ioc.confidence),
            ("source", sample_ioc.source.value),
            ("first_seen", sample_ioc.first_seen),
            ("last_seen", sample_ioc.last_seen),
            ("tags", sample_ioc.tags),
            ("is_active", True),
        ])

        query_job = MagicMock()
        query_job.result.return_value = [mock_row]
        mock_all_clients["bigquery"].query.return_value = query_job

        result = await storage_service.get_ioc(
            sample_ioc.ioc_value, sample_ioc.ioc_type.value, use_cache=True
        )

        assert result is not None
        # Verify both Redis and BigQuery were queried
        mock_all_clients["redis"].get.assert_called_once()
        mock_all_clients["bigquery"].query.assert_called_once()
        # Verify result was cached after BigQuery lookup
        mock_all_clients["redis"].setex.assert_called_once()

    @pytest.mark.asyncio
    async def test_store_iocs_batch_with_selective_caching(
        self, storage_service, sample_iocs, mock_all_clients
    ):
        """Test batch IOC storage with selective caching based on criteria."""
        mock_all_clients["bigquery"].insert_rows_json.return_value = []

        result = await storage_service.store_iocs_batch(sample_iocs, cache_hot=True)

        assert result["success"] == 5
        assert result["failed"] == 0
        # Verify batch insert was called
        mock_all_clients["bigquery"].insert_rows_json.assert_called_once()
        # Verify some IOCs were cached (high confidence ones)
        assert mock_all_clients["redis"].setex.call_count > 0

    # ========================================================================
    # Activity Operations
    # ========================================================================

    @pytest.mark.asyncio
    async def test_store_activity(self, storage_service, sample_activity, mock_all_clients):
        """Test storing activity event."""
        mock_all_clients["bigquery"].insert_rows_json.return_value = []

        result = await storage_service.store_activity(sample_activity)

        assert result is True
        mock_all_clients["bigquery"].insert_rows_json.assert_called_once()

    # ========================================================================
    # Detection Operations
    # ========================================================================

    @pytest.mark.asyncio
    async def test_store_detection(self, storage_service, sample_detection, mock_all_clients):
        """Test storing detection."""
        mock_all_clients["bigquery"].insert_rows_json.return_value = []

        result = await storage_service.store_detection(sample_detection)

        assert result is True
        mock_all_clients["bigquery"].insert_rows_json.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_detection_status_with_case_id(
        self, storage_service, mock_all_clients
    ):
        """Test updating detection status with ServiceNow case ID."""
        query_job = MagicMock()
        query_job.result.return_value = None
        mock_all_clients["bigquery"].query.return_value = query_job

        result = await storage_service.update_detection_status(
            detection_id="det_123", status="Investigating", case_id="INC0012345"
        )

        assert result is True
        mock_all_clients["bigquery"].query.assert_called_once()

    # ========================================================================
    # Cache Operations
    # ========================================================================

    @pytest.mark.asyncio
    async def test_invalidate_ioc_cache(self, storage_service, mock_all_clients):
        """Test invalidating IOC from cache."""
        mock_all_clients["redis"].delete.return_value = 1

        result = await storage_service.invalidate_ioc_cache("evil.com", "domain")

        assert result is True
        mock_all_clients["redis"].delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_cache_stats(self, storage_service, mock_all_clients):
        """Test retrieving cache statistics."""
        mock_all_clients["redis"].info.side_effect = [
            {"keyspace_hits": 1000, "keyspace_misses": 50},
            {},
        ]
        mock_all_clients["redis"].scan.return_value = (0, [])

        stats = await storage_service.get_cache_stats()

        assert "hits" in stats
        assert "misses" in stats
        assert "hit_rate" in stats

    @pytest.mark.asyncio
    async def test_warm_ioc_cache(self, storage_service, sample_iocs, mock_all_clients):
        """Test warming cache with hot IOCs from BigQuery."""
        # Mock BigQuery search to return hot IOCs
        mock_rows = []
        for ioc in sample_iocs:
            mock_row = MagicMock()
            mock_row.__iter__ = lambda self, i=ioc: iter([
                ("ioc_value", i.ioc_value),
                ("ioc_type", i.ioc_type.value),
                ("threat_type", i.threat_type.value),
                ("confidence", i.confidence),
                ("source", i.source.value),
                ("first_seen", i.first_seen),
                ("last_seen", i.last_seen),
                ("tags", i.tags),
                ("is_active", True),
            ])
            mock_rows.append(mock_row)

        query_job = MagicMock()
        query_job.result.return_value = mock_rows
        mock_all_clients["bigquery"].query.return_value = query_job

        cached_count = await storage_service.warm_ioc_cache(min_confidence=0.7, hours=48)

        assert cached_count > 0
        # Verify BigQuery search was called
        mock_all_clients["bigquery"].query.assert_called()
        # Verify IOCs were cached
        assert mock_all_clients["redis"].setex.call_count > 0

    # ========================================================================
    # Metadata Operations
    # ========================================================================

    @pytest.mark.asyncio
    async def test_get_watermark(self, storage_service, mock_all_clients):
        """Test retrieving collection watermark."""
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "source_id": "mde_logs",
            "last_successful_timestamp": datetime.utcnow(),
            "status": "success",
        }

        mock_collection = MagicMock()
        mock_collection.document.return_value.get.return_value = mock_doc
        mock_all_clients["firestore"].collection.return_value = mock_collection

        watermark = await storage_service.get_watermark("mde_logs")

        assert watermark is not None
        assert watermark["source_id"] == "mde_logs"

    @pytest.mark.asyncio
    async def test_update_watermark(self, storage_service, mock_all_clients):
        """Test updating collection watermark."""
        mock_doc_ref = MagicMock()
        mock_collection = MagicMock()
        mock_collection.document.return_value = mock_doc_ref
        mock_all_clients["firestore"].collection.return_value = mock_collection

        result = await storage_service.update_watermark(
            source_id="mde_logs", timestamp=datetime.utcnow(), status="success"
        )

        assert result is True
        mock_doc_ref.set.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_and_set_config(self, storage_service, mock_all_clients):
        """Test storing and retrieving configuration."""
        # Test set_config
        mock_doc_ref = MagicMock()
        mock_collection = MagicMock()
        mock_collection.document.return_value = mock_doc_ref
        mock_all_clients["firestore"].collection.return_value = mock_collection

        config_value = {"enabled": True, "threshold": 0.8}
        result = await storage_service.set_config("detection_settings", config_value)

        assert result is True

        # Test get_config
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {"enabled": True, "threshold": 0.8}
        mock_collection.document.return_value.get.return_value = mock_doc

        config = await storage_service.get_config("detection_settings")

        assert config is not None
        assert config["enabled"] is True

    # ========================================================================
    # Health Checks
    # ========================================================================

    @pytest.mark.asyncio
    async def test_health_check_all_healthy(self, storage_service, mock_all_clients):
        """Test health check when all backends are healthy."""
        # Mock healthy responses
        query_job = MagicMock()
        query_job.result.return_value = []
        mock_all_clients["bigquery"].query.return_value = query_job

        mock_all_clients["redis"].info.return_value = {"keyspace_hits": 100}
        mock_all_clients["redis"].scan.return_value = (0, [])

        mock_doc = MagicMock()
        mock_doc.exists = False
        mock_collection = MagicMock()
        mock_collection.document.return_value.get.return_value = mock_doc
        mock_all_clients["firestore"].collection.return_value = mock_collection

        health = await storage_service.health_check()

        assert health["bigquery"] is True
        assert health["redis"] is True
        assert health["firestore"] is True

    @pytest.mark.asyncio
    async def test_health_check_bigquery_unhealthy(
        self, storage_service, mock_all_clients
    ):
        """Test health check when BigQuery is unhealthy."""
        # Mock BigQuery error
        mock_all_clients["bigquery"].query.side_effect = Exception("Connection error")

        mock_all_clients["redis"].info.return_value = {"keyspace_hits": 100}
        mock_all_clients["redis"].scan.return_value = (0, [])

        mock_doc = MagicMock()
        mock_doc.exists = False
        mock_collection = MagicMock()
        mock_collection.document.return_value.get.return_value = mock_doc
        mock_all_clients["firestore"].collection.return_value = mock_collection

        health = await storage_service.health_check()

        assert health["bigquery"] is False
        assert health["redis"] is True
        assert health["firestore"] is True

    # ========================================================================
    # Cleanup
    # ========================================================================

    @pytest.mark.asyncio
    async def test_cleanup(self, storage_service, mock_all_clients):
        """Test service cleanup."""
        await storage_service.cleanup()

        # Verify Redis disconnect was called
        mock_all_clients["redis"].close.assert_called_once()
