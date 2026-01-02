"""Tests for Firestore metadata repository."""

from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from storage_service.repositories.firestore_repository import FirestoreMetadataRepository


class TestFirestoreMetadataRepository:
    """Tests for Firestore metadata repository."""

    @pytest.fixture
    def repository(self, firestore_config, mock_firestore_client):
        """Create Firestore repository with mocked client."""
        with patch("storage_service.repositories.firestore_repository.firestore.Client") as mock_client_class:
            mock_client_class.return_value = mock_firestore_client
            repo = FirestoreMetadataRepository(firestore_config)
            repo.client = mock_firestore_client
            return repo

    @pytest.mark.asyncio
    async def test_get_watermark_exists(self, repository, mock_firestore_client):
        """Test retrieving an existing watermark."""
        # Mock document that exists
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "source_id": "mde_logs",
            "last_successful_timestamp": datetime.utcnow(),
            "status": "success",
        }

        mock_collection = MagicMock()
        mock_collection.document.return_value.get.return_value = mock_doc
        mock_firestore_client.collection.return_value = mock_collection

        watermark = await repository.get_watermark("mde_logs")

        assert watermark is not None
        assert watermark["source_id"] == "mde_logs"
        assert watermark["status"] == "success"

    @pytest.mark.asyncio
    async def test_get_watermark_not_exists(self, repository, mock_firestore_client):
        """Test retrieving a non-existent watermark."""
        # Mock document that doesn't exist
        mock_doc = MagicMock()
        mock_doc.exists = False

        mock_collection = MagicMock()
        mock_collection.document.return_value.get.return_value = mock_doc
        mock_firestore_client.collection.return_value = mock_collection

        watermark = await repository.get_watermark("nonexistent_source")

        assert watermark is None

    @pytest.mark.asyncio
    async def test_update_watermark_success(self, repository, mock_firestore_client):
        """Test updating watermark with success status."""
        mock_doc_ref = MagicMock()
        mock_collection = MagicMock()
        mock_collection.document.return_value = mock_doc_ref
        mock_firestore_client.collection.return_value = mock_collection

        timestamp = datetime.utcnow()
        result = await repository.update_watermark(
            source_id="mde_logs", timestamp=timestamp, status="success"
        )

        assert result is True
        mock_doc_ref.set.assert_called_once()

        # Verify the data being set
        call_args = mock_doc_ref.set.call_args
        data = call_args[0][0]
        assert data["source_id"] == "mde_logs"
        assert data["status"] == "success"
        assert "last_successful_timestamp" in data
        assert data["error_message"] is None

    @pytest.mark.asyncio
    async def test_update_watermark_failed(self, repository, mock_firestore_client):
        """Test updating watermark with failed status."""
        mock_doc_ref = MagicMock()
        mock_collection = MagicMock()
        mock_collection.document.return_value = mock_doc_ref
        mock_firestore_client.collection.return_value = mock_collection

        timestamp = datetime.utcnow()
        result = await repository.update_watermark(
            source_id="mde_logs",
            timestamp=timestamp,
            status="failed",
            error_message="Connection timeout",
        )

        assert result is True

        call_args = mock_doc_ref.set.call_args
        data = call_args[0][0]
        assert data["status"] == "failed"
        assert data["error_message"] == "Connection timeout"
        assert "last_successful_timestamp" not in data

    @pytest.mark.asyncio
    async def test_get_config_exists(self, repository, mock_firestore_client):
        """Test retrieving existing configuration."""
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "key": "notification_rules",
            "critical": {"slack": True, "email": True},
            "high": {"slack": False, "email": True},
        }

        mock_collection = MagicMock()
        mock_collection.document.return_value.get.return_value = mock_doc
        mock_firestore_client.collection.return_value = mock_collection

        config = await repository.get_config("notification_rules")

        assert config is not None
        assert config["key"] == "notification_rules"
        assert config["critical"]["slack"] is True

    @pytest.mark.asyncio
    async def test_get_config_not_exists(self, repository, mock_firestore_client):
        """Test retrieving non-existent configuration."""
        mock_doc = MagicMock()
        mock_doc.exists = False

        mock_collection = MagicMock()
        mock_collection.document.return_value.get.return_value = mock_doc
        mock_firestore_client.collection.return_value = mock_collection

        config = await repository.get_config("nonexistent_key")

        assert config is None

    @pytest.mark.asyncio
    async def test_set_config(self, repository, mock_firestore_client):
        """Test storing configuration."""
        mock_doc_ref = MagicMock()
        mock_collection = MagicMock()
        mock_collection.document.return_value = mock_doc_ref
        mock_firestore_client.collection.return_value = mock_collection

        config_value = {"enabled": True, "threshold": 0.8}
        result = await repository.set_config("detection_settings", config_value)

        assert result is True
        mock_doc_ref.set.assert_called_once()

        call_args = mock_doc_ref.set.call_args
        data = call_args[0][0]
        assert data["key"] == "detection_settings"
        assert data["enabled"] is True
        assert "updated_at" in data

    @pytest.mark.asyncio
    async def test_delete_config(self, repository, mock_firestore_client):
        """Test deleting configuration."""
        mock_doc_ref = MagicMock()
        mock_collection = MagicMock()
        mock_collection.document.return_value = mock_doc_ref
        mock_firestore_client.collection.return_value = mock_collection

        result = await repository.delete_config("old_config")

        assert result is True
        mock_doc_ref.delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_configs(self, repository, mock_firestore_client):
        """Test listing all configurations."""
        # Mock multiple documents
        mock_docs = []
        for i in range(3):
            mock_doc = MagicMock()
            mock_doc.id = f"config_{i}"
            mock_doc.to_dict.return_value = {"key": f"config_{i}", "value": i}
            mock_docs.append(mock_doc)

        mock_collection = MagicMock()
        mock_collection.stream.return_value = mock_docs
        mock_firestore_client.collection.return_value = mock_collection

        configs = await repository.list_configs()

        assert len(configs) == 3
        assert "config_0" in configs
        assert configs["config_1"]["value"] == 1

    @pytest.mark.asyncio
    async def test_store_metadata(self, repository, mock_firestore_client):
        """Test storing arbitrary metadata."""
        mock_doc_ref = MagicMock()
        mock_collection = MagicMock()
        mock_collection.document.return_value = mock_doc_ref
        mock_firestore_client.collection.return_value = mock_collection

        metadata = {"user_id": "analyst1", "session_id": "abc123"}
        result = await repository.store_metadata("sessions", "session_123", metadata)

        assert result is True
        mock_doc_ref.set.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_metadata(self, repository, mock_firestore_client):
        """Test retrieving metadata."""
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {"user_id": "analyst1", "session_id": "abc123"}

        mock_collection = MagicMock()
        mock_collection.document.return_value.get.return_value = mock_doc
        mock_firestore_client.collection.return_value = mock_collection

        metadata = await repository.get_metadata("sessions", "session_123")

        assert metadata is not None
        assert metadata["user_id"] == "analyst1"

    @pytest.mark.asyncio
    async def test_query_watermarks_by_status(self, repository, mock_firestore_client):
        """Test querying watermarks by status."""
        # Mock query results
        mock_docs = []
        for i in range(2):
            mock_doc = MagicMock()
            mock_doc.id = f"source_{i}"
            mock_doc.to_dict.return_value = {"source_id": f"source_{i}", "status": "failed"}
            mock_docs.append(mock_doc)

        mock_query = MagicMock()
        mock_query.stream.return_value = mock_docs

        mock_collection = MagicMock()
        mock_collection.where.return_value = mock_query
        mock_firestore_client.collection.return_value = mock_collection

        watermarks = await repository.query_watermarks_by_status("failed")

        assert len(watermarks) == 2
        assert "source_0" in watermarks
        assert watermarks["source_1"]["status"] == "failed"

    @pytest.mark.asyncio
    async def test_get_stale_watermarks(self, repository, mock_firestore_client):
        """Test finding stale watermarks."""
        # Mock query results
        mock_doc = MagicMock()
        mock_doc.id = "stale_source"
        mock_doc.to_dict.return_value = {
            "source_id": "stale_source",
            "last_run_timestamp": datetime.utcnow() - timedelta(hours=48),
        }

        mock_query = MagicMock()
        mock_query.stream.return_value = [mock_doc]

        mock_collection = MagicMock()
        mock_collection.where.return_value = mock_query
        mock_firestore_client.collection.return_value = mock_collection

        stale_watermarks = await repository.get_stale_watermarks(hours=24)

        assert len(stale_watermarks) == 1
        assert "stale_source" in stale_watermarks
