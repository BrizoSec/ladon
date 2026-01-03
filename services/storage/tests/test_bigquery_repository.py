"""Tests for BigQuery repository implementations."""

from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from storage_service.repositories.bigquery_repository import (
    BigQueryActivityRepository,
    BigQueryDetectionRepository,
    BigQueryIOCRepository,
)


class TestBigQueryIOCRepository:
    """Tests for BigQuery IOC repository."""

    @pytest.fixture
    def repository(self, bigquery_config, mock_bigquery_client):
        """Create IOC repository with mocked client."""
        with patch("storage_service.repositories.bigquery_repository.bigquery.Client") as mock_client_class:
            mock_client_class.return_value = mock_bigquery_client
            repo = BigQueryIOCRepository(bigquery_config)
            repo.client = mock_bigquery_client
            return repo

    @pytest.mark.asyncio
    async def test_store_ioc_success(self, repository, sample_ioc, mock_bigquery_client):
        """Test successfully storing a single IOC."""
        mock_bigquery_client.insert_rows_json.return_value = []

        result = await repository.store_ioc(sample_ioc)

        assert result is True
        mock_bigquery_client.insert_rows_json.assert_called_once()

        # Verify the row data
        call_args = mock_bigquery_client.insert_rows_json.call_args
        rows = call_args[0][1]
        assert len(rows) == 1
        assert rows[0]["ioc_value"] == sample_ioc.ioc_value
        assert rows[0]["ioc_type"] == sample_ioc.ioc_type.value
        assert rows[0]["confidence"] == sample_ioc.confidence

    @pytest.mark.asyncio
    async def test_store_ioc_failure(self, repository, sample_ioc, mock_bigquery_client):
        """Test handling of BigQuery insert errors."""
        mock_bigquery_client.insert_rows_json.return_value = [
            {"index": 0, "errors": [{"reason": "invalid"}]}
        ]

        result = await repository.store_ioc(sample_ioc)

        assert result is False

    @pytest.mark.asyncio
    async def test_store_iocs_batch(self, repository, sample_iocs, mock_bigquery_client):
        """Test batch IOC storage."""
        mock_bigquery_client.insert_rows_json.return_value = []

        result = await repository.store_iocs_batch(sample_iocs)

        assert result["success"] == 5
        assert result["failed"] == 0
        mock_bigquery_client.insert_rows_json.assert_called_once()

    @pytest.mark.asyncio
    async def test_store_iocs_batch_partial_failure(
        self, repository, sample_iocs, mock_bigquery_client
    ):
        """Test batch insert with some failures."""
        # Simulate 2 errors out of 5 rows
        mock_bigquery_client.insert_rows_json.return_value = [
            {"index": 0, "errors": [{"reason": "invalid"}]},
            {"index": 2, "errors": [{"reason": "invalid"}]},
        ]

        result = await repository.store_iocs_batch(sample_iocs)

        assert result["success"] == 3
        assert result["failed"] == 2

    @pytest.mark.asyncio
    async def test_get_ioc_found(self, repository, sample_ioc, mock_bigquery_client):
        """Test retrieving an existing IOC."""
        # Mock query result
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
        mock_bigquery_client.query.return_value = query_job

        result = await repository.get_ioc(sample_ioc.ioc_value, sample_ioc.ioc_type.value)

        assert result is not None
        assert result.ioc_value == sample_ioc.ioc_value
        assert result.confidence == sample_ioc.confidence

    @pytest.mark.asyncio
    async def test_get_ioc_not_found(self, repository, mock_bigquery_client):
        """Test retrieving a non-existent IOC."""
        query_job = MagicMock()
        query_job.result.return_value = []
        mock_bigquery_client.query.return_value = query_job

        result = await repository.get_ioc("nonexistent.com", "domain")

        assert result is None

    @pytest.mark.asyncio
    async def test_search_iocs_with_filters(self, repository, mock_bigquery_client):
        """Test searching IOCs with multiple filters."""
        query_job = MagicMock()
        query_job.result.return_value = []
        mock_bigquery_client.query.return_value = query_job

        await repository.search_iocs(
            ioc_type="domain",
            threat_type="c2",
            min_confidence=0.8,
            limit=50,
        )

        # Verify query was called with parameters
        mock_bigquery_client.query.assert_called_once()
        call_args = mock_bigquery_client.query.call_args
        query = call_args[0][0]

        assert "ioc_type = @ioc_type" in query
        assert "threat_type = @threat_type" in query
        assert "confidence >= @min_confidence" in query

    @pytest.mark.asyncio
    async def test_delete_ioc(self, repository, sample_ioc, mock_bigquery_client):
        """Test soft-deleting an IOC."""
        query_job = MagicMock()
        query_job.result.return_value = None
        mock_bigquery_client.query.return_value = query_job

        result = await repository.delete_ioc(sample_ioc.ioc_value, sample_ioc.ioc_type.value)

        assert result is True
        mock_bigquery_client.query.assert_called_once()


class TestBigQueryActivityRepository:
    """Tests for BigQuery Activity repository."""

    @pytest.fixture
    def repository(self, bigquery_config, mock_bigquery_client):
        """Create Activity repository with mocked client."""
        with patch("storage_service.repositories.bigquery_repository.bigquery.Client") as mock_client_class:
            mock_client_class.return_value = mock_bigquery_client
            repo = BigQueryActivityRepository(bigquery_config)
            repo.client = mock_bigquery_client
            return repo

    @pytest.mark.asyncio
    async def test_store_activity(self, repository, sample_activity, mock_bigquery_client):
        """Test storing a single activity event."""
        mock_bigquery_client.insert_rows_json.return_value = []

        result = await repository.store_activity(sample_activity)

        assert result is True
        mock_bigquery_client.insert_rows_json.assert_called_once()

    @pytest.mark.asyncio
    async def test_store_activities_batch(self, repository, mock_bigquery_client):
        """Test batch activity storage."""
        from ladon_models import ActivityEventType, ActivitySource, NormalizedActivity

        activities = [
            NormalizedActivity(
                event_id=f"evt_{i}",
                timestamp=datetime.utcnow(),
                source=ActivitySource.DNS,
                event_type=ActivityEventType.DNS_QUERY,
                domain=f"test{i}.com",
            )
            for i in range(3)
        ]

        mock_bigquery_client.insert_rows_json.return_value = []

        result = await repository.store_activities_batch(activities)

        assert result["success"] == 3
        assert result["failed"] == 0

    @pytest.mark.asyncio
    async def test_search_activities_by_source(self, repository, mock_bigquery_client):
        """Test searching activities by source."""
        query_job = MagicMock()
        query_job.result.return_value = []
        mock_bigquery_client.query.return_value = query_job

        await repository.search_activities(source="dns", limit=100)

        mock_bigquery_client.query.assert_called_once()
        call_args = mock_bigquery_client.query.call_args
        query = call_args[0][0]

        assert "source = @source" in query

    @pytest.mark.asyncio
    async def test_search_activities_by_time_range(self, repository, mock_bigquery_client):
        """Test searching activities within time range."""
        query_job = MagicMock()
        query_job.result.return_value = []
        mock_bigquery_client.query.return_value = query_job

        start_time = datetime.utcnow() - timedelta(hours=1)
        end_time = datetime.utcnow()

        await repository.search_activities(
            start_time=start_time, end_time=end_time, limit=100
        )

        call_args = mock_bigquery_client.query.call_args
        query = call_args[0][0]

        assert "timestamp >= @start_time" in query
        assert "timestamp <= @end_time" in query


class TestBigQueryDetectionRepository:
    """Tests for BigQuery Detection repository."""

    @pytest.fixture
    def repository(self, bigquery_config, mock_bigquery_client):
        """Create Detection repository with mocked client."""
        with patch("storage_service.repositories.bigquery_repository.bigquery.Client") as mock_client_class:
            mock_client_class.return_value = mock_bigquery_client
            repo = BigQueryDetectionRepository(bigquery_config)
            repo.client = mock_bigquery_client
            return repo

    @pytest.mark.asyncio
    async def test_store_detection(self, repository, sample_detection, mock_bigquery_client):
        """Test storing a single detection."""
        mock_bigquery_client.insert_rows_json.return_value = []

        result = await repository.store_detection(sample_detection)

        assert result is True
        mock_bigquery_client.insert_rows_json.assert_called_once()

        # Verify detection data
        call_args = mock_bigquery_client.insert_rows_json.call_args
        rows = call_args[0][1]
        assert rows[0]["detection_id"] == sample_detection.detection_id
        assert rows[0]["severity"] == sample_detection.severity.value

    @pytest.mark.asyncio
    async def test_search_detections_by_severity(self, repository, mock_bigquery_client):
        """Test searching detections by severity."""
        query_job = MagicMock()
        query_job.result.return_value = []
        mock_bigquery_client.query.return_value = query_job

        await repository.search_detections(severity="HIGH", limit=50)

        call_args = mock_bigquery_client.query.call_args
        query = call_args[0][0]

        assert "severity = @severity" in query

    @pytest.mark.asyncio
    async def test_update_detection_status(self, repository, mock_bigquery_client):
        """Test updating detection status."""
        query_job = MagicMock()
        query_job.result.return_value = None
        mock_bigquery_client.query.return_value = query_job

        result = await repository.update_detection_status(
            detection_id="det_123", status="Investigating", case_id="INC0012345"
        )

        assert result is True
        call_args = mock_bigquery_client.query.call_args
        query = call_args[0][0]

        assert "UPDATE" in query
        assert "status = @status" in query
        assert "case_id = @case_id" in query

    @pytest.mark.asyncio
    async def test_update_detection_status_without_case_id(
        self, repository, mock_bigquery_client
    ):
        """Test updating detection status without case ID."""
        query_job = MagicMock()
        query_job.result.return_value = None
        mock_bigquery_client.query.return_value = query_job

        result = await repository.update_detection_status(
            detection_id="det_123", status="False Positive"
        )

        assert result is True
        call_args = mock_bigquery_client.query.call_args
        query = call_args[0][0]

        assert "status = @status" in query
        assert "case_id" not in query
