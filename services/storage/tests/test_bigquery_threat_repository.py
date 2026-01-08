"""Tests for BigQuery Threat repository implementation."""

import sys
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add src directory to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from repositories.bigquery_repository import BigQueryThreatRepository


class TestBigQueryThreatRepository:
    """Tests for BigQuery Threat repository."""

    @pytest.fixture
    def repository(self, bigquery_config, mock_bigquery_client):
        """Create Threat repository with mocked client."""
        with patch(
            "repositories.bigquery_repository.bigquery.Client"
        ) as mock_client_class:
            mock_client_class.return_value = mock_bigquery_client
            repo = BigQueryThreatRepository(bigquery_config)
            repo.client = mock_bigquery_client
            return repo

    @pytest.mark.asyncio
    async def test_store_threat_success(
        self, repository, sample_threat, mock_bigquery_client
    ):
        """Test successfully storing a single threat."""
        mock_bigquery_client.insert_rows_json.return_value = []

        result = await repository.store_threat(sample_threat)

        assert result is True
        mock_bigquery_client.insert_rows_json.assert_called_once()

        # Verify the row data
        call_args = mock_bigquery_client.insert_rows_json.call_args
        rows = call_args[0][1]
        assert len(rows) == 1
        assert rows[0]["threat_id"] == sample_threat.threat_id
        assert rows[0]["name"] == sample_threat.name
        assert rows[0]["threat_category"] == sample_threat.threat_category
        assert rows[0]["confidence"] == sample_threat.confidence

    @pytest.mark.asyncio
    async def test_store_threat_failure(
        self, repository, sample_threat, mock_bigquery_client
    ):
        """Test handling of BigQuery insert errors."""
        mock_bigquery_client.insert_rows_json.return_value = [
            {"index": 0, "errors": [{"reason": "invalid"}]}
        ]

        result = await repository.store_threat(sample_threat)

        assert result is False

    @pytest.mark.asyncio
    async def test_store_threats_batch(
        self, repository, sample_threats, mock_bigquery_client
    ):
        """Test batch threat storage."""
        mock_bigquery_client.insert_rows_json.return_value = []

        result = await repository.store_threats_batch(sample_threats)

        assert result["success"] == 2
        assert result["failed"] == 0
        mock_bigquery_client.insert_rows_json.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_threats_for_ioc(
        self, repository, sample_threat, mock_bigquery_client
    ):
        """Test retrieving threats associated with an IOC."""
        # Mock query result
        mock_row = MagicMock()
        mock_row.__iter__ = lambda self: iter(
            [
                ("threat_id", sample_threat.threat_id),
                ("name", sample_threat.name),
                ("aliases", sample_threat.aliases),
                ("threat_category", sample_threat.threat_category),
                ("threat_type", sample_threat.threat_type.value),
                ("description", sample_threat.description),
                ("severity", sample_threat.severity),
                ("confidence", sample_threat.confidence),
                ("techniques", "[]"),
                ("tactics", sample_threat.tactics),
                ("first_seen", sample_threat.first_seen),
                ("last_seen", sample_threat.last_seen),
                ("sources", sample_threat.sources),
                ("reference_urls", sample_threat.reference_urls),
                ("tags", sample_threat.tags),
                ("is_active", True),
            ]
        )

        query_job = MagicMock()
        query_job.result.return_value = [mock_row]
        mock_bigquery_client.query.return_value = query_job

        threats = await repository.get_threats_for_ioc("evil.com", "domain")

        assert len(threats) == 1
        assert threats[0].threat_id == sample_threat.threat_id
        assert threats[0].name == sample_threat.name
        mock_bigquery_client.query.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_iocs_for_threat(
        self, repository, sample_threat, mock_bigquery_client
    ):
        """Test retrieving IOCs associated with a threat."""
        # Mock query result
        mock_row = MagicMock()
        mock_row.__iter__ = lambda self: iter(
            [
                ("ioc_value", "evil.com"),
                ("ioc_type", "domain"),
                ("relationship_type", "uses"),
                ("confidence", 0.95),
                ("observation_count", 5),
            ]
        )

        query_job = MagicMock()
        query_job.result.return_value = [mock_row]
        mock_bigquery_client.query.return_value = query_job

        iocs = await repository.get_iocs_for_threat(sample_threat.threat_id, limit=100)

        assert len(iocs) == 1
        assert iocs[0]["ioc_value"] == "evil.com"
        assert iocs[0]["ioc_type"] == "domain"
        assert iocs[0]["relationship_type"] == "uses"
        mock_bigquery_client.query.assert_called_once()

    @pytest.mark.asyncio
    async def test_associate_ioc_with_threat_success(
        self, repository, sample_threat_ioc_association, mock_bigquery_client
    ):
        """Test successfully creating threat-IOC association."""
        mock_bigquery_client.insert_rows_json.return_value = []

        result = await repository.associate_ioc_with_threat(
            sample_threat_ioc_association
        )

        assert result is True
        mock_bigquery_client.insert_rows_json.assert_called_once()

        # Verify the row data
        call_args = mock_bigquery_client.insert_rows_json.call_args
        rows = call_args[0][1]
        assert len(rows) == 1
        assert rows[0]["threat_id"] == sample_threat_ioc_association.threat_id
        assert rows[0]["ioc_value"] == sample_threat_ioc_association.ioc_value
        assert rows[0]["ioc_type"] == sample_threat_ioc_association.ioc_type.value
        assert (
            rows[0]["relationship_type"]
            == sample_threat_ioc_association.relationship_type
        )

    @pytest.mark.asyncio
    async def test_associate_ioc_with_threat_failure(
        self, repository, sample_threat_ioc_association, mock_bigquery_client
    ):
        """Test handling of association creation errors."""
        mock_bigquery_client.insert_rows_json.return_value = [
            {"index": 0, "errors": [{"reason": "invalid"}]}
        ]

        result = await repository.associate_ioc_with_threat(
            sample_threat_ioc_association
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_get_threats_for_ioc_no_results(
        self, repository, mock_bigquery_client
    ):
        """Test retrieving threats when none are found."""
        query_job = MagicMock()
        query_job.result.return_value = []
        mock_bigquery_client.query.return_value = query_job

        threats = await repository.get_threats_for_ioc("unknown.com", "domain")

        assert len(threats) == 0

    @pytest.mark.asyncio
    async def test_threat_to_row_conversion(self, repository, sample_threat):
        """Test conversion of Threat model to BigQuery row format."""
        row = repository._threat_to_row(sample_threat)

        assert row["threat_id"] == sample_threat.threat_id
        assert row["name"] == sample_threat.name
        assert row["threat_category"] == sample_threat.threat_category
        assert row["threat_type"] == sample_threat.threat_type.value
        assert row["confidence"] == sample_threat.confidence
        assert row["first_seen"] == sample_threat.first_seen.isoformat()
        assert row["last_seen"] == sample_threat.last_seen.isoformat()
        assert row["is_active"] is True

        # Verify MITRE techniques are serialized as JSON
        import json

        techniques = json.loads(row["techniques"])
        assert isinstance(techniques, list)
        if len(techniques) > 0:
            assert "technique_id" in techniques[0]

    @pytest.mark.asyncio
    async def test_association_to_row_conversion(
        self, repository, sample_threat_ioc_association
    ):
        """Test conversion of ThreatIOCAssociation to BigQuery row format."""
        row = repository._association_to_row(sample_threat_ioc_association)

        assert row["threat_id"] == sample_threat_ioc_association.threat_id
        assert row["ioc_value"] == sample_threat_ioc_association.ioc_value
        assert row["ioc_type"] == sample_threat_ioc_association.ioc_type.value
        assert (
            row["relationship_type"]
            == sample_threat_ioc_association.relationship_type
        )
        assert row["confidence"] == sample_threat_ioc_association.confidence
        assert (
            row["observation_count"] == sample_threat_ioc_association.observation_count
        )
        assert row["sources"] == sample_threat_ioc_association.sources
