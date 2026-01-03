"""Tests for Storage Service HTTP client."""

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from aioresponses import aioresponses

# Add src directory to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from clients.storage_client import CircuitBreaker, MockStorageClient, StorageServiceClient


class TestCircuitBreaker:
    """Tests for Circuit Breaker pattern."""

    @pytest.mark.asyncio
    async def test_circuit_breaker_closed_state(self):
        """Test circuit breaker in closed state allows calls."""
        breaker = CircuitBreaker(failure_threshold=3, timeout_seconds=60)

        assert breaker.state == "closed"

        # Successful call should work
        async def success_func():
            return "success"

        result = await breaker.call(success_func)
        assert result == "success"
        assert breaker.state == "closed"
        assert breaker.failure_count == 0

    @pytest.mark.asyncio
    async def test_circuit_breaker_opens_after_threshold(self):
        """Test circuit breaker opens after failure threshold."""
        breaker = CircuitBreaker(failure_threshold=3, timeout_seconds=60)

        # Cause 3 failures
        async def fail_func():
            raise Exception("fail")

        for i in range(3):
            try:
                await breaker.call(fail_func)
            except Exception:
                pass

        assert breaker.state == "open"
        assert breaker.failure_count == 3

        # Next call should raise RuntimeError (circuit open)
        async def should_fail():
            return "should fail"

        with pytest.raises(RuntimeError, match="Circuit breaker is OPEN"):
            await breaker.call(should_fail)

    @pytest.mark.asyncio
    async def test_circuit_breaker_half_open_state(self):
        """Test circuit breaker enters half-open state after timeout."""
        breaker = CircuitBreaker(failure_threshold=2, timeout_seconds=0)

        # Cause failures to open circuit
        async def fail_func():
            raise Exception("fail")

        for i in range(2):
            try:
                await breaker.call(fail_func)
            except Exception:
                pass

        assert breaker.state == "open"

        # Wait for timeout (0 seconds - immediate)
        import time
        time.sleep(0.1)

        # Next call should enter half-open state
        async def success_func():
            return "success"

        result = await breaker.call(success_func)
        assert result == "success"
        assert breaker.state == "closed"  # Success closes circuit
        assert breaker.failure_count == 0


class TestStorageServiceClient:
    """Tests for Storage Service HTTP client."""

    @pytest.fixture
    def storage_client(self):
        """Create storage client for testing."""
        return StorageServiceClient(
            base_url="http://test-storage:8000",
            timeout=10,
            verify_ssl=False,
            environment="development",
        )

    @pytest.fixture
    def production_client(self):
        """Create production storage client for testing."""
        return StorageServiceClient(
            base_url="http://test-storage:8000",
            timeout=10,
            verify_ssl=True,
            environment="production",
        )

    @pytest.mark.asyncio
    async def test_get_watermark_success(self, storage_client):
        """Test successfully retrieving a watermark."""
        with aioresponses() as mocked:
            watermark_data = {
                "source_id": "test_source",
                "last_successful_timestamp": "2024-01-01T12:00:00+00:00",
                "status": "success",
            }

            mocked.get(
                "http://test-storage:8000/api/v1/watermarks/test_source",
                payload=watermark_data,
                status=200,
            )

            watermark = await storage_client.get_watermark("test_source")

            assert watermark is not None
            assert watermark["source_id"] == "test_source"
            assert watermark["status"] == "success"

        await storage_client.close()

    @pytest.mark.asyncio
    async def test_get_watermark_not_found(self, storage_client):
        """Test retrieving non-existent watermark returns None."""
        with aioresponses() as mocked:
            mocked.get(
                "http://test-storage:8000/api/v1/watermarks/nonexistent",
                status=404,
            )

            watermark = await storage_client.get_watermark("nonexistent")

            assert watermark is None

        await storage_client.close()

    @pytest.mark.asyncio
    async def test_get_watermark_http_error(self, storage_client):
        """Test handling of HTTP errors when retrieving watermark."""
        with aioresponses() as mocked:
            mocked.get(
                "http://test-storage:8000/api/v1/watermarks/test_source",
                status=500,
            )

            watermark = await storage_client.get_watermark("test_source")

            assert watermark is None

        await storage_client.close()

    @pytest.mark.asyncio
    async def test_update_watermark_success(self, storage_client):
        """Test successfully updating a watermark."""
        with aioresponses() as mocked:
            mocked.put(
                "http://test-storage:8000/api/v1/watermarks/test_source",
                status=200,
            )

            timestamp = datetime.now(timezone.utc)
            result = await storage_client.update_watermark(
                source_id="test_source",
                timestamp=timestamp,
                status="success",
            )

            assert result is True

        await storage_client.close()

    @pytest.mark.asyncio
    async def test_update_watermark_with_timezone(self, storage_client):
        """Test updating watermark with naive timestamp adds timezone."""
        with aioresponses() as mocked:
            mocked.put(
                "http://test-storage:8000/api/v1/watermarks/test_source",
                status=200,
            )

            # Naive timestamp (no timezone)
            timestamp = datetime(2024, 1, 1, 12, 0, 0)
            result = await storage_client.update_watermark(
                source_id="test_source",
                timestamp=timestamp,
                status="success",
            )

            # Verify the update succeeded
            # The storage_client automatically adds UTC timezone to naive timestamps
            assert result is True

        await storage_client.close()

    @pytest.mark.asyncio
    async def test_update_watermark_with_error_message(self, storage_client):
        """Test updating watermark with error message."""
        with aioresponses() as mocked:
            mocked.put(
                "http://test-storage:8000/api/v1/watermarks/test_source",
                status=200,
            )

            timestamp = datetime.now(timezone.utc)
            result = await storage_client.update_watermark(
                source_id="test_source",
                timestamp=timestamp,
                status="failed",
                error_message="Connection timeout",
            )

            assert result is True

        await storage_client.close()

    @pytest.mark.asyncio
    async def test_update_watermark_http_error(self, storage_client):
        """Test handling of HTTP errors when updating watermark."""
        with aioresponses() as mocked:
            mocked.put(
                "http://test-storage:8000/api/v1/watermarks/test_source",
                status=500,
            )

            timestamp = datetime.now(timezone.utc)
            result = await storage_client.update_watermark(
                source_id="test_source",
                timestamp=timestamp,
                status="success",
            )

            assert result is False

        await storage_client.close()

    @pytest.mark.asyncio
    async def test_health_check_healthy(self, storage_client):
        """Test health check with healthy service."""
        with aioresponses() as mocked:
            mocked.get("http://test-storage:8000/health", status=200)

            is_healthy = await storage_client.health_check()

            assert is_healthy is True

        await storage_client.close()

    @pytest.mark.asyncio
    async def test_health_check_unhealthy(self, storage_client):
        """Test health check with unhealthy service in development."""
        with aioresponses() as mocked:
            mocked.get("http://test-storage:8000/health", status=503)

            is_healthy = await storage_client.health_check()

            assert is_healthy is False

        await storage_client.close()

    @pytest.mark.asyncio
    async def test_health_check_production_raises_on_unhealthy(
        self, production_client
    ):
        """Test health check raises RuntimeError in production if unhealthy."""
        with aioresponses() as mocked:
            mocked.get("http://test-storage:8000/health", status=503)

            with pytest.raises(RuntimeError, match="health check failed in production"):
                await production_client.health_check()

        await production_client.close()

    @pytest.mark.asyncio
    async def test_circuit_breaker_integration(self, storage_client):
        """Test circuit breaker prevents calls after failures."""
        with aioresponses() as mocked:
            # First 5 requests fail (opens circuit)
            for i in range(5):
                mocked.get(
                    "http://test-storage:8000/api/v1/watermarks/test_source",
                    status=500,
                )

            # Cause 5 failures
            for i in range(5):
                await storage_client.get_watermark("test_source")

            # Circuit should be open now
            assert storage_client.circuit_breaker.state == "open"

            # Next call should fail without making HTTP request
            watermark = await storage_client.get_watermark("test_source")
            assert watermark is None

        await storage_client.close()

    @pytest.mark.asyncio
    async def test_connection_pooling(self, storage_client):
        """Test connection pooling configuration."""
        session = await storage_client._get_session()

        assert session is not None
        assert session.connector.limit == 100
        assert session.connector.limit_per_host == 30

        await storage_client.close()

    def test_invalid_connection_pool_per_host_exceeds_total(self):
        """Test validation when max_connections_per_host > max_connections."""
        with pytest.raises(ValueError, match="max_connections_per_host cannot exceed max_connections"):
            StorageServiceClient(
                base_url="http://test-storage:8000",
                max_connections=10,
                max_connections_per_host=20,
            )

    def test_invalid_connection_pool_zero_connections(self):
        """Test validation when max_connections < 1."""
        with pytest.raises(ValueError, match="max_connections must be positive"):
            StorageServiceClient(
                base_url="http://test-storage:8000",
                max_connections=0,
            )

    def test_ssl_verification_warning(self, caplog):
        """Test warning is logged when SSL verification is disabled."""
        import logging
        with caplog.at_level(logging.WARNING):
            client = StorageServiceClient(
                base_url="http://test-storage:8000",
                verify_ssl=False,
            )
            assert "SSL verification is DISABLED" in caplog.text

    @pytest.mark.asyncio
    async def test_configurable_circuit_breaker(self):
        """Test circuit breaker parameters are configurable."""
        client = StorageServiceClient(
            base_url="http://test-storage:8000",
            circuit_breaker_threshold=3,
            circuit_breaker_timeout=30,
        )

        assert client.circuit_breaker.failure_threshold == 3
        assert client.circuit_breaker.timeout_seconds == 30

        await client.close()


class TestMockStorageClient:
    """Tests for Mock Storage Client."""

    @pytest.mark.asyncio
    async def test_mock_get_watermark_not_found(self):
        """Test mock client returns None for non-existent watermark."""
        client = MockStorageClient()

        watermark = await client.get_watermark("test_source")

        assert watermark is None

        await client.close()

    @pytest.mark.asyncio
    async def test_mock_update_and_get_watermark(self):
        """Test mock client stores and retrieves watermarks."""
        client = MockStorageClient()

        # Update watermark
        timestamp = datetime.now(timezone.utc)
        result = await client.update_watermark(
            source_id="test_source",
            timestamp=timestamp,
            status="success",
        )

        assert result is True

        # Retrieve watermark
        watermark = await client.get_watermark("test_source")

        assert watermark is not None
        assert watermark["source_id"] == "test_source"
        assert watermark["status"] == "success"
        assert watermark["last_successful_timestamp"] == timestamp

        await client.close()

    @pytest.mark.asyncio
    async def test_mock_update_watermark_failed_status(self):
        """Test mock client handles failed status correctly."""
        client = MockStorageClient()

        timestamp = datetime.now(timezone.utc)
        result = await client.update_watermark(
            source_id="test_source",
            timestamp=timestamp,
            status="failed",
            error_message="Test error",
        )

        assert result is True

        watermark = await client.get_watermark("test_source")

        assert watermark["status"] == "failed"
        assert watermark["error_message"] == "Test error"
        # Should NOT have last_successful_timestamp on failure
        assert "last_successful_timestamp" not in watermark

        await client.close()

    @pytest.mark.asyncio
    async def test_mock_health_check_always_healthy(self):
        """Test mock client health check always returns True."""
        client = MockStorageClient()

        is_healthy = await client.health_check()

        assert is_healthy is True

        await client.close()
