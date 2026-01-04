"""Storage Service HTTP client for watermark management."""

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import aiohttp
from ladon_common import CircuitBreaker

from .storage_metrics import (
    get_circuit_breaker_state_value,
    storage_client_circuit_breaker_state,
    storage_client_latency_seconds,
    storage_client_requests_total,
)

logger = logging.getLogger(__name__)


class StorageServiceClient:
    """HTTP client for Storage Service.

    Used by Collection Service to manage watermarks for incremental collection.
    Implements circuit breaker pattern and connection pooling for reliability.
    """

    def __init__(
        self,
        base_url: str,
        timeout: int = 30,
        verify_ssl: bool = True,
        environment: str = "production",
        max_connections: int = 100,
        max_connections_per_host: int = 30,
        circuit_breaker_threshold: int = 5,
        circuit_breaker_timeout: int = 60,
    ):
        """Initialize storage client.

        Args:
            base_url: Storage Service URL (e.g., "http://storage-service:8000")
            timeout: Request timeout in seconds
            verify_ssl: Verify SSL certificates
            environment: Environment (production, staging, development)
            max_connections: Total connection pool size
            max_connections_per_host: Connections per host
            circuit_breaker_threshold: Number of failures before opening circuit
            circuit_breaker_timeout: Seconds to wait before attempting half-open
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.verify_ssl = verify_ssl
        self.environment = environment
        self.max_connections = max_connections
        self.max_connections_per_host = max_connections_per_host

        # Validate connection pool parameters
        if max_connections < 1:
            raise ValueError("max_connections must be positive")
        if max_connections_per_host > max_connections:
            raise ValueError("max_connections_per_host cannot exceed max_connections")

        # Log warning if SSL verification is disabled
        if not self.verify_ssl:
            logger.warning("SSL verification is DISABLED - only use in development!")

        self.session: Optional[aiohttp.ClientSession] = None
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=circuit_breaker_threshold,
            timeout_seconds=circuit_breaker_timeout,
        )

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session with connection pooling.

        Returns:
            aiohttp ClientSession
        """
        if self.session is None or self.session.closed:
            # Create TCP connector with connection pooling
            connector = aiohttp.TCPConnector(
                limit=self.max_connections,
                limit_per_host=self.max_connections_per_host,
                ssl=self.verify_ssl if self.verify_ssl else False,
                ttl_dns_cache=300,  # Cache DNS for 5 minutes
            )

            self.session = aiohttp.ClientSession(
                timeout=self.timeout,
                connector=connector,
            )
        return self.session

    async def close(self):
        """Close HTTP session."""
        if self.session and not self.session.closed:
            await self.session.close()

    async def get_watermark(self, source_id: str) -> Optional[Dict[str, Any]]:
        """Get watermark for a data source.

        Args:
            source_id: Data source identifier

        Returns:
            Watermark dictionary or None if not found
        """
        start_time = time.time()
        status_code = None
        error_type = ""

        async def _fetch():
            nonlocal status_code
            session = await self._get_session()
            url = f"{self.base_url}/api/v1/watermarks/{source_id}"

            async with session.get(url) as response:
                status_code = response.status
                if response.status == 200:
                    watermark = await response.json()
                    logger.debug(f"Retrieved watermark for {source_id}")
                    return watermark
                elif response.status == 404:
                    logger.debug(f"No watermark found for {source_id}")
                    return None
                else:
                    error_msg = f"Failed to get watermark: {response.status}"
                    logger.error(
                        error_msg,
                        exc_info=True,
                        extra={
                            "source_id": source_id,
                            "error_type": "http_error",
                            "status_code": response.status,
                        },
                    )
                    # Raise exception to trigger circuit breaker
                    raise aiohttp.ClientResponseError(
                        request_info=response.request_info,
                        history=(),
                        status=response.status,
                        message=error_msg,
                    )

        try:
            result = await self.circuit_breaker.call(lambda: _fetch())
            # Record metrics
            storage_client_latency_seconds.labels(method="get_watermark").observe(
                time.time() - start_time
            )
            storage_client_requests_total.labels(
                method="get_watermark",
                status=str(status_code) if status_code else "unknown",
                error_type="",
            ).inc()
            storage_client_circuit_breaker_state.set(
                get_circuit_breaker_state_value(self.circuit_breaker.state)
            )
            return result
        except aiohttp.ClientError as e:
            error_type = "client_error"
            logger.error(
                "Storage service request failed",
                exc_info=True,
                extra={
                    "source_id": source_id,
                    "error_type": error_type,
                    "error": str(e),
                },
            )
            storage_client_requests_total.labels(
                method="get_watermark",
                status=str(status_code) if status_code else "error",
                error_type=error_type,
            ).inc()
            storage_client_circuit_breaker_state.set(
                get_circuit_breaker_state_value(self.circuit_breaker.state)
            )
            return None
        except RuntimeError as e:
            # Circuit breaker open
            error_type = "circuit_breaker_open"
            logger.warning(
                str(e),
                extra={
                    "source_id": source_id,
                    "error_type": error_type,
                },
            )
            storage_client_requests_total.labels(
                method="get_watermark",
                status="circuit_open",
                error_type=error_type,
            ).inc()
            storage_client_circuit_breaker_state.set(
                get_circuit_breaker_state_value(self.circuit_breaker.state)
            )
            return None
        except Exception as e:
            error_type = "unexpected_error"
            logger.error(
                "Unexpected error getting watermark",
                exc_info=True,
                extra={
                    "source_id": source_id,
                    "error_type": error_type,
                },
            )
            storage_client_requests_total.labels(
                method="get_watermark",
                status="error",
                error_type=error_type,
            ).inc()
            storage_client_circuit_breaker_state.set(
                get_circuit_breaker_state_value(self.circuit_breaker.state)
            )
            return None

    async def update_watermark(
        self,
        source_id: str,
        timestamp: datetime,
        status: str = "success",
        error_message: Optional[str] = None,
    ) -> bool:
        """Update watermark after collection run.

        Args:
            source_id: Data source identifier
            timestamp: Latest timestamp collected (must have tzinfo)
            status: Collection status (success, failed, running)
            error_message: Error message if status is failed

        Returns:
            True if update succeeded
        """

        # Ensure timestamp has timezone info
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        async def _update():
            session = await self._get_session()
            url = f"{self.base_url}/api/v1/watermarks/{source_id}"

            payload = {
                "timestamp": timestamp.isoformat(),
                "status": status,
            }

            if error_message:
                payload["error_message"] = error_message

            async with session.put(url, json=payload) as response:
                if response.status in (200, 201):
                    logger.debug(f"Updated watermark for {source_id}")
                    return True
                else:
                    error_msg = f"Failed to update watermark: {response.status}"
                    logger.error(
                        error_msg,
                        exc_info=True,
                        extra={
                            "source_id": source_id,
                            "error_type": "http_error",
                            "status_code": response.status,
                        },
                    )
                    # Raise exception to trigger circuit breaker
                    raise aiohttp.ClientResponseError(
                        request_info=response.request_info,
                        history=(),
                        status=response.status,
                        message=error_msg,
                    )

        try:
            return await self.circuit_breaker.call(lambda: _update())
        except aiohttp.ClientError as e:
            logger.error(
                "Storage service request failed",
                exc_info=True,
                extra={
                    "source_id": source_id,
                    "error_type": "client_error",
                    "error": str(e),
                },
            )
            return False
        except RuntimeError as e:
            # Circuit breaker open
            logger.warning(
                str(e),
                extra={
                    "source_id": source_id,
                    "error_type": "circuit_breaker_open",
                },
            )
            return False
        except Exception as e:
            logger.error(
                "Unexpected error updating watermark",
                exc_info=True,
                extra={
                    "source_id": source_id,
                    "error_type": "unexpected_error",
                },
            )
            return False

    async def health_check(self) -> bool:
        """Check if Storage Service is healthy.

        In production environment, raises RuntimeError if service is not healthy.
        In non-production environments, returns False but allows service to continue.

        Note: Health checks bypass the circuit breaker to allow service startup
        verification. Circuit breaker state should not affect initial health checks,
        as they're used to determine if the service should start at all.

        Returns:
            True if service is healthy

        Raises:
            RuntimeError: If service is unhealthy in production environment
        """
        try:
            session = await self._get_session()
            url = f"{self.base_url}/health"

            async with session.get(url) as response:
                is_healthy = response.status == 200

                if not is_healthy and self.environment == "production":
                    error_msg = (
                        f"Storage Service health check failed in production: "
                        f"status={response.status}"
                    )
                    logger.error(
                        error_msg,
                        exc_info=True,
                        extra={
                            "error_type": "health_check_failed",
                            "status_code": response.status,
                            "environment": self.environment,
                        },
                    )
                    raise RuntimeError(error_msg)

                return is_healthy

        except RuntimeError:
            # Re-raise RuntimeError from production check
            raise
        except Exception as e:
            error_msg = f"Storage service health check failed: {e}"
            logger.error(
                error_msg,
                exc_info=True,
                extra={
                    "error_type": "health_check_exception",
                    "environment": self.environment,
                },
            )

            if self.environment == "production":
                raise RuntimeError(error_msg) from e

            return False


class MockStorageClient:
    """Mock storage client for testing and development."""

    def __init__(self, base_url: str = "http://mock-storage", timeout: int = 30):
        """Initialize mock storage client."""
        self.base_url = base_url
        self.timeout = timeout
        self.watermarks: Dict[str, Dict[str, Any]] = {}

    async def close(self):
        """Close client (no-op for mock)."""
        pass

    async def get_watermark(self, source_id: str) -> Optional[Dict[str, Any]]:
        """Get watermark from in-memory store."""
        watermark = self.watermarks.get(source_id)
        if watermark:
            logger.debug(f"Mock: Retrieved watermark for {source_id}")
        else:
            logger.debug(f"Mock: No watermark found for {source_id}")
        return watermark

    async def update_watermark(
        self,
        source_id: str,
        timestamp: datetime,
        status: str = "success",
        error_message: Optional[str] = None,
    ) -> bool:
        """Update watermark in in-memory store."""
        watermark = {
            "source_id": source_id,
            "last_run_timestamp": datetime.now(timezone.utc),
            "status": status,
            "error_message": error_message,
        }

        if status == "success":
            watermark["last_successful_timestamp"] = timestamp

        self.watermarks[source_id] = watermark
        logger.debug(f"Mock: Updated watermark for {source_id}")
        return True

    async def health_check(self) -> bool:
        """Mock health check always returns True."""
        return True
