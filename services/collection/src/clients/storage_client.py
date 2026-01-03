"""Storage Service HTTP client for watermark management."""

import logging
from datetime import datetime
from typing import Any, Dict, Optional

import aiohttp

logger = logging.getLogger(__name__)


class StorageServiceClient:
    """HTTP client for Storage Service.

    Used by Collection Service to manage watermarks for incremental collection.
    """

    def __init__(self, base_url: str, timeout: int = 30):
        """Initialize storage client.

        Args:
            base_url: Storage Service URL (e.g., "http://storage-service:8000")
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session.

        Returns:
            aiohttp ClientSession
        """
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(timeout=self.timeout)
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
        try:
            session = await self._get_session()
            url = f"{self.base_url}/api/v1/watermarks/{source_id}"

            async with session.get(url) as response:
                if response.status == 200:
                    watermark = await response.json()
                    logger.debug(f"Retrieved watermark for {source_id}")
                    return watermark
                elif response.status == 404:
                    logger.debug(f"No watermark found for {source_id}")
                    return None
                else:
                    logger.error(
                        f"Failed to get watermark: {response.status}"
                    )
                    return None

        except aiohttp.ClientError as e:
            logger.error(f"Storage service request failed: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting watermark: {e}")
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
            timestamp: Latest timestamp collected
            status: Collection status (success, failed, running)
            error_message: Error message if status is failed

        Returns:
            True if update succeeded
        """
        try:
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
                    logger.error(
                        f"Failed to update watermark: {response.status}"
                    )
                    return False

        except aiohttp.ClientError as e:
            logger.error(f"Storage service request failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error updating watermark: {e}")
            return False

    async def health_check(self) -> bool:
        """Check if Storage Service is healthy.

        Returns:
            True if service is healthy
        """
        try:
            session = await self._get_session()
            url = f"{self.base_url}/health"

            async with session.get(url) as response:
                return response.status == 200

        except Exception as e:
            logger.error(f"Storage service health check failed: {e}")
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
            "last_run_timestamp": datetime.utcnow(),
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
