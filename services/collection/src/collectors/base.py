"""Base collector interface and watermark management for Collection Service."""

import asyncio
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from ladon_models import NormalizedActivity, NormalizedIOC


class WatermarkManager:
    """Manages collection watermarks for incremental data ingestion.

    Watermarks track the last successfully collected timestamp for each data source,
    enabling incremental collection and preventing duplicate data ingestion.
    """

    def __init__(self, storage_client=None):
        """Initialize watermark manager.

        Args:
            storage_client: Storage service client for persisting watermarks
        """
        self.storage_client = storage_client
        self._watermarks: Dict[str, Dict[str, Any]] = {}

    async def get_watermark(self, source_id: str) -> Optional[Dict[str, Any]]:
        """Get the last watermark for a data source.

        Args:
            source_id: Unique identifier for the data source

        Returns:
            Watermark dictionary with:
                - source_id: str
                - last_successful_timestamp: datetime
                - last_run_timestamp: datetime
                - status: str (success, failed, running)
                - records_collected: int
                - error_message: Optional[str]
            None if no watermark exists
        """
        # Check in-memory cache first
        if source_id in self._watermarks:
            return self._watermarks[source_id]

        # Fetch from storage if available
        if self.storage_client:
            watermark = await self.storage_client.get_watermark(source_id)
            if watermark:
                self._watermarks[source_id] = watermark
                return watermark

        return None

    async def update_watermark(
        self,
        source_id: str,
        timestamp: datetime,
        status: str = "success",
        records_collected: int = 0,
        error_message: Optional[str] = None,
    ) -> bool:
        """Update watermark after collection run.

        Args:
            source_id: Unique identifier for the data source
            timestamp: Latest timestamp collected
            status: Status of collection run (success, failed, running)
            records_collected: Number of records collected in this run
            error_message: Error message if status is failed

        Returns:
            True if update succeeded
        """
        watermark = {
            "source_id": source_id,
            "last_run_timestamp": datetime.utcnow(),
            "status": status,
            "records_collected": records_collected,
            "error_message": error_message,
        }

        # Only update last_successful_timestamp if status is success
        if status == "success":
            watermark["last_successful_timestamp"] = timestamp

        # Update in-memory cache
        self._watermarks[source_id] = watermark

        # Persist to storage if available
        if self.storage_client:
            return await self.storage_client.update_watermark(
                source_id=source_id,
                timestamp=timestamp,
                status=status,
                error_message=error_message,
            )

        return True

    def get_starting_timestamp(
        self, source_id: str, default_lookback_hours: int = 24
    ) -> datetime:
        """Get the starting timestamp for collection.

        Args:
            source_id: Unique identifier for the data source
            default_lookback_hours: Default lookback period if no watermark exists

        Returns:
            Starting timestamp for collection
        """
        watermark = self._watermarks.get(source_id)

        if watermark and watermark.get("last_successful_timestamp"):
            return watermark["last_successful_timestamp"]

        # Default to looking back N hours
        return datetime.utcnow() - timedelta(hours=default_lookback_hours)


class CollectionMetrics:
    """Tracks collection metrics for observability."""

    def __init__(self):
        self.events_collected = 0
        self.events_failed = 0
        self.batches_processed = 0
        self.collection_errors: List[str] = []
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

    def start(self):
        """Mark collection start."""
        self.start_time = datetime.utcnow()

    def end(self):
        """Mark collection end."""
        self.end_time = datetime.utcnow()

    def add_success(self, count: int):
        """Increment successful event count."""
        self.events_collected += count

    def add_failure(self, count: int, error: Optional[str] = None):
        """Increment failed event count."""
        self.events_failed += count
        if error:
            self.collection_errors.append(error)

    def increment_batch(self):
        """Increment batch counter."""
        self.batches_processed += 1

    def get_duration_seconds(self) -> Optional[float]:
        """Get collection duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            "events_collected": self.events_collected,
            "events_failed": self.events_failed,
            "batches_processed": self.batches_processed,
            "collection_errors": self.collection_errors,
            "duration_seconds": self.get_duration_seconds(),
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
        }


class BaseCollector(ABC):
    """Abstract base class for all data collectors.

    Collectors are responsible for:
    1. Connecting to external data sources (threat feeds, activity logs)
    2. Incrementally collecting new data using watermarks
    3. Publishing raw events to Pub/Sub for normalization
    4. Handling retries and errors
    5. Tracking collection metrics
    """

    def __init__(
        self,
        config: Any,
        watermark_manager: WatermarkManager,
        publisher: Any,
    ):
        """Initialize collector.

        Args:
            config: Data source configuration
            watermark_manager: Watermark manager instance
            publisher: Pub/Sub publisher instance
        """
        self.config = config
        self.watermark_manager = watermark_manager
        self.publisher = publisher
        self.metrics = CollectionMetrics()

    @abstractmethod
    async def collect(self) -> Dict[str, Any]:
        """Collect data from source and publish to Pub/Sub.

        This method should:
        1. Get watermark to determine starting point
        2. Fetch data from source
        3. Publish raw events in batches
        4. Update watermark on success
        5. Handle errors and retries

        Returns:
            Collection metrics dictionary
        """
        pass

    @abstractmethod
    async def validate_connection(self) -> bool:
        """Validate connection to data source.

        Returns:
            True if connection is valid
        """
        pass

    async def _retry_with_backoff(
        self,
        func,
        max_retries: int = 3,
        base_delay: int = 5,
        backoff_multiplier: float = 2.0,
    ):
        """Retry a function with exponential backoff.

        Args:
            func: Async function to retry
            max_retries: Maximum retry attempts
            base_delay: Initial delay in seconds
            backoff_multiplier: Backoff multiplier for each retry

        Returns:
            Result of function call

        Raises:
            Last exception if all retries fail
        """
        delay = base_delay
        last_exception = None

        for attempt in range(max_retries):
            try:
                return await func()
            except Exception as e:
                last_exception = e
                self.metrics.add_failure(1, str(e))

                if attempt < max_retries - 1:
                    await asyncio.sleep(delay)
                    delay *= backoff_multiplier

        raise last_exception

    async def _publish_batch(
        self, events: List[Dict[str, Any]], topic: str
    ) -> bool:
        """Publish a batch of events to Pub/Sub.

        Args:
            events: List of event dictionaries
            topic: Pub/Sub topic name

        Returns:
            True if publish succeeded
        """
        try:
            await self.publisher.publish_batch(topic, events)
            self.metrics.add_success(len(events))
            self.metrics.increment_batch()
            return True
        except Exception as e:
            self.metrics.add_failure(len(events), str(e))
            return False

    def _batch_events(
        self, events: List[Any], batch_size: int
    ) -> List[List[Any]]:
        """Split events into batches.

        Args:
            events: List of events
            batch_size: Maximum events per batch

        Returns:
            List of event batches
        """
        batches = []
        for i in range(0, len(events), batch_size):
            batches.append(events[i : i + batch_size])
        return batches
