"""Trino activity log collector."""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from trino.dbapi import connect
from trino.exceptions import TrinoExternalError, TrinoQueryError

from ..config import TrinoConfig
from .base import BaseCollector, WatermarkManager

logger = logging.getLogger(__name__)


class TrinoCollector(BaseCollector):
    """Collector for activity logs from Trino data sources.

    Collects activity logs from Trino using watermark-based incremental queries.
    Supports high-volume log sources like:
    - Proxy logs
    - DNS logs
    - Network traffic logs
    """

    def __init__(
        self,
        config: TrinoConfig,
        watermark_manager: WatermarkManager,
        publisher: Any,
    ):
        """Initialize Trino collector.

        Args:
            config: Trino configuration
            watermark_manager: Watermark manager instance
            publisher: Pub/Sub publisher instance
        """
        super().__init__(config, watermark_manager, publisher)
        self.connection: Optional[Any] = None

    def _get_connection(self):
        """Get or create Trino connection.

        Returns:
            Trino connection
        """
        if self.connection is None:
            self.connection = connect(
                host=self.config.host,
                port=self.config.port,
                user=self.config.user,
                catalog=self.config.catalog,
                schema=self.config.schema,
                http_scheme="https",
                request_timeout=self.config.timeout_seconds,
            )

        return self.connection

    async def validate_connection(self) -> bool:
        """Validate connection to Trino.

        Returns:
            True if connection is valid
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            # Test query
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            cursor.close()

            if result and result[0] == 1:
                logger.info("Trino connection validated successfully")
                return True
            else:
                logger.error("Trino connection validation failed")
                return False

        except Exception as e:
            logger.error(f"Trino connection validation error: {e}")
            return False

    async def collect(self) -> Dict[str, Any]:
        """Collect activity logs from Trino.

        Returns:
            Collection metrics dictionary
        """
        self.metrics.start()

        try:
            # Get watermark to determine starting point
            watermark = await self.watermark_manager.get_watermark(self.config.id)

            # Get starting timestamp
            start_timestamp = self.watermark_manager.get_starting_timestamp(
                self.config.id, default_lookback_hours=24
            )

            logger.info(
                f"Collecting Trino activity logs from {self.config.table} "
                f"since {start_timestamp}"
            )

            # Build and execute query
            query = self._build_incremental_query(start_timestamp)
            events = await self._execute_query(query)

            logger.info(f"Fetched {len(events)} activity events from Trino")

            if not events:
                await self.watermark_manager.update_watermark(
                    source_id=self.config.id,
                    timestamp=datetime.utcnow(),
                    status="success",
                    records_collected=0,
                )
                self.metrics.end()
                return self.metrics.to_dict()

            # Determine latest timestamp for watermark
            latest_timestamp = max(
                event[self.config.timestamp_column] for event in events
            )

            # Publish events in batches
            batches = self._batch_events(events, self.config.batch_size)

            for batch in batches:
                success = await self._publish_batch(batch, self.config.pubsub_topic)
                if not success:
                    logger.error(f"Failed to publish batch of {len(batch)} events")

            # Update watermark on success
            await self.watermark_manager.update_watermark(
                source_id=self.config.id,
                timestamp=latest_timestamp,
                status="success",
                records_collected=len(events),
            )

        except Exception as e:
            logger.error(f"Trino collection error: {e}")
            await self.watermark_manager.update_watermark(
                source_id=self.config.id,
                timestamp=datetime.utcnow(),
                status="failed",
                error_message=str(e),
            )
            raise

        finally:
            self.metrics.end()
            if self.connection:
                self.connection.close()
                self.connection = None

        return self.metrics.to_dict()

    def _build_incremental_query(self, start_timestamp: datetime) -> str:
        """Build incremental query with watermark filter.

        Args:
            start_timestamp: Starting timestamp for query

        Returns:
            SQL query string
        """
        # Use parameterized query to prevent SQL injection
        query = f"""
            SELECT *
            FROM {self.config.catalog}.{self.config.schema}.{self.config.table}
            WHERE {self.config.timestamp_column} > TIMESTAMP '{start_timestamp.isoformat()}'
            ORDER BY {self.config.order_by_column}
            LIMIT {self.config.batch_size}
        """

        return query

    async def _execute_query(self, query: str) -> List[Dict[str, Any]]:
        """Execute query and return results.

        Args:
            query: SQL query string

        Returns:
            List of row dictionaries
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            logger.debug(f"Executing Trino query: {query}")
            cursor.execute(query)

            # Fetch column names
            columns = [desc[0] for desc in cursor.description]

            # Fetch all rows and convert to dictionaries
            rows = cursor.fetchall()
            events = []

            for row in rows:
                event = {}
                for i, column in enumerate(columns):
                    value = row[i]
                    # Convert datetime objects to ISO format strings
                    if isinstance(value, datetime):
                        value = value.isoformat()
                    event[column] = value
                events.append(event)

            cursor.close()
            return events

        except TrinoQueryError as e:
            logger.error(f"Trino query error: {e}")
            raise
        except TrinoExternalError as e:
            logger.error(f"Trino external error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error executing Trino query: {e}")
            raise
