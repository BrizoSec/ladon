"""BigQuery activity log collector."""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from google.cloud import bigquery
from google.cloud.exceptions import GoogleCloudError

from ..config import BigQuerySourceConfig
from .base import BaseCollector, WatermarkManager

logger = logging.getLogger(__name__)


class BigQueryCollector(BaseCollector):
    """Collector for activity logs from BigQuery data sources.

    Collects activity logs from BigQuery using watermark-based incremental queries.
    Optimized for partitioned tables to minimize costs and improve performance.
    """

    def __init__(
        self,
        config: BigQuerySourceConfig,
        watermark_manager: WatermarkManager,
        publisher: Any,
    ):
        """Initialize BigQuery collector.

        Args:
            config: BigQuery configuration
            watermark_manager: Watermark manager instance
            publisher: Pub/Sub publisher instance
        """
        super().__init__(config, watermark_manager, publisher)
        self.client: Optional[bigquery.Client] = None

    def _get_client(self) -> bigquery.Client:
        """Get or create BigQuery client.

        Returns:
            BigQuery client
        """
        if self.client is None:
            self.client = bigquery.Client(project=self.config.project_id)

        return self.client

    async def validate_connection(self) -> bool:
        """Validate connection to BigQuery.

        Returns:
            True if connection is valid
        """
        try:
            client = self._get_client()

            # Test query
            query = "SELECT 1 as test"
            query_job = client.query(query)
            results = query_job.result()

            for row in results:
                if row.test == 1:
                    logger.info("BigQuery connection validated successfully")
                    return True

            logger.error("BigQuery connection validation failed")
            return False

        except Exception as e:
            logger.error(f"BigQuery connection validation error: {e}")
            return False

    async def collect(self) -> Dict[str, Any]:
        """Collect activity logs from BigQuery.

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
                f"Collecting BigQuery activity logs from "
                f"{self.config.project_id}.{self.config.dataset}.{self.config.table} "
                f"since {start_timestamp}"
            )

            # Build and execute query
            query = self._build_incremental_query(start_timestamp)
            events = await self._execute_query(query)

            logger.info(f"Fetched {len(events)} activity events from BigQuery")

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
                datetime.fromisoformat(
                    event[self.config.timestamp_column].replace("Z", "+00:00")
                )
                if isinstance(event[self.config.timestamp_column], str)
                else event[self.config.timestamp_column]
                for event in events
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
            logger.error(f"BigQuery collection error: {e}")
            await self.watermark_manager.update_watermark(
                source_id=self.config.id,
                timestamp=datetime.utcnow(),
                status="failed",
                error_message=str(e),
            )
            raise

        finally:
            self.metrics.end()
            if self.client:
                self.client.close()
                self.client = None

        return self.metrics.to_dict()

    def _build_incremental_query(self, start_timestamp: datetime) -> str:
        """Build incremental query with partition filter and watermark.

        IMPORTANT: Uses partition filter to minimize BigQuery costs.

        Args:
            start_timestamp: Starting timestamp for query

        Returns:
            SQL query string
        """
        table_ref = f"{self.config.project_id}.{self.config.dataset}.{self.config.table}"

        # Build partition filter for cost optimization
        # This ensures we only scan relevant partitions
        partition_filter = f"""
            DATE({self.config.partition_field}) >= DATE('{start_timestamp.date().isoformat()}')
        """

        # Build timestamp filter for exact data selection
        timestamp_filter = f"""
            {self.config.timestamp_column} > TIMESTAMP('{start_timestamp.isoformat()}')
        """

        query = f"""
            SELECT *
            FROM `{table_ref}`
            WHERE {partition_filter}
              AND {timestamp_filter}
            ORDER BY {self.config.timestamp_column}
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
            client = self._get_client()

            logger.debug(f"Executing BigQuery query: {query}")

            # Configure query job
            job_config = bigquery.QueryJobConfig(
                use_query_cache=False,  # Always fetch fresh data
                use_legacy_sql=False,
            )

            # Execute query
            query_job = client.query(query, job_config=job_config)
            results = query_job.result()

            # Log query statistics
            logger.info(
                f"BigQuery query processed {results.total_rows} rows, "
                f"scanned {query_job.total_bytes_processed / (1024**3):.2f} GB"
            )

            # Convert rows to dictionaries
            events = []
            for row in results:
                event = {}
                for key, value in row.items():
                    # Convert datetime objects to ISO format strings
                    if isinstance(value, datetime):
                        value = value.isoformat()
                    event[key] = value
                events.append(event)

            return events

        except GoogleCloudError as e:
            logger.error(f"BigQuery error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error executing BigQuery query: {e}")
            raise

    def estimate_query_cost(self, start_timestamp: datetime) -> Dict[str, Any]:
        """Estimate the cost of running a collection query.

        Args:
            start_timestamp: Starting timestamp for query

        Returns:
            Dictionary with cost estimate information
        """
        try:
            client = self._get_client()
            query = self._build_incremental_query(start_timestamp)

            # Dry run to get bytes processed
            job_config = bigquery.QueryJobConfig(dry_run=True, use_legacy_sql=False)
            query_job = client.query(query, job_config=job_config)

            bytes_processed = query_job.total_bytes_processed
            gb_processed = bytes_processed / (1024**3)

            # BigQuery pricing: $5 per TB scanned (as of 2024)
            cost_per_tb = 5.0
            estimated_cost = (gb_processed / 1024) * cost_per_tb

            return {
                "bytes_processed": bytes_processed,
                "gb_processed": round(gb_processed, 2),
                "estimated_cost_usd": round(estimated_cost, 4),
            }

        except Exception as e:
            logger.error(f"Failed to estimate query cost: {e}")
            return {"error": str(e)}
