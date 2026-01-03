"""Collection Service - Orchestrates data collection from multiple sources."""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from .collectors.abuse_ch import AbuseCHCollector
from .collectors.alienvault_otx import AlienVaultOTXCollector
from .collectors.base import WatermarkManager
from .collectors.bigquery import BigQueryCollector
from .collectors.misp import MISPCollector
from .collectors.trino import TrinoCollector
from .config import (
    AbuseCHConfig,
    AlienVaultOTXConfig,
    BigQuerySourceConfig,
    CollectionConfig,
    CollectorType,
    DataSourceConfig,
    MISPConfig,
    TrinoConfig,
)
from .publishers.pubsub_publisher import MockPubSubPublisher, PubSubPublisher

logger = logging.getLogger(__name__)


class CollectionService:
    """Main service for orchestrating data collection.

    Manages multiple collectors running on scheduled intervals, tracking watermarks,
    and publishing raw events to Pub/Sub for downstream processing.
    """

    def __init__(self, config: CollectionConfig, storage_client=None):
        """Initialize Collection Service.

        Args:
            config: Collection service configuration
            storage_client: Storage service client for watermark persistence
        """
        self.config = config
        self.storage_client = storage_client
        self.watermark_manager = WatermarkManager(storage_client)
        self.publisher = self._create_publisher()
        self.collectors: Dict[str, Any] = {}
        self.collection_tasks: Dict[str, asyncio.Task] = {}

    def _create_publisher(self):
        """Create Pub/Sub publisher based on environment.

        Returns:
            PubSubPublisher instance
        """
        if self.config.environment == "development":
            logger.info("Using MockPubSubPublisher for development")
            return MockPubSubPublisher(
                project_id=self.config.pubsub.project_id,
                max_messages_per_batch=self.config.pubsub.max_messages_per_batch,
            )
        else:
            return PubSubPublisher(
                project_id=self.config.pubsub.project_id,
                max_messages_per_batch=self.config.pubsub.max_messages_per_batch,
            )

    async def initialize(self):
        """Initialize the collection service.

        Creates collectors for all enabled data sources and validates connections.
        """
        logger.info("Initializing Collection Service")

        enabled_sources = self.config.get_enabled_sources()
        logger.info(f"Found {len(enabled_sources)} enabled data sources")

        for source_config in enabled_sources:
            try:
                collector = self._create_collector(source_config)
                self.collectors[source_config.id] = collector

                # Validate connection
                is_valid = await collector.validate_connection()
                if is_valid:
                    logger.info(
                        f"Collector '{source_config.id}' initialized and validated"
                    )
                else:
                    logger.warning(
                        f"Collector '{source_config.id}' validation failed"
                    )

            except Exception as e:
                logger.error(
                    f"Failed to initialize collector '{source_config.id}': {e}"
                )

        logger.info(f"Initialized {len(self.collectors)} collectors")

    def _create_collector(self, source_config: DataSourceConfig):
        """Create a collector based on source configuration.

        Args:
            source_config: Data source configuration

        Returns:
            Collector instance

        Raises:
            ValueError: If collector type is unknown
        """
        collector_map = {
            CollectorType.ALIENVAULT_OTX: AlienVaultOTXCollector,
            CollectorType.ABUSE_CH: AbuseCHCollector,
            CollectorType.MISP: MISPCollector,
            CollectorType.TRINO: TrinoCollector,
            CollectorType.BIGQUERY: BigQueryCollector,
        }

        collector_class = collector_map.get(source_config.collector_type)
        if not collector_class:
            raise ValueError(
                f"Unknown collector type: {source_config.collector_type}"
            )

        return collector_class(
            config=source_config,
            watermark_manager=self.watermark_manager,
            publisher=self.publisher,
        )

    async def start(self):
        """Start all collectors on their scheduled intervals.

        This starts background tasks for each collector that run periodically
        based on their configured collection intervals.
        """
        logger.info("Starting Collection Service")

        for source_id, collector in self.collectors.items():
            # Start collection task
            task = asyncio.create_task(
                self._run_collector_loop(source_id, collector)
            )
            self.collection_tasks[source_id] = task

        logger.info(f"Started {len(self.collection_tasks)} collection tasks")

    async def _run_collector_loop(self, source_id: str, collector):
        """Run collector in a loop at configured intervals.

        Args:
            source_id: Data source ID
            collector: Collector instance
        """
        source_config = self.config.get_source_by_id(source_id)
        interval = source_config.collection_interval_minutes * 60  # Convert to seconds

        logger.info(
            f"Starting collection loop for '{source_id}' "
            f"(interval: {source_config.collection_interval_minutes} minutes)"
        )

        while True:
            try:
                logger.info(f"Running collection for '{source_id}'")
                metrics = await collector.collect()

                logger.info(
                    f"Collection completed for '{source_id}': "
                    f"{metrics['events_collected']} events collected, "
                    f"{metrics['events_failed']} failed, "
                    f"duration: {metrics['duration_seconds']:.2f}s"
                )

            except Exception as e:
                logger.error(f"Collection failed for '{source_id}': {e}")

            # Wait for next collection interval
            await asyncio.sleep(interval)

    async def collect_once(self, source_id: str) -> Dict[str, Any]:
        """Trigger a one-time collection for a specific source.

        Useful for manual triggers and testing.

        Args:
            source_id: Data source ID

        Returns:
            Collection metrics

        Raises:
            KeyError: If source_id is not found
        """
        if source_id not in self.collectors:
            raise KeyError(f"Collector '{source_id}' not found")

        logger.info(f"Triggering one-time collection for '{source_id}'")

        collector = self.collectors[source_id]
        metrics = await collector.collect()

        logger.info(
            f"One-time collection completed for '{source_id}': "
            f"{metrics['events_collected']} events collected"
        )

        return metrics

    async def collect_all_once(self) -> Dict[str, Dict[str, Any]]:
        """Trigger a one-time collection for all enabled sources.

        Returns:
            Dictionary mapping source_id to collection metrics
        """
        logger.info("Triggering one-time collection for all sources")

        results = {}

        # Run all collections concurrently
        tasks = []
        source_ids = []

        for source_id, collector in self.collectors.items():
            tasks.append(collector.collect())
            source_ids.append(source_id)

        # Wait for all to complete
        metrics_list = await asyncio.gather(*tasks, return_exceptions=True)

        # Map results
        for source_id, metrics in zip(source_ids, metrics_list):
            if isinstance(metrics, Exception):
                logger.error(f"Collection failed for '{source_id}': {metrics}")
                results[source_id] = {"error": str(metrics)}
            else:
                results[source_id] = metrics

        logger.info("All collections completed")
        return results

    async def stop(self):
        """Stop all collection tasks."""
        logger.info("Stopping Collection Service")

        for source_id, task in self.collection_tasks.items():
            logger.info(f"Cancelling collection task for '{source_id}'")
            task.cancel()

        # Wait for all tasks to cancel
        await asyncio.gather(*self.collection_tasks.values(), return_exceptions=True)

        self.collection_tasks.clear()
        logger.info("Collection Service stopped")

    async def get_status(self) -> Dict[str, Any]:
        """Get current status of all collectors.

        Returns:
            Status dictionary with collector information
        """
        status = {
            "service": "collection",
            "collectors": {},
            "total_collectors": len(self.collectors),
            "running_tasks": len(self.collection_tasks),
        }

        for source_id in self.collectors.keys():
            watermark = await self.watermark_manager.get_watermark(source_id)
            source_config = self.config.get_source_by_id(source_id)

            status["collectors"][source_id] = {
                "name": source_config.name,
                "collector_type": source_config.collector_type.value,
                "source_type": source_config.source_type.value,
                "enabled": source_config.enabled,
                "interval_minutes": source_config.collection_interval_minutes,
                "watermark": watermark,
                "is_running": source_id in self.collection_tasks,
            }

        return status

    async def health_check(self) -> Dict[str, bool]:
        """Check health of all collectors.

        Returns:
            Dictionary mapping source_id to health status
        """
        health = {}

        for source_id, collector in self.collectors.items():
            try:
                is_healthy = await collector.validate_connection()
                health[source_id] = is_healthy
            except Exception as e:
                logger.error(f"Health check failed for '{source_id}': {e}")
                health[source_id] = False

        return health
