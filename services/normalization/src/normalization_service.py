"""Normalization Service - Orchestrates data normalization from Pub/Sub."""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from google.cloud import pubsub_v1

from .config import NormalizationConfig
from .normalizers.activity_normalizers import get_activity_normalizer
from .normalizers.ioc_normalizers import get_ioc_normalizer
from .normalizers.threat_normalizers import get_threat_normalizer
from .subscribers.pubsub_subscriber import (
    MockPubSubSubscriber,
    PubSubSubscriber,
)

logger = logging.getLogger(__name__)


class NormalizationService:
    """Main service for normalizing raw events from Pub/Sub.

    Consumes raw events, transforms them into standardized formats,
    and publishes normalized events for downstream processing.
    """

    def __init__(self, config: NormalizationConfig):
        """Initialize Normalization Service.

        Args:
            config: Normalization service configuration
        """
        self.config = config
        self.publisher = self._create_publisher()
        self.ioc_subscriber = self._create_subscriber("ioc")
        self.activity_subscriber = self._create_subscriber("activity")
        self.threat_subscriber = self._create_subscriber("threat")
        self.running = False
        self.processing_tasks: List[asyncio.Task] = []

    def _create_publisher(self):
        """Create Pub/Sub publisher.

        Returns:
            Publisher client
        """
        if self.config.environment == "development":
            logger.info("Using mock publisher for development")
            return None  # Mock publisher
        else:
            return pubsub_v1.PublisherClient()

    def _create_subscriber(self, event_type: str):
        """Create Pub/Sub subscriber.

        Args:
            event_type: Type of events (ioc, activity, or threat)

        Returns:
            Subscriber instance
        """
        if event_type == "ioc":
            subscription_name = self.config.pubsub.ioc_subscription
        elif event_type == "activity":
            subscription_name = self.config.pubsub.activity_subscription
        elif event_type == "threat":
            subscription_name = self.config.pubsub.threat_subscription
        else:
            raise ValueError(f"Unknown event type: {event_type}")

        if self.config.environment == "development":
            logger.info(f"Using mock subscriber for {event_type} events")
            return MockPubSubSubscriber(
                project_id=self.config.pubsub.project_id,
                subscription_name=subscription_name,
                max_messages=self.config.pubsub.max_messages_per_pull,
            )
        else:
            return PubSubSubscriber(
                project_id=self.config.pubsub.project_id,
                subscription_name=subscription_name,
                max_messages=self.config.pubsub.max_messages_per_pull,
                ack_deadline_seconds=self.config.pubsub.ack_deadline_seconds,
            )

    def _get_topic_path(self, topic_name: str) -> str:
        """Get full topic path.

        Args:
            topic_name: Topic name

        Returns:
            Full topic path
        """
        if self.publisher:
            return self.publisher.topic_path(self.config.pubsub.project_id, topic_name)
        else:
            return f"projects/{self.config.pubsub.project_id}/topics/{topic_name}"

    def _publish_normalized(
        self, topic: str, events: List[Any], source: str
    ) -> int:
        """Publish normalized events to output topic.

        Args:
            topic: Topic name
            events: List of normalized events
            source: Source name

        Returns:
            Number of published events
        """
        if not events:
            return 0

        try:
            topic_path = self._get_topic_path(topic)

            # Serialize events
            import json

            for event in events:
                # Convert to dict
                if hasattr(event, "model_dump"):
                    event_dict = event.model_dump(mode="json")
                else:
                    event_dict = event

                data = json.dumps(event_dict).encode("utf-8")

                if self.publisher:
                    future = self.publisher.publish(topic_path, data, source=source)
                    future.result()  # Wait for publish
                else:
                    # Mock mode - just log
                    logger.debug(f"Mock publish to {topic}: {event_dict}")

            logger.info(f"Published {len(events)} events to {topic}")
            return len(events)

        except Exception as e:
            logger.error(f"Failed to publish normalized events: {e}")
            return 0

    def _publish_to_dlq(
        self, topic: str, raw_event: Dict[str, Any], error: str
    ):
        """Publish failed event to dead letter queue.

        Args:
            topic: DLQ topic name
            raw_event: Raw event that failed
            error: Error message
        """
        try:
            topic_path = self._get_topic_path(topic)

            import json

            dlq_event = {
                "raw_event": raw_event,
                "error": error,
                "timestamp": datetime.utcnow().isoformat(),
            }

            data = json.dumps(dlq_event).encode("utf-8")

            if self.publisher:
                future = self.publisher.publish(topic_path, data)
                future.result()

            logger.info(f"Published failed event to DLQ: {topic}")

        except Exception as e:
            logger.error(f"Failed to publish to DLQ: {e}")

    def process_ioc_message(self, message: Dict[str, Any]) -> bool:
        """Process a single IOC message.

        Args:
            message: Message dictionary

        Returns:
            True if processing succeeded
        """
        try:
            raw_data = message["data"]
            source = message["attributes"].get("source", "unknown")

            # Get appropriate normalizer
            normalizer = get_ioc_normalizer(
                source, skip_invalid=self.config.skip_invalid_iocs
            )

            # Normalize
            normalized_ioc = normalizer.normalize(raw_data)

            if normalized_ioc:
                # Publish to normalized topic
                self._publish_normalized(
                    topic=self.config.pubsub.normalized_ioc_events_topic,
                    events=[normalized_ioc],
                    source=source,
                )
                return True
            else:
                # Normalization failed
                self._publish_to_dlq(
                    topic=self.config.pubsub.dlq_ioc_events_topic,
                    raw_event=raw_data,
                    error="Normalization returned None",
                )
                return False

        except Exception as e:
            logger.error(f"Error processing IOC message: {e}")
            self._publish_to_dlq(
                topic=self.config.pubsub.dlq_ioc_events_topic,
                raw_event=message.get("data", {}),
                error=str(e),
            )
            return False

    def process_activity_message(self, message: Dict[str, Any]) -> bool:
        """Process a single activity message.

        Args:
            message: Message dictionary

        Returns:
            True if processing succeeded
        """
        try:
            raw_data = message["data"]
            source = message["attributes"].get("source", "unknown")

            # Get appropriate normalizer
            normalizer = get_activity_normalizer(
                source, skip_invalid=self.config.skip_invalid_iocs
            )

            # Normalize
            normalized_activity = normalizer.normalize(raw_data)

            if normalized_activity:
                # Publish to normalized topic
                self._publish_normalized(
                    topic=self.config.pubsub.normalized_activity_events_topic,
                    events=[normalized_activity],
                    source=source,
                )
                return True
            else:
                # Normalization failed
                self._publish_to_dlq(
                    topic=self.config.pubsub.dlq_activity_events_topic,
                    raw_event=raw_data,
                    error="Normalization returned None",
                )
                return False

        except Exception as e:
            logger.error(f"Error processing activity message: {e}")
            self._publish_to_dlq(
                topic=self.config.pubsub.dlq_activity_events_topic,
                raw_event=message.get("data", {}),
                error=str(e),
            )
            return False

    def process_threat_message(self, message: Dict[str, Any]) -> bool:
        """Process a single threat message.

        Args:
            message: Message dictionary

        Returns:
            True if processing succeeded
        """
        try:
            raw_data = message["data"]
            source = message["attributes"].get("source", "unknown")

            # Get appropriate normalizer
            normalizer = get_threat_normalizer(
                source, skip_invalid=self.config.skip_invalid_iocs
            )

            # Normalize
            normalized_threat = normalizer.normalize(raw_data)

            if normalized_threat:
                # Publish to normalized topic
                self._publish_normalized(
                    topic=self.config.pubsub.normalized_threat_events_topic,
                    events=[normalized_threat],
                    source=source,
                )
                return True
            else:
                # Normalization failed
                self._publish_to_dlq(
                    topic=self.config.pubsub.dlq_threat_events_topic,
                    raw_event=raw_data,
                    error="Normalization returned None",
                )
                return False

        except Exception as e:
            logger.error(f"Error processing threat message: {e}")
            self._publish_to_dlq(
                topic=self.config.pubsub.dlq_threat_events_topic,
                raw_event=message.get("data", {}),
                error=str(e),
            )
            return False

    async def process_ioc_batch(self) -> Dict[str, int]:
        """Process a batch of IOC messages.

        Returns:
            Processing statistics
        """
        stats = self.ioc_subscriber.process_messages(
            handler=self.process_ioc_message, auto_ack=True
        )

        logger.info(
            f"Processed IOC batch: {stats['success']} success, {stats['failed']} failed"
        )

        return stats

    async def process_activity_batch(self) -> Dict[str, int]:
        """Process a batch of activity messages.

        Returns:
            Processing statistics
        """
        stats = self.activity_subscriber.process_messages(
            handler=self.process_activity_message, auto_ack=True
        )

        logger.info(
            f"Processed activity batch: {stats['success']} success, {stats['failed']} failed"
        )

        return stats

    async def process_threat_batch(self) -> Dict[str, int]:
        """Process a batch of threat messages.

        Returns:
            Processing statistics
        """
        stats = self.threat_subscriber.process_messages(
            handler=self.process_threat_message, auto_ack=True
        )

        logger.info(
            f"Processed threat batch: {stats['success']} success, {stats['failed']} failed"
        )

        return stats

    async def start(self):
        """Start the normalization service.

        Begins processing messages from Pub/Sub subscriptions.
        """
        logger.info("Starting Normalization Service")
        self.running = True

        # Start processing loops
        ioc_task = asyncio.create_task(self._ioc_processing_loop())
        activity_task = asyncio.create_task(self._activity_processing_loop())
        threat_task = asyncio.create_task(self._threat_processing_loop())

        self.processing_tasks = [ioc_task, activity_task, threat_task]

        logger.info("Normalization Service started")

    async def _ioc_processing_loop(self):
        """Process IOC messages in a loop."""
        logger.info("Starting IOC processing loop")

        while self.running:
            try:
                stats = await self.process_ioc_batch()

                # If no messages, wait before polling again
                if stats["total"] == 0:
                    await asyncio.sleep(5)

            except Exception as e:
                logger.error(f"Error in IOC processing loop: {e}")
                await asyncio.sleep(10)

    async def _activity_processing_loop(self):
        """Process activity messages in a loop."""
        logger.info("Starting activity processing loop")

        while self.running:
            try:
                stats = await self.process_activity_batch()

                # If no messages, wait before polling again
                if stats["total"] == 0:
                    await asyncio.sleep(5)

            except Exception as e:
                logger.error(f"Error in activity processing loop: {e}")
                await asyncio.sleep(10)

    async def _threat_processing_loop(self):
        """Process threat messages in a loop."""
        logger.info("Starting threat processing loop")

        while self.running:
            try:
                stats = await self.process_threat_batch()

                # If no messages, wait before polling again
                if stats["total"] == 0:
                    await asyncio.sleep(5)

            except Exception as e:
                logger.error(f"Error in threat processing loop: {e}")
                await asyncio.sleep(10)

    async def stop(self):
        """Stop the normalization service."""
        logger.info("Stopping Normalization Service")
        self.running = False

        # Cancel processing tasks
        for task in self.processing_tasks:
            task.cancel()

        # Wait for tasks to complete
        await asyncio.gather(*self.processing_tasks, return_exceptions=True)

        # Close subscribers
        self.ioc_subscriber.close()
        self.activity_subscriber.close()
        self.threat_subscriber.close()

        # Close publisher
        if self.publisher:
            self.publisher.close()

        logger.info("Normalization Service stopped")

    async def get_status(self) -> Dict[str, Any]:
        """Get current service status.

        Returns:
            Status dictionary
        """
        return {
            "service": "normalization",
            "running": self.running,
            "processing_tasks": len(self.processing_tasks),
            "config": {
                "environment": self.config.environment,
                "strict_validation": self.config.strict_validation,
                "skip_invalid_iocs": self.config.skip_invalid_iocs,
            },
        }
