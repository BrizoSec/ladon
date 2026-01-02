"""Pub/Sub publisher for raw events."""

import json
import logging
from typing import Any, Dict, List

from google.cloud import pubsub_v1

logger = logging.getLogger(__name__)


class PubSubPublisher:
    """Publisher for Google Cloud Pub/Sub.

    Publishes raw events to Pub/Sub topics for downstream processing
    by normalization and detection services.
    """

    def __init__(self, project_id: str, max_messages_per_batch: int = 1000):
        """Initialize Pub/Sub publisher.

        Args:
            project_id: GCP project ID
            max_messages_per_batch: Maximum messages per batch
        """
        self.project_id = project_id
        self.max_messages_per_batch = max_messages_per_batch
        self.client = pubsub_v1.PublisherClient()

    def get_topic_path(self, topic_name: str) -> str:
        """Get full topic path.

        Args:
            topic_name: Topic name

        Returns:
            Full topic path
        """
        return self.client.topic_path(self.project_id, topic_name)

    async def publish(
        self, topic: str, message: Dict[str, Any], **attributes
    ) -> str:
        """Publish a single message to Pub/Sub.

        Args:
            topic: Topic name
            message: Message data as dictionary
            **attributes: Message attributes

        Returns:
            Message ID

        Raises:
            Exception if publish fails
        """
        topic_path = self.get_topic_path(topic)

        # Serialize message to JSON bytes
        data = json.dumps(message).encode("utf-8")

        # Publish message
        future = self.client.publish(topic_path, data, **attributes)
        message_id = future.result()

        logger.debug(f"Published message {message_id} to {topic}")
        return message_id

    async def publish_batch(
        self,
        topic: str,
        messages: List[Dict[str, Any]],
        **common_attributes,
    ) -> List[str]:
        """Publish a batch of messages to Pub/Sub.

        Args:
            topic: Topic name
            messages: List of message dictionaries
            **common_attributes: Common attributes for all messages

        Returns:
            List of message IDs

        Raises:
            Exception if any publish fails
        """
        if not messages:
            return []

        topic_path = self.get_topic_path(topic)
        message_ids = []

        # Split into smaller batches if needed
        for batch_start in range(0, len(messages), self.max_messages_per_batch):
            batch = messages[batch_start : batch_start + self.max_messages_per_batch]

            futures = []
            for message in batch:
                # Serialize message to JSON bytes
                data = json.dumps(message).encode("utf-8")

                # Publish message
                future = self.client.publish(topic_path, data, **common_attributes)
                futures.append(future)

            # Wait for all futures to complete
            for future in futures:
                message_id = future.result()
                message_ids.append(message_id)

        logger.info(
            f"Published {len(message_ids)} messages to {topic} in "
            f"{(len(messages) + self.max_messages_per_batch - 1) // self.max_messages_per_batch} batch(es)"
        )

        return message_ids

    async def publish_ioc_batch(
        self, iocs: List[Dict[str, Any]], source: str
    ) -> List[str]:
        """Publish IOC events to raw-ioc-events topic.

        Args:
            iocs: List of IOC dictionaries
            source: IOC source name

        Returns:
            List of message IDs
        """
        return await self.publish_batch(
            topic="raw-ioc-events",
            messages=iocs,
            source=source,
            event_type="ioc",
        )

    async def publish_activity_batch(
        self, activities: List[Dict[str, Any]], source: str
    ) -> List[str]:
        """Publish activity events to raw-activity-events topic.

        Args:
            activities: List of activity event dictionaries
            source: Activity source name

        Returns:
            List of message IDs
        """
        return await self.publish_batch(
            topic="raw-activity-events",
            messages=activities,
            source=source,
            event_type="activity",
        )


class MockPubSubPublisher:
    """Mock Pub/Sub publisher for testing."""

    def __init__(self, project_id: str = "test-project", max_messages_per_batch: int = 1000):
        """Initialize mock publisher."""
        self.project_id = project_id
        self.max_messages_per_batch = max_messages_per_batch
        self.published_messages: List[Dict[str, Any]] = []

    def get_topic_path(self, topic_name: str) -> str:
        """Get full topic path."""
        return f"projects/{self.project_id}/topics/{topic_name}"

    async def publish(
        self, topic: str, message: Dict[str, Any], **attributes
    ) -> str:
        """Publish a single message (mock)."""
        self.published_messages.append(
            {"topic": topic, "message": message, "attributes": attributes}
        )
        return f"mock-msg-{len(self.published_messages)}"

    async def publish_batch(
        self,
        topic: str,
        messages: List[Dict[str, Any]],
        **common_attributes,
    ) -> List[str]:
        """Publish a batch of messages (mock)."""
        message_ids = []
        for message in messages:
            msg_id = await self.publish(topic, message, **common_attributes)
            message_ids.append(msg_id)
        return message_ids

    async def publish_ioc_batch(
        self, iocs: List[Dict[str, Any]], source: str
    ) -> List[str]:
        """Publish IOC events (mock)."""
        return await self.publish_batch(
            topic="raw-ioc-events",
            messages=iocs,
            source=source,
            event_type="ioc",
        )

    async def publish_activity_batch(
        self, activities: List[Dict[str, Any]], source: str
    ) -> List[str]:
        """Publish activity events (mock)."""
        return await self.publish_batch(
            topic="raw-activity-events",
            messages=activities,
            source=source,
            event_type="activity",
        )

    def clear(self):
        """Clear published messages."""
        self.published_messages.clear()
