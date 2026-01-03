"""Pub/Sub subscriber for consuming raw events."""

import json
import logging
from typing import Any, Callable, Dict, List, Optional

from google.cloud import pubsub_v1
from google.cloud.pubsub_v1.types import PullResponse

logger = logging.getLogger(__name__)


class PubSubSubscriber:
    """Subscriber for Google Cloud Pub/Sub.

    Consumes raw events from Pub/Sub topics and processes them.
    """

    def __init__(
        self,
        project_id: str,
        subscription_name: str,
        max_messages: int = 100,
        ack_deadline_seconds: int = 60,
    ):
        """Initialize Pub/Sub subscriber.

        Args:
            project_id: GCP project ID
            subscription_name: Subscription name
            max_messages: Maximum messages to pull at once
            ack_deadline_seconds: Acknowledgment deadline
        """
        self.project_id = project_id
        self.subscription_name = subscription_name
        self.max_messages = max_messages
        self.ack_deadline_seconds = ack_deadline_seconds
        self.client = pubsub_v1.SubscriberClient()
        self.subscription_path = self.client.subscription_path(
            project_id, subscription_name
        )

    def pull_messages(self) -> List[Dict[str, Any]]:
        """Pull messages from subscription.

        Returns:
            List of message dictionaries with data and metadata
        """
        try:
            # Pull messages
            response: PullResponse = self.client.pull(
                request={
                    "subscription": self.subscription_path,
                    "max_messages": self.max_messages,
                }
            )

            messages = []
            for received_message in response.received_messages:
                try:
                    # Decode message data
                    data = json.loads(received_message.message.data.decode("utf-8"))

                    # Extract attributes
                    attributes = dict(received_message.message.attributes)

                    messages.append(
                        {
                            "data": data,
                            "attributes": attributes,
                            "ack_id": received_message.ack_id,
                            "message_id": received_message.message.message_id,
                        }
                    )

                except json.JSONDecodeError as e:
                    logger.error(
                        f"Failed to decode message {received_message.message.message_id}: {e}"
                    )
                    # Acknowledge malformed message to remove from queue
                    self.client.acknowledge(
                        request={
                            "subscription": self.subscription_path,
                            "ack_ids": [received_message.ack_id],
                        }
                    )

            logger.info(f"Pulled {len(messages)} messages from {self.subscription_name}")
            return messages

        except Exception as e:
            logger.error(f"Failed to pull messages: {e}")
            return []

    def acknowledge(self, ack_ids: List[str]):
        """Acknowledge messages.

        Args:
            ack_ids: List of acknowledgment IDs
        """
        if not ack_ids:
            return

        try:
            self.client.acknowledge(
                request={"subscription": self.subscription_path, "ack_ids": ack_ids}
            )
            logger.debug(f"Acknowledged {len(ack_ids)} messages")

        except Exception as e:
            logger.error(f"Failed to acknowledge messages: {e}")

    def nack(self, ack_ids: List[str]):
        """Negatively acknowledge messages (for redelivery).

        Args:
            ack_ids: List of acknowledgment IDs
        """
        if not ack_ids:
            return

        try:
            self.client.modify_ack_deadline(
                request={
                    "subscription": self.subscription_path,
                    "ack_ids": ack_ids,
                    "ack_deadline_seconds": 0,  # Immediate redelivery
                }
            )
            logger.debug(f"Nacked {len(ack_ids)} messages for redelivery")

        except Exception as e:
            logger.error(f"Failed to nack messages: {e}")

    def process_messages(
        self,
        handler: Callable[[Dict[str, Any]], bool],
        auto_ack: bool = True,
    ) -> Dict[str, int]:
        """Pull and process messages with a handler function.

        Args:
            handler: Function that processes a message and returns success/failure
            auto_ack: Automatically acknowledge successful messages

        Returns:
            Dictionary with processing statistics
        """
        messages = self.pull_messages()

        success_ack_ids = []
        failed_ack_ids = []

        for message in messages:
            try:
                # Process message
                success = handler(message)

                if success:
                    success_ack_ids.append(message["ack_id"])
                else:
                    failed_ack_ids.append(message["ack_id"])

            except Exception as e:
                logger.error(
                    f"Error processing message {message['message_id']}: {e}"
                )
                failed_ack_ids.append(message["ack_id"])

        # Auto-acknowledge successful messages
        if auto_ack:
            self.acknowledge(success_ack_ids)
            # Nack failed messages for redelivery
            self.nack(failed_ack_ids)

        return {
            "total": len(messages),
            "success": len(success_ack_ids),
            "failed": len(failed_ack_ids),
        }

    def close(self):
        """Close the subscriber client."""
        self.client.close()


class MockPubSubSubscriber:
    """Mock Pub/Sub subscriber for testing."""

    def __init__(
        self,
        project_id: str = "test-project",
        subscription_name: str = "test-sub",
        max_messages: int = 100,
        ack_deadline_seconds: int = 60,
    ):
        """Initialize mock subscriber."""
        self.project_id = project_id
        self.subscription_name = subscription_name
        self.max_messages = max_messages
        self.ack_deadline_seconds = ack_deadline_seconds
        self.messages: List[Dict[str, Any]] = []
        self.acknowledged_ids: List[str] = []
        self.nacked_ids: List[str] = []

    def add_message(
        self, data: Dict[str, Any], attributes: Optional[Dict[str, str]] = None
    ):
        """Add a message to the mock queue.

        Args:
            data: Message data
            attributes: Message attributes
        """
        message_id = f"msg-{len(self.messages)}"
        ack_id = f"ack-{len(self.messages)}"

        self.messages.append(
            {
                "data": data,
                "attributes": attributes or {},
                "ack_id": ack_id,
                "message_id": message_id,
            }
        )

    def pull_messages(self) -> List[Dict[str, Any]]:
        """Pull messages from mock queue."""
        # Return up to max_messages
        messages = self.messages[: self.max_messages]
        return messages

    def acknowledge(self, ack_ids: List[str]):
        """Acknowledge messages."""
        self.acknowledged_ids.extend(ack_ids)
        # Remove acknowledged messages
        self.messages = [
            msg for msg in self.messages if msg["ack_id"] not in ack_ids
        ]

    def nack(self, ack_ids: List[str]):
        """Nack messages."""
        self.nacked_ids.extend(ack_ids)

    def process_messages(
        self,
        handler: Callable[[Dict[str, Any]], bool],
        auto_ack: bool = True,
    ) -> Dict[str, int]:
        """Process messages with handler."""
        messages = self.pull_messages()

        success_ack_ids = []
        failed_ack_ids = []

        for message in messages:
            try:
                success = handler(message)
                if success:
                    success_ack_ids.append(message["ack_id"])
                else:
                    failed_ack_ids.append(message["ack_id"])
            except Exception:
                failed_ack_ids.append(message["ack_id"])

        if auto_ack:
            self.acknowledge(success_ack_ids)
            self.nack(failed_ack_ids)

        return {
            "total": len(messages),
            "success": len(success_ack_ids),
            "failed": len(failed_ack_ids),
        }

    def close(self):
        """Close subscriber (no-op for mock)."""
        pass
