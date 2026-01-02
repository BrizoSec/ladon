"""
Firestore repository implementation for metadata and configuration.

Handles watermark tracking for incremental collection and
dynamic configuration storage.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Optional

from google.cloud import firestore
from google.cloud.firestore_v1.base_query import FieldFilter

from ..config import FirestoreConfig
from .base import MetadataRepository

logger = logging.getLogger(__name__)


class FirestoreMetadataRepository(MetadataRepository):
    """Firestore implementation for metadata and configuration storage."""

    def __init__(self, config: FirestoreConfig):
        """
        Initialize Firestore repository.

        Args:
            config: Firestore configuration
        """
        self.config = config
        self.client = firestore.Client(
            project=config.project_id, database=config.database
        )
        logger.info(f"Initialized Firestore client for project {config.project_id}")

    async def get_watermark(self, source_id: str) -> Optional[Dict]:
        """
        Get the last successful watermark for a data source.

        Args:
            source_id: Identifier for the data source (e.g., "mde_logs", "dns_logs")

        Returns:
            Watermark document with fields:
            - source_id: str
            - last_successful_timestamp: datetime
            - last_run_timestamp: datetime
            - status: str ("success", "failed", "in_progress")
            - error_message: str (optional)
        """
        try:
            doc_ref = self.client.collection(
                self.config.watermarks_collection
            ).document(source_id)
            doc = doc_ref.get()

            if doc.exists:
                watermark = doc.to_dict()
                logger.debug(f"Retrieved watermark for {source_id}: {watermark}")
                return watermark
            else:
                logger.info(f"No watermark found for {source_id}")
                return None

        except Exception as e:
            logger.error(f"Error retrieving watermark for {source_id}: {e}", exc_info=True)
            return None

    async def update_watermark(
        self,
        source_id: str,
        timestamp: datetime,
        status: str = "success",
        error_message: Optional[str] = None,
    ) -> bool:
        """
        Update the watermark for a data source.

        Args:
            source_id: Identifier for the data source
            timestamp: New watermark timestamp
            status: Status of the collection run ("success", "failed", "in_progress")
            error_message: Error message if status is "failed"

        Returns:
            True if updated successfully, False otherwise
        """
        try:
            doc_ref = self.client.collection(
                self.config.watermarks_collection
            ).document(source_id)

            watermark_data = {
                "source_id": source_id,
                "last_run_timestamp": firestore.SERVER_TIMESTAMP,
                "status": status,
                "updated_at": firestore.SERVER_TIMESTAMP,
            }

            # Only update last_successful_timestamp if status is success
            if status == "success":
                watermark_data["last_successful_timestamp"] = timestamp

            if error_message:
                watermark_data["error_message"] = error_message
            else:
                # Clear error message on success
                watermark_data["error_message"] = None

            # Use set with merge to create or update
            doc_ref.set(watermark_data, merge=True)

            logger.info(
                f"Updated watermark for {source_id}: status={status}, timestamp={timestamp}"
            )
            return True

        except Exception as e:
            logger.error(f"Error updating watermark for {source_id}: {e}", exc_info=True)
            return False

    async def get_config(self, key: str) -> Optional[Dict]:
        """
        Retrieve a configuration value.

        Args:
            key: Configuration key (e.g., "detection_rules", "notification_settings")

        Returns:
            Configuration document as dictionary, None if not found
        """
        try:
            doc_ref = self.client.collection(self.config.config_collection).document(
                key
            )
            doc = doc_ref.get()

            if doc.exists:
                config = doc.to_dict()
                logger.debug(f"Retrieved config for {key}")
                return config
            else:
                logger.info(f"No config found for {key}")
                return None

        except Exception as e:
            logger.error(f"Error retrieving config for {key}: {e}", exc_info=True)
            return None

    async def set_config(
        self, key: str, value: Dict, merge: bool = True
    ) -> bool:
        """
        Store a configuration value.

        Args:
            key: Configuration key
            value: Configuration value as dictionary
            merge: If True, merge with existing data; if False, replace

        Returns:
            True if stored successfully, False otherwise
        """
        try:
            doc_ref = self.client.collection(self.config.config_collection).document(
                key
            )

            # Add metadata
            config_data = {
                **value,
                "updated_at": firestore.SERVER_TIMESTAMP,
                "key": key,
            }

            doc_ref.set(config_data, merge=merge)

            logger.info(f"Stored config for {key} (merge={merge})")
            return True

        except Exception as e:
            logger.error(f"Error storing config for {key}: {e}", exc_info=True)
            return False

    async def delete_config(self, key: str) -> bool:
        """
        Delete a configuration value.

        Args:
            key: Configuration key to delete

        Returns:
            True if deleted, False if not found or error
        """
        try:
            doc_ref = self.client.collection(self.config.config_collection).document(
                key
            )
            doc_ref.delete()

            logger.info(f"Deleted config for {key}")
            return True

        except Exception as e:
            logger.error(f"Error deleting config for {key}: {e}", exc_info=True)
            return False

    async def list_configs(self, prefix: Optional[str] = None) -> Dict[str, Dict]:
        """
        List all configuration keys, optionally filtered by prefix.

        Args:
            prefix: Optional prefix to filter keys

        Returns:
            Dictionary mapping keys to their configuration values
        """
        try:
            collection_ref = self.client.collection(self.config.config_collection)

            if prefix:
                # Query for documents where key starts with prefix
                query = collection_ref.where(
                    filter=FieldFilter("key", ">=", prefix)
                ).where(filter=FieldFilter("key", "<", prefix + "\uf8ff"))
                docs = query.stream()
            else:
                docs = collection_ref.stream()

            configs = {}
            for doc in docs:
                configs[doc.id] = doc.to_dict()

            logger.info(
                f"Listed {len(configs)} configs" + (f" with prefix '{prefix}'" if prefix else "")
            )
            return configs

        except Exception as e:
            logger.error(f"Error listing configs: {e}", exc_info=True)
            return {}

    async def store_metadata(
        self, collection: str, document_id: str, data: Dict
    ) -> bool:
        """
        Store arbitrary metadata in a custom collection.

        Args:
            collection: Collection name
            document_id: Document ID
            data: Data to store

        Returns:
            True if stored successfully
        """
        try:
            doc_ref = self.client.collection(collection).document(document_id)

            metadata = {
                **data,
                "updated_at": firestore.SERVER_TIMESTAMP,
            }

            doc_ref.set(metadata, merge=True)

            logger.debug(f"Stored metadata: {collection}/{document_id}")
            return True

        except Exception as e:
            logger.error(
                f"Error storing metadata {collection}/{document_id}: {e}",
                exc_info=True,
            )
            return False

    async def get_metadata(
        self, collection: str, document_id: str
    ) -> Optional[Dict]:
        """
        Retrieve metadata from a custom collection.

        Args:
            collection: Collection name
            document_id: Document ID

        Returns:
            Metadata dictionary if found, None otherwise
        """
        try:
            doc_ref = self.client.collection(collection).document(document_id)
            doc = doc_ref.get()

            if doc.exists:
                return doc.to_dict()
            else:
                return None

        except Exception as e:
            logger.error(
                f"Error retrieving metadata {collection}/{document_id}: {e}",
                exc_info=True,
            )
            return None

    async def query_watermarks_by_status(self, status: str) -> Dict[str, Dict]:
        """
        Query watermarks by status.

        Useful for finding failed or in-progress collection runs.

        Args:
            status: Status to filter by ("success", "failed", "in_progress")

        Returns:
            Dictionary mapping source_id to watermark data
        """
        try:
            collection_ref = self.client.collection(self.config.watermarks_collection)
            query = collection_ref.where(filter=FieldFilter("status", "==", status))

            watermarks = {}
            for doc in query.stream():
                watermarks[doc.id] = doc.to_dict()

            logger.info(f"Found {len(watermarks)} watermarks with status '{status}'")
            return watermarks

        except Exception as e:
            logger.error(f"Error querying watermarks by status: {e}", exc_info=True)
            return {}

    async def get_stale_watermarks(self, hours: int = 24) -> Dict[str, Dict]:
        """
        Find watermarks that haven't been updated recently.

        Useful for detecting stale data sources or failed collection jobs.

        Args:
            hours: Number of hours to consider stale

        Returns:
            Dictionary mapping source_id to watermark data
        """
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)

            collection_ref = self.client.collection(self.config.watermarks_collection)
            query = collection_ref.where(
                filter=FieldFilter("last_run_timestamp", "<", cutoff_time)
            )

            stale_watermarks = {}
            for doc in query.stream():
                stale_watermarks[doc.id] = doc.to_dict()

            logger.info(
                f"Found {len(stale_watermarks)} watermarks stale for >{hours} hours"
            )
            return stale_watermarks

        except Exception as e:
            logger.error(f"Error querying stale watermarks: {e}", exc_info=True)
            return {}

    def close(self):
        """Close Firestore client connection."""
        # Firestore client doesn't require explicit close,
        # but we include this for consistency with other repositories
        logger.info("Firestore client cleanup (no-op)")
        pass
