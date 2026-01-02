"""
LADON Storage Service

Unified storage layer providing access to BigQuery, Redis, and Firestore
for the Threat XDR platform.
"""

from .config import BigQueryConfig, FirestoreConfig, RedisConfig, StorageConfig
from .storage_service import StorageService

__version__ = "0.1.0"

__all__ = [
    "StorageService",
    "StorageConfig",
    "BigQueryConfig",
    "RedisConfig",
    "FirestoreConfig",
]
