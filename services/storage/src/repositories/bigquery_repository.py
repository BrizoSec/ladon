"""
BigQuery repository implementations for IOCs, Activities, and Detections.

Implements the repository interfaces using Google BigQuery as the backend.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from google.cloud import bigquery
from google.cloud.bigquery import QueryJobConfig
from ladon_models import Detection, NormalizedActivity, NormalizedIOC, Threat, ThreatIOCAssociation

from ..config import BigQueryConfig
from .base import ActivityRepository, DetectionRepository, IOCRepository, ThreatRepository

logger = logging.getLogger(__name__)


class BigQueryIOCRepository(IOCRepository):
    """BigQuery implementation of IOC repository."""

    def __init__(self, config: BigQueryConfig):
        """
        Initialize BigQuery IOC repository.

        Args:
            config: BigQuery configuration
        """
        self.config = config
        self.client = bigquery.Client(project=config.project_id)
        self.table_id = f"{config.project_id}.{config.dataset}.{config.iocs_table}"

    async def store_ioc(self, ioc: NormalizedIOC) -> bool:
        """Store a single IOC in BigQuery."""
        try:
            row = self._ioc_to_row(ioc)
            errors = self.client.insert_rows_json(self.table_id, [row])

            if errors:
                logger.error(f"Failed to insert IOC: {errors}")
                return False

            logger.info(f"Stored IOC: {ioc.ioc_value} ({ioc.ioc_type})")
            return True

        except Exception as e:
            logger.error(f"Error storing IOC: {e}", exc_info=True)
            return False

    async def store_iocs_batch(self, iocs: List[NormalizedIOC]) -> Dict[str, int]:
        """Store multiple IOCs in a batch operation."""
        try:
            rows = [self._ioc_to_row(ioc) for ioc in iocs]

            # Use streaming insert for batch loading
            errors = self.client.insert_rows_json(self.table_id, rows)

            if errors:
                logger.error(f"Batch insert had errors: {errors}")
                success_count = len(iocs) - len(errors)
            else:
                success_count = len(iocs)

            logger.info(
                f"Stored IOC batch: {success_count}/{len(iocs)} successful"
            )

            return {"success": success_count, "failed": len(iocs) - success_count}

        except Exception as e:
            logger.error(f"Error in batch IOC insert: {e}", exc_info=True)
            return {"success": 0, "failed": len(iocs)}

    async def get_ioc(
        self, ioc_value: str, ioc_type: str
    ) -> Optional[NormalizedIOC]:
        """Retrieve a single IOC by value and type."""
        query = f"""
            SELECT *
            FROM `{self.table_id}`
            WHERE ioc_value = @ioc_value
              AND ioc_type = @ioc_type
              AND is_active = TRUE
            ORDER BY last_seen DESC
            LIMIT 1
        """

        job_config = QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("ioc_value", "STRING", ioc_value),
                bigquery.ScalarQueryParameter("ioc_type", "STRING", ioc_type),
            ]
        )

        try:
            query_job = self.client.query(query, job_config=job_config)
            results = list(query_job.result())

            if not results:
                return None

            return self._row_to_ioc(dict(results[0]))

        except Exception as e:
            logger.error(f"Error querying IOC: {e}", exc_info=True)
            return None

    async def search_iocs(
        self,
        ioc_type: Optional[str] = None,
        threat_type: Optional[str] = None,
        source: Optional[str] = None,
        min_confidence: Optional[float] = None,
        limit: int = 100,
    ) -> List[NormalizedIOC]:
        """Search for IOCs matching criteria."""
        # Build query with filters
        filters = ["is_active = TRUE"]
        params = []

        if ioc_type:
            filters.append("ioc_type = @ioc_type")
            params.append(bigquery.ScalarQueryParameter("ioc_type", "STRING", ioc_type))

        if threat_type:
            filters.append("threat_type = @threat_type")
            params.append(
                bigquery.ScalarQueryParameter("threat_type", "STRING", threat_type)
            )

        if source:
            filters.append("source = @source")
            params.append(bigquery.ScalarQueryParameter("source", "STRING", source))

        if min_confidence:
            filters.append("confidence >= @min_confidence")
            params.append(
                bigquery.ScalarQueryParameter("min_confidence", "FLOAT64", min_confidence)
            )

        where_clause = " AND ".join(filters)

        query = f"""
            SELECT *
            FROM `{self.table_id}`
            WHERE {where_clause}
            ORDER BY last_seen DESC
            LIMIT @limit
        """

        params.append(bigquery.ScalarQueryParameter("limit", "INT64", limit))
        job_config = QueryJobConfig(query_parameters=params)

        try:
            query_job = self.client.query(query, job_config=job_config)
            results = query_job.result()

            return [self._row_to_ioc(dict(row)) for row in results]

        except Exception as e:
            logger.error(f"Error searching IOCs: {e}", exc_info=True)
            return []

    async def delete_ioc(self, ioc_value: str, ioc_type: str) -> bool:
        """Delete an IOC (soft delete by marking inactive)."""
        query = f"""
            UPDATE `{self.table_id}`
            SET is_active = FALSE
            WHERE ioc_value = @ioc_value
              AND ioc_type = @ioc_type
        """

        job_config = QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("ioc_value", "STRING", ioc_value),
                bigquery.ScalarQueryParameter("ioc_type", "STRING", ioc_type),
            ]
        )

        try:
            query_job = self.client.query(query, job_config=job_config)
            query_job.result()  # Wait for completion

            logger.info(f"Deleted IOC: {ioc_value} ({ioc_type})")
            return True

        except Exception as e:
            logger.error(f"Error deleting IOC: {e}", exc_info=True)
            return False

    def _ioc_to_row(self, ioc: NormalizedIOC) -> Dict:
        """Convert IOC model to BigQuery row format."""
        return {
            "ioc_value": ioc.ioc_value,
            "ioc_type": ioc.ioc_type.value if hasattr(ioc.ioc_type, "value") else ioc.ioc_type,
            "threat_type": ioc.threat_type.value if hasattr(ioc.threat_type, "value") else ioc.threat_type,
            "confidence": ioc.confidence,
            "source": ioc.source.value if hasattr(ioc.source, "value") else ioc.source,
            "first_seen": ioc.first_seen.isoformat(),
            "last_seen": ioc.last_seen.isoformat(),
            "tags": ioc.tags,
            "enrichment": json.dumps(ioc.metadata.model_dump() if ioc.metadata else {}),
            "is_active": ioc.is_active,
            "created_at": datetime.utcnow().isoformat(),
        }

    def _row_to_ioc(self, row: Dict) -> NormalizedIOC:
        """Convert BigQuery row to IOC model."""
        return NormalizedIOC(
            ioc_value=row["ioc_value"],
            ioc_type=row["ioc_type"],
            threat_type=row["threat_type"],
            confidence=row["confidence"],
            source=row["source"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            tags=row.get("tags", []),
            is_active=row.get("is_active", True),
        )


class BigQueryActivityRepository(ActivityRepository):
    """BigQuery implementation of Activity repository."""

    def __init__(self, config: BigQueryConfig):
        """Initialize BigQuery Activity repository."""
        self.config = config
        self.client = bigquery.Client(project=config.project_id)
        self.table_id = (
            f"{config.project_id}.{config.dataset}.{config.activity_logs_table}"
        )

    async def store_activity(self, activity: NormalizedActivity) -> bool:
        """Store a single activity event."""
        try:
            row = self._activity_to_row(activity)
            errors = self.client.insert_rows_json(self.table_id, [row])

            if errors:
                logger.error(f"Failed to insert activity: {errors}")
                return False

            return True

        except Exception as e:
            logger.error(f"Error storing activity: {e}", exc_info=True)
            return False

    async def store_activities_batch(
        self, activities: List[NormalizedActivity]
    ) -> Dict[str, int]:
        """Store multiple activities in a batch."""
        try:
            rows = [self._activity_to_row(activity) for activity in activities]
            errors = self.client.insert_rows_json(self.table_id, rows)

            success_count = len(activities) - len(errors) if errors else len(activities)

            logger.info(
                f"Stored activity batch: {success_count}/{len(activities)} successful"
            )

            return {"success": success_count, "failed": len(activities) - success_count}

        except Exception as e:
            logger.error(f"Error in batch activity insert: {e}", exc_info=True)
            return {"success": 0, "failed": len(activities)}

    async def get_activity(self, event_id: str) -> Optional[NormalizedActivity]:
        """Retrieve a single activity event by ID."""
        query = f"""
            SELECT *
            FROM `{self.table_id}`
            WHERE event_id = @event_id
            LIMIT 1
        """

        job_config = QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("event_id", "STRING", event_id)
            ]
        )

        try:
            query_job = self.client.query(query, job_config=job_config)
            results = list(query_job.result())

            if not results:
                return None

            return self._row_to_activity(dict(results[0]))

        except Exception as e:
            logger.error(f"Error querying activity: {e}", exc_info=True)
            return None

    async def search_activities(
        self,
        source: Optional[str] = None,
        event_type: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[NormalizedActivity]:
        """Search for activity events matching criteria."""
        filters = []
        params = []

        if source:
            filters.append("source = @source")
            params.append(bigquery.ScalarQueryParameter("source", "STRING", source))

        if event_type:
            filters.append("event_type = @event_type")
            params.append(
                bigquery.ScalarQueryParameter("event_type", "STRING", event_type)
            )

        if start_time:
            filters.append("timestamp >= @start_time")
            params.append(
                bigquery.ScalarQueryParameter("start_time", "TIMESTAMP", start_time)
            )

        if end_time:
            filters.append("timestamp <= @end_time")
            params.append(
                bigquery.ScalarQueryParameter("end_time", "TIMESTAMP", end_time)
            )

        where_clause = " AND ".join(filters) if filters else "TRUE"

        query = f"""
            SELECT *
            FROM `{self.table_id}`
            WHERE {where_clause}
            ORDER BY timestamp DESC
            LIMIT @limit
        """

        params.append(bigquery.ScalarQueryParameter("limit", "INT64", limit))
        job_config = QueryJobConfig(query_parameters=params)

        try:
            query_job = self.client.query(query, job_config=job_config)
            results = query_job.result()

            return [self._row_to_activity(dict(row)) for row in results]

        except Exception as e:
            logger.error(f"Error searching activities: {e}", exc_info=True)
            return []

    def _activity_to_row(self, activity: NormalizedActivity) -> Dict:
        """Convert Activity model to BigQuery row format."""
        return {
            "event_id": activity.event_id,
            "timestamp": activity.timestamp.isoformat(),
            "source": activity.source.value if hasattr(activity.source, "value") else activity.source,
            "event_type": activity.event_type.value if hasattr(activity.event_type, "value") else activity.event_type,
            "src_ip": activity.src_ip,
            "dst_ip": activity.dst_ip,
            "domain": activity.domain,
            "url": activity.url,
            "hostname": activity.hostname,
            "user": activity.user_name,
            "process_name": activity.process_name,
            "file_hash": activity.file_hash,
            "enrichment": json.dumps(activity.enrichment),
            "raw_event": json.dumps(activity.raw_event),
        }

    def _row_to_activity(self, row: Dict) -> NormalizedActivity:
        """Convert BigQuery row to Activity model."""
        return NormalizedActivity(
            event_id=row["event_id"],
            timestamp=row["timestamp"],
            source=row["source"],
            event_type=row["event_type"],
            src_ip=row.get("src_ip"),
            dst_ip=row.get("dst_ip"),
            domain=row.get("domain"),
            url=row.get("url"),
            hostname=row.get("hostname"),
            user_name=row.get("user"),
            process_name=row.get("process_name"),
            file_hash=row.get("file_hash"),
            enrichment=json.loads(row.get("enrichment", "{}")),
            raw_event=json.loads(row.get("raw_event", "{}")),
        )


class BigQueryDetectionRepository(DetectionRepository):
    """BigQuery implementation of Detection repository."""

    def __init__(self, config: BigQueryConfig):
        """Initialize BigQuery Detection repository."""
        self.config = config
        self.client = bigquery.Client(project=config.project_id)
        self.table_id = f"{config.project_id}.{config.dataset}.{config.detections_table}"

    async def store_detection(self, detection: Detection) -> bool:
        """Store a single detection."""
        try:
            row = self._detection_to_row(detection)
            errors = self.client.insert_rows_json(self.table_id, [row])

            if errors:
                logger.error(f"Failed to insert detection: {errors}")
                return False

            logger.info(f"Stored detection: {detection.detection_id}")
            return True

        except Exception as e:
            logger.error(f"Error storing detection: {e}", exc_info=True)
            return False

    async def store_detections_batch(
        self, detections: List[Detection]
    ) -> Dict[str, int]:
        """Store multiple detections in a batch."""
        try:
            rows = [self._detection_to_row(det) for det in detections]
            errors = self.client.insert_rows_json(self.table_id, rows)

            success_count = (
                len(detections) - len(errors) if errors else len(detections)
            )

            logger.info(
                f"Stored detection batch: {success_count}/{len(detections)} successful"
            )

            return {
                "success": success_count,
                "failed": len(detections) - success_count,
            }

        except Exception as e:
            logger.error(f"Error in batch detection insert: {e}", exc_info=True)
            return {"success": 0, "failed": len(detections)}

    async def get_detection(self, detection_id: str) -> Optional[Detection]:
        """Retrieve a single detection by ID."""
        query = f"""
            SELECT *
            FROM `{self.table_id}`
            WHERE detection_id = @detection_id
            LIMIT 1
        """

        job_config = QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("detection_id", "STRING", detection_id)
            ]
        )

        try:
            query_job = self.client.query(query, job_config=job_config)
            results = list(query_job.result())

            if not results:
                return None

            return self._row_to_detection(dict(results[0]))

        except Exception as e:
            logger.error(f"Error querying detection: {e}", exc_info=True)
            return None

    async def search_detections(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Detection]:
        """Search for detections matching criteria."""
        filters = []
        params = []

        if severity:
            filters.append("severity = @severity")
            params.append(bigquery.ScalarQueryParameter("severity", "STRING", severity))

        if status:
            filters.append("status = @status")
            params.append(bigquery.ScalarQueryParameter("status", "STRING", status))

        if start_time:
            filters.append("timestamp >= @start_time")
            params.append(
                bigquery.ScalarQueryParameter("start_time", "TIMESTAMP", start_time)
            )

        if end_time:
            filters.append("timestamp <= @end_time")
            params.append(
                bigquery.ScalarQueryParameter("end_time", "TIMESTAMP", end_time)
            )

        where_clause = " AND ".join(filters) if filters else "TRUE"

        query = f"""
            SELECT *
            FROM `{self.table_id}`
            WHERE {where_clause}
            ORDER BY timestamp DESC
            LIMIT @limit
        """

        params.append(bigquery.ScalarQueryParameter("limit", "INT64", limit))
        job_config = QueryJobConfig(query_parameters=params)

        try:
            query_job = self.client.query(query, job_config=job_config)
            results = query_job.result()

            return [self._row_to_detection(dict(row)) for row in results]

        except Exception as e:
            logger.error(f"Error searching detections: {e}", exc_info=True)
            return []

    async def update_detection_status(
        self, detection_id: str, status: str, case_id: Optional[str] = None
    ) -> bool:
        """Update the status of a detection."""
        if case_id:
            query = f"""
                UPDATE `{self.table_id}`
                SET status = @status, case_id = @case_id
                WHERE detection_id = @detection_id
            """
            params = [
                bigquery.ScalarQueryParameter("detection_id", "STRING", detection_id),
                bigquery.ScalarQueryParameter("status", "STRING", status),
                bigquery.ScalarQueryParameter("case_id", "STRING", case_id),
            ]
        else:
            query = f"""
                UPDATE `{self.table_id}`
                SET status = @status
                WHERE detection_id = @detection_id
            """
            params = [
                bigquery.ScalarQueryParameter("detection_id", "STRING", detection_id),
                bigquery.ScalarQueryParameter("status", "STRING", status),
            ]

        job_config = QueryJobConfig(query_parameters=params)

        try:
            query_job = self.client.query(query, job_config=job_config)
            query_job.result()  # Wait for completion

            logger.info(f"Updated detection {detection_id} status to {status}")
            return True

        except Exception as e:
            logger.error(f"Error updating detection status: {e}", exc_info=True)
            return False

    def _detection_to_row(self, detection: Detection) -> Dict:
        """Convert Detection model to BigQuery row format."""
        return {
            "detection_id": detection.detection_id,
            "timestamp": detection.timestamp.isoformat(),
            "ioc_value": detection.ioc_value,
            "ioc_type": detection.ioc_type,
            "activity_event_id": detection.activity_event_id,
            "activity_source": detection.activity_source.value if hasattr(detection.activity_source, "value") else detection.activity_source,
            "severity": detection.severity.value if hasattr(detection.severity, "value") else detection.severity,
            "confidence": detection.confidence,
            "enrichment": json.dumps(
                {k: v.model_dump() if hasattr(v, "model_dump") else v for k, v in detection.enrichment.items()}
            ),
            "case_id": detection.case_id,
            "status": detection.status.value if hasattr(detection.status, "value") else detection.status,
            "created_at": detection.created_at.isoformat(),
        }

    def _row_to_detection(self, row: Dict) -> Detection:
        """Convert BigQuery row to Detection model."""
        return Detection(
            detection_id=row["detection_id"],
            timestamp=row["timestamp"],
            ioc_value=row["ioc_value"],
            ioc_type=row["ioc_type"],
            activity_event_id=row["activity_event_id"],
            activity_source=row["activity_source"],
            severity=row["severity"],
            confidence=row["confidence"],
            enrichment=json.loads(row.get("enrichment", "{}")),
            case_id=row.get("case_id"),
            status=row.get("status", "New"),
            first_seen=row["timestamp"],
            last_seen=row["timestamp"],
        )


class BigQueryThreatRepository(ThreatRepository):
    """BigQuery implementation of Threat repository."""

    def __init__(self, config: BigQueryConfig):
        """
        Initialize BigQuery Threat repository.

        Args:
            config: BigQuery configuration
        """
        self.config = config
        self.client = bigquery.Client(project=config.project_id)
        self.threats_table = f"{config.project_id}.{config.dataset}.threats"
        self.threat_ioc_associations_table = f"{config.project_id}.{config.dataset}.threat_ioc_associations"

    async def store_threat(self, threat: Threat) -> bool:
        """Store a single threat in BigQuery."""
        try:
            row = self._threat_to_row(threat)
            errors = self.client.insert_rows_json(self.threats_table, [row])

            if errors:
                logger.error(f"Failed to insert threat: {errors}")
                return False

            logger.info(f"Stored threat: {threat.threat_id} ({threat.name})")
            return True

        except Exception as e:
            logger.error(f"Error storing threat: {e}", exc_info=True)
            return False

    async def store_threats_batch(self, threats: List[Threat]) -> Dict[str, int]:
        """Store multiple threats in a batch operation."""
        try:
            rows = [self._threat_to_row(threat) for threat in threats]

            errors = self.client.insert_rows_json(self.threats_table, rows)

            if errors:
                logger.error(f"Batch insert had errors: {errors}")
                success_count = len(threats) - len(errors)
            else:
                success_count = len(threats)

            logger.info(
                f"Stored threat batch: {success_count}/{len(threats)} successful"
            )

            return {"success": success_count, "failed": len(threats) - success_count}

        except Exception as e:
            logger.error(f"Error in batch threat insert: {e}", exc_info=True)
            return {"success": 0, "failed": len(threats)}

    async def get_threat(self, threat_id: str) -> Optional[Threat]:
        """Retrieve a single threat by ID."""
        query = f"""
            SELECT *
            FROM `{self.threats_table}`
            WHERE threat_id = @threat_id
            LIMIT 1
        """

        job_config = QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("threat_id", "STRING", threat_id),
            ]
        )

        try:
            query_job = self.client.query(query, job_config=job_config)
            results = list(query_job.result())

            if not results:
                return None

            return self._row_to_threat(dict(results[0]))

        except Exception as e:
            logger.error(f"Error retrieving threat {threat_id}: {e}", exc_info=True)
            return None

    async def search_threats(
        self,
        category: Optional[str] = None,
        threat_type: Optional[str] = None,
        is_active: Optional[bool] = None,
        min_confidence: Optional[float] = None,
        limit: int = 100,
    ) -> List[Threat]:
        """Search for threats matching criteria."""
        conditions = []
        parameters = []

        if category:
            conditions.append("threat_category = @category")
            parameters.append(
                bigquery.ScalarQueryParameter("category", "STRING", category)
            )

        if threat_type:
            conditions.append("threat_type = @threat_type")
            parameters.append(
                bigquery.ScalarQueryParameter("threat_type", "STRING", threat_type)
            )

        if is_active is not None:
            conditions.append("is_active = @is_active")
            parameters.append(
                bigquery.ScalarQueryParameter("is_active", "BOOL", is_active)
            )

        if min_confidence is not None:
            conditions.append("confidence >= @min_confidence")
            parameters.append(
                bigquery.ScalarQueryParameter("min_confidence", "FLOAT64", min_confidence)
            )

        where_clause = " AND ".join(conditions) if conditions else "TRUE"

        query = f"""
            SELECT *
            FROM `{self.threats_table}`
            WHERE {where_clause}
            ORDER BY last_seen DESC
            LIMIT @limit
        """

        parameters.append(bigquery.ScalarQueryParameter("limit", "INT64", limit))

        job_config = QueryJobConfig(query_parameters=parameters)

        try:
            query_job = self.client.query(query, job_config=job_config)
            results = query_job.result()

            threats = [self._row_to_threat(dict(row)) for row in results]
            logger.info(f"Found {len(threats)} threats matching criteria")
            return threats

        except Exception as e:
            logger.error(f"Error searching threats: {e}", exc_info=True)
            return []

    async def associate_ioc_with_threat(
        self, association: ThreatIOCAssociation
    ) -> bool:
        """Associate an IOC with a threat."""
        try:
            row = self._association_to_row(association)
            errors = self.client.insert_rows_json(
                self.threat_ioc_associations_table, [row]
            )

            if errors:
                logger.error(f"Failed to insert threat-IOC association: {errors}")
                return False

            logger.info(
                f"Associated IOC {association.ioc_value} with threat {association.threat_id}"
            )
            return True

        except Exception as e:
            logger.error(f"Error creating threat-IOC association: {e}", exc_info=True)
            return False

    async def get_threats_for_ioc(
        self, ioc_value: str, ioc_type: str
    ) -> List[Threat]:
        """Get all threats associated with an IOC."""
        query = f"""
            SELECT t.*
            FROM `{self.threats_table}` t
            JOIN `{self.threat_ioc_associations_table}` a
                ON t.threat_id = a.threat_id
            WHERE a.ioc_value = @ioc_value
              AND a.ioc_type = @ioc_type
            ORDER BY a.confidence DESC, t.last_seen DESC
        """

        job_config = QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("ioc_value", "STRING", ioc_value),
                bigquery.ScalarQueryParameter("ioc_type", "STRING", ioc_type),
            ]
        )

        try:
            query_job = self.client.query(query, job_config=job_config)
            results = query_job.result()

            threats = [self._row_to_threat(dict(row)) for row in results]
            logger.info(
                f"Found {len(threats)} threats associated with IOC {ioc_value}"
            )
            return threats

        except Exception as e:
            logger.error(f"Error retrieving threats for IOC: {e}", exc_info=True)
            return []

    async def get_iocs_for_threat(
        self, threat_id: str, limit: int = 100
    ) -> List[Dict]:
        """Get all IOCs associated with a threat."""
        query = f"""
            SELECT
                a.ioc_value,
                a.ioc_type,
                a.relationship_type,
                a.confidence,
                a.first_seen,
                a.last_seen,
                a.observation_count
            FROM `{self.threat_ioc_associations_table}` a
            WHERE a.threat_id = @threat_id
            ORDER BY a.confidence DESC, a.last_seen DESC
            LIMIT @limit
        """

        job_config = QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("threat_id", "STRING", threat_id),
                bigquery.ScalarQueryParameter("limit", "INT64", limit),
            ]
        )

        try:
            query_job = self.client.query(query, job_config=job_config)
            results = query_job.result()

            iocs = [dict(row) for row in results]
            logger.info(f"Found {len(iocs)} IOCs associated with threat {threat_id}")
            return iocs

        except Exception as e:
            logger.error(f"Error retrieving IOCs for threat: {e}", exc_info=True)
            return []

    async def update_threat(self, threat_id: str, updates: Dict) -> bool:
        """Update a threat's fields."""
        # BigQuery doesn't support direct updates well, so we use MERGE
        set_clauses = []
        parameters = [
            bigquery.ScalarQueryParameter("threat_id", "STRING", threat_id)
        ]

        for key, value in updates.items():
            if key in ["is_active", "severity", "confidence", "description"]:
                set_clauses.append(f"{key} = @{key}")
                # Determine type based on key
                if key == "is_active":
                    param_type = "BOOL"
                elif key == "confidence":
                    param_type = "FLOAT64"
                else:
                    param_type = "STRING"
                parameters.append(
                    bigquery.ScalarQueryParameter(key, param_type, value)
                )

        if not set_clauses:
            logger.warning("No valid fields to update")
            return False

        # Add updated_at
        set_clauses.append("updated_at = @updated_at")
        parameters.append(
            bigquery.ScalarQueryParameter(
                "updated_at", "TIMESTAMP", datetime.utcnow()
            )
        )

        query = f"""
            UPDATE `{self.threats_table}`
            SET {', '.join(set_clauses)}
            WHERE threat_id = @threat_id
        """

        job_config = QueryJobConfig(query_parameters=parameters)

        try:
            query_job = self.client.query(query, job_config=job_config)
            query_job.result()  # Wait for completion

            logger.info(f"Updated threat {threat_id}")
            return True

        except Exception as e:
            logger.error(f"Error updating threat: {e}", exc_info=True)
            return False

    def _threat_to_row(self, threat: Threat) -> Dict:
        """Convert Threat model to BigQuery row format."""
        return {
            "threat_id": threat.threat_id,
            "name": threat.name,
            "aliases": threat.aliases,
            "threat_category": threat.threat_category,
            "threat_type": threat.threat_type.value if hasattr(threat.threat_type, "value") else threat.threat_type,
            "description": threat.description,
            "severity": threat.severity,
            "confidence": threat.confidence,
            "first_seen": threat.first_seen.isoformat(),
            "last_seen": threat.last_seen.isoformat(),
            "is_active": threat.is_active,
            "techniques": json.dumps([tech.model_dump() for tech in threat.techniques]),
            "tactics": threat.tactics or threat.get_all_tactics(),
            "sources": threat.sources,
            "reference_urls": threat.reference_urls,
            "tags": threat.tags,
            "metadata": json.dumps(threat.metadata),
            "created_at": threat.created_at.isoformat(),
            "updated_at": threat.updated_at.isoformat(),
        }

    def _row_to_threat(self, row: Dict) -> Threat:
        """Convert BigQuery row to Threat model."""
        from ladon_models import MITRETechnique

        # Parse techniques from JSON
        techniques = []
        if row.get("techniques"):
            tech_data = json.loads(row["techniques"]) if isinstance(row["techniques"], str) else row["techniques"]
            techniques = [MITRETechnique(**tech) for tech in tech_data]

        return Threat(
            threat_id=row["threat_id"],
            name=row["name"],
            aliases=row.get("aliases", []),
            threat_category=row["threat_category"],
            threat_type=row["threat_type"],
            description=row["description"],
            severity=row.get("severity", "medium"),
            confidence=row.get("confidence", 0.5),
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            is_active=row.get("is_active", True),
            techniques=techniques,
            tactics=row.get("tactics", []),
            sources=row.get("sources", []),
            reference_urls=row.get("reference_urls", []),
            tags=row.get("tags", []),
            metadata=json.loads(row.get("metadata", "{}")) if isinstance(row.get("metadata"), str) else row.get("metadata", {}),
            created_at=row.get("created_at", datetime.utcnow()),
            updated_at=row.get("updated_at", datetime.utcnow()),
        )

    def _association_to_row(self, association: ThreatIOCAssociation) -> Dict:
        """Convert ThreatIOCAssociation model to BigQuery row format."""
        return {
            "threat_id": association.threat_id,
            "ioc_value": association.ioc_value,
            "ioc_type": association.ioc_type,
            "relationship_type": association.relationship_type,
            "confidence": association.confidence,
            "first_seen": association.first_seen.isoformat(),
            "last_seen": association.last_seen.isoformat(),
            "observation_count": association.observation_count,
            "sources": association.sources,
            "reference_urls": association.reference_urls,
            "notes": association.notes,
            "tags": association.tags,
            "created_at": association.created_at.isoformat(),
            "updated_at": association.updated_at.isoformat(),
        }
