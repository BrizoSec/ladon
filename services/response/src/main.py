"""
Response Service - Automated Security Response and Remediation

This service executes automated response actions based on detections from the Detection Service.

Capabilities:
- Network response (block IP/domain/URL)
- Endpoint response (isolate host, kill process, quarantine file)
- Identity response (disable user, reset password, revoke sessions)
- Investigation response (collect forensics, capture memory)
- Notification (Slack, email, ServiceNow tickets)

Architecture:
- Subscribe to detection events from Pub/Sub
- Match detections to response playbooks
- Execute actions with approval workflow
- Track action status and results
- Support rollback operations
"""

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from google.cloud import pubsub_v1
import json

from models import (
    Detection,
    ResponseAction,
    ResponsePlaybook,
    ResponseStatus,
    ResponseActionType,
    ApprovalRequirement,
)
from response_engine import ResponseEngine
from action_executors.firewall import FirewallExecutor
from action_executors.edr import EDRExecutor
from action_executors.identity import IdentityExecutor
from action_executors.notification import NotificationExecutor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Configuration
PROJECT_ID = os.getenv("GCP_PROJECT_ID", "ladon-production")
DETECTION_TOPIC = os.getenv("DETECTION_TOPIC", "detection-events")
DETECTION_SUBSCRIPTION = os.getenv("DETECTION_SUBSCRIPTION", "response-service-detections")

# Response engine (initialized in lifespan)
response_engine: Optional[ResponseEngine] = None
pubsub_subscriber: Optional[pubsub_v1.SubscriberClient] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    global response_engine, pubsub_subscriber

    logger.info("Starting Response Service...")

    # Initialize action executors
    firewall_config = {
        "palo_alto": {"enabled": True},
        "fortigate": {"enabled": True},
        "gcp_firewall": {"enabled": True},
    }
    edr_config = {
        "mde": {"enabled": True},
        "crowdstrike": {"enabled": True},
    }
    identity_config = {
        "active_directory": {"enabled": True},
        "azure_ad": {"enabled": True},
        "okta": {"enabled": False},
    }
    notification_config = {
        "slack": {"enabled": True},
        "email": {"enabled": True},
        "servicenow": {"enabled": True},
    }

    firewall_executor = FirewallExecutor(firewall_config)
    edr_executor = EDRExecutor(edr_config)
    identity_executor = IdentityExecutor(identity_config)
    notification_executor = NotificationExecutor(notification_config)

    # Initialize response engine
    response_engine = ResponseEngine(
        firewall_executor=firewall_executor,
        edr_executor=edr_executor,
        identity_executor=identity_executor,
        notification_executor=notification_executor,
    )

    # Register default playbooks
    register_default_playbooks(response_engine)

    # Start Pub/Sub subscriber
    pubsub_subscriber = pubsub_v1.SubscriberClient()
    subscription_path = pubsub_subscriber.subscription_path(
        PROJECT_ID, DETECTION_SUBSCRIPTION
    )

    # Start background task to process detections
    asyncio.create_task(process_detection_events(subscription_path))

    logger.info("Response Service started successfully")

    yield

    # Shutdown
    logger.info("Shutting down Response Service...")
    if pubsub_subscriber:
        pubsub_subscriber.close()


app = FastAPI(
    title="LADON Response Service",
    description="Automated security response and remediation service",
    version="1.0.0",
    lifespan=lifespan,
)


def register_default_playbooks(engine: ResponseEngine):
    """Register default response playbooks."""

    # Playbook 1: Block malicious IPs (C2, malware)
    playbook_block_ip = ResponsePlaybook(
        playbook_id="playbook_block_malicious_ip",
        name="Block Malicious IP",
        description="Block IPs associated with C2, malware, or ransomware",
        trigger_severity=["CRITICAL", "HIGH"],
        trigger_threat_types=["c2", "malware", "ransomware"],
        trigger_ioc_types=["ip"],
        actions=[
            {
                "action_type": "block_ip",
                "parameters": {
                    "duration_hours": 24,
                    "firewall_targets": ["palo_alto", "gcp_firewall"],
                },
                "approval_required": "none",  # Auto-execute for high confidence
            },
            {
                "action_type": "notify_slack",
                "parameters": {
                    "channel": "#security-alerts",
                    "message": "Malicious IP blocked automatically",
                },
                "approval_required": "none",
            },
        ],
        enabled=True,
        auto_approve=True,
    )
    engine.register_playbook(playbook_block_ip)

    # Playbook 2: Isolate compromised hosts
    playbook_isolate_host = ResponsePlaybook(
        playbook_id="playbook_isolate_compromised_host",
        name="Isolate Compromised Host",
        description="Isolate hosts showing signs of compromise (ransomware, C2 beaconing)",
        trigger_severity=["CRITICAL"],
        trigger_threat_types=["ransomware", "c2"],
        trigger_ioc_types=["domain", "ip"],
        actions=[
            {
                "action_type": "isolate_host",
                "parameters": {
                    "platform": "mde",
                },
                "approval_required": "soc_lead",  # Requires approval
            },
            {
                "action_type": "collect_forensics",
                "parameters": {
                    "evidence_types": ["memory", "disk"],
                },
                "approval_required": "soc_lead",
            },
            {
                "action_type": "create_ticket",
                "parameters": {
                    "priority": "P1",
                    "assignment_group": "SOC Team",
                },
                "approval_required": "none",
            },
        ],
        enabled=True,
        auto_approve=False,  # Requires manual approval
    )
    engine.register_playbook(playbook_isolate_host)

    # Playbook 3: Disable compromised user accounts
    playbook_disable_user = ResponsePlaybook(
        playbook_id="playbook_disable_compromised_user",
        name="Disable Compromised User",
        description="Disable user accounts showing suspicious activity",
        trigger_severity=["CRITICAL", "HIGH"],
        trigger_threat_types=["credential_theft", "lateral_movement"],
        actions=[
            {
                "action_type": "disable_user",
                "parameters": {
                    "identity_provider": "active_directory",
                    "revoke_sessions": True,
                },
                "approval_required": "soc_analyst",
            },
            {
                "action_type": "notify_email",
                "parameters": {
                    "recipients": ["security-team@company.com"],
                    "subject": "User account disabled due to suspicious activity",
                },
                "approval_required": "none",
            },
        ],
        enabled=True,
        auto_approve=False,
    )
    engine.register_playbook(playbook_disable_user)

    logger.info("Registered 3 default playbooks")


async def process_detection_events(subscription_path: str):
    """Background task to process detection events from Pub/Sub."""
    logger.info(f"Starting detection event processor: {subscription_path}")

    def callback(message):
        """Process a single detection message."""
        try:
            data = json.loads(message.data.decode("utf-8"))
            detection = Detection(**data)

            logger.info(
                f"Received detection: {detection.detection_id} "
                f"(severity: {detection.severity}, threat: {detection.threat_type})"
            )

            # Process detection and generate actions
            actions = response_engine.process_detection(detection)

            # Execute auto-approved actions
            for action in actions:
                if action.status == ResponseStatus.APPROVED:
                    asyncio.create_task(response_engine.execute_action(action.action_id))

            message.ack()

        except Exception as e:
            logger.error(f"Error processing detection message: {e}", exc_info=True)
            message.nack()

    # Subscribe to detection events
    streaming_pull_future = pubsub_subscriber.subscribe(
        subscription_path, callback=callback
    )

    try:
        await asyncio.get_event_loop().run_in_executor(None, streaming_pull_future.result)
    except Exception as e:
        logger.error(f"Error in detection event processor: {e}", exc_info=True)
        streaming_pull_future.cancel()


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "response",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    # TODO: Implement Prometheus metrics
    return {
        "actions_total": len(response_engine.actions),
        "actions_pending": len(response_engine.get_pending_actions()),
        "playbooks_registered": len(response_engine.playbooks),
    }


@app.get("/actions", response_model=List[ResponseAction])
async def list_actions(
    status: Optional[ResponseStatus] = None,
    limit: int = 100,
):
    """List response actions."""
    actions = list(response_engine.actions.values())

    if status:
        actions = [a for a in actions if a.status == status]

    # Sort by created_at descending
    actions.sort(key=lambda a: a.created_at, reverse=True)

    return actions[:limit]


@app.get("/actions/pending", response_model=List[ResponseAction])
async def list_pending_actions():
    """List actions pending approval."""
    return response_engine.get_pending_actions()


@app.get("/actions/{action_id}", response_model=ResponseAction)
async def get_action(action_id: str):
    """Get action details."""
    action = response_engine.get_action_status(action_id)
    if not action:
        raise HTTPException(status_code=404, detail=f"Action {action_id} not found")
    return action


@app.post("/actions/{action_id}/approve")
async def approve_action(action_id: str, approver: str, background_tasks: BackgroundTasks):
    """Approve a pending action."""
    success = response_engine.approve_action(action_id, approver)

    if not success:
        raise HTTPException(status_code=400, detail="Action could not be approved")

    # Execute the action in background
    background_tasks.add_task(response_engine.execute_action, action_id)

    return {"status": "approved", "action_id": action_id}


@app.post("/actions/{action_id}/reject")
async def reject_action(action_id: str, reason: str):
    """Reject a pending action."""
    success = response_engine.reject_action(action_id, reason)

    if not success:
        raise HTTPException(status_code=400, detail="Action could not be rejected")

    return {"status": "rejected", "action_id": action_id}


@app.post("/actions/{action_id}/rollback")
async def rollback_action(action_id: str):
    """Rollback a completed action."""
    result = await response_engine.rollback_action(action_id)

    return {
        "status": "rolled_back" if result.success else "failed",
        "action_id": action_id,
        "message": result.message,
    }


@app.get("/playbooks", response_model=List[ResponsePlaybook])
async def list_playbooks():
    """List all registered playbooks."""
    return list(response_engine.playbooks.values())


@app.post("/playbooks", response_model=ResponsePlaybook)
async def create_playbook(playbook: ResponsePlaybook):
    """Register a new playbook."""
    response_engine.register_playbook(playbook)
    return playbook


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
