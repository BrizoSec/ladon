"""
Response Service - Data Models

Defines the data structures for automated response actions.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class ResponseActionType(str, Enum):
    """Types of automated response actions."""

    # Network Actions
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    BLOCK_URL = "block_url"

    # Endpoint Actions
    ISOLATE_HOST = "isolate_host"
    UNISOLATE_HOST = "unisolate_host"
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"

    # Identity Actions
    DISABLE_USER = "disable_user"
    RESET_PASSWORD = "reset_password"
    REVOKE_SESSION = "revoke_session"

    # Email Actions
    DELETE_EMAIL = "delete_email"
    QUARANTINE_EMAIL = "quarantine_email"

    # Investigation Actions
    COLLECT_FORENSICS = "collect_forensics"
    CAPTURE_MEMORY = "capture_memory"
    CAPTURE_NETWORK = "capture_network"

    # Notification Actions
    NOTIFY_SLACK = "notify_slack"
    NOTIFY_EMAIL = "notify_email"
    CREATE_TICKET = "create_ticket"


class ResponseStatus(str, Enum):
    """Status of response action execution."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class ApprovalRequirement(str, Enum):
    """Approval requirements for actions."""
    NONE = "none"  # Auto-execute
    SOC_ANALYST = "soc_analyst"
    SOC_LEAD = "soc_lead"
    SECURITY_MANAGER = "security_manager"


class ResponseAction(BaseModel):
    """A single response action to be executed."""

    action_id: str = Field(description="Unique action ID")
    action_type: ResponseActionType = Field(description="Type of action")
    detection_id: str = Field(description="Source detection ID")
    severity: str = Field(description="Detection severity: CRITICAL, HIGH, MEDIUM, LOW")

    # Action parameters (specific to action type)
    parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Action-specific parameters"
    )

    # Approval workflow
    approval_required: ApprovalRequirement = Field(
        default=ApprovalRequirement.NONE,
        description="Required approval level"
    )
    approved_by: Optional[str] = Field(default=None, description="User who approved")
    approved_at: Optional[datetime] = Field(default=None, description="Approval timestamp")

    # Execution tracking
    status: ResponseStatus = Field(
        default=ResponseStatus.PENDING,
        description="Current status"
    )
    executed_at: Optional[datetime] = Field(default=None, description="Execution timestamp")
    completed_at: Optional[datetime] = Field(default=None, description="Completion timestamp")

    # Results
    result: Optional[Dict[str, Any]] = Field(default=None, description="Execution result")
    error_message: Optional[str] = Field(default=None, description="Error if failed")

    # Rollback support
    rollback_action_id: Optional[str] = Field(
        default=None,
        description="ID of action to rollback this one"
    )
    rolled_back_at: Optional[datetime] = Field(default=None)

    # Metadata
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Creation timestamp"
    )
    created_by: str = Field(default="system", description="Creator (system or user)")
    playbook_id: Optional[str] = Field(default=None, description="Playbook that triggered this")


class ResponsePlaybook(BaseModel):
    """Automated response playbook defining actions for specific threat scenarios."""

    playbook_id: str = Field(description="Unique playbook ID")
    name: str = Field(description="Playbook name")
    description: str = Field(description="Playbook description")

    # Trigger conditions
    trigger_severity: List[str] = Field(
        default=["CRITICAL", "HIGH"],
        description="Severities that trigger this playbook"
    )
    trigger_threat_types: List[str] = Field(
        default_factory=list,
        description="Threat types that trigger (e.g., ['ransomware', 'c2'])"
    )
    trigger_ioc_types: List[str] = Field(
        default_factory=list,
        description="IOC types that trigger (e.g., ['ip', 'domain'])"
    )

    # Actions to execute
    actions: List[Dict[str, Any]] = Field(
        description="List of actions to execute"
    )

    # Configuration
    enabled: bool = Field(default=True, description="Whether playbook is active")
    auto_approve: bool = Field(
        default=False,
        description="Auto-approve actions without human review"
    )

    # Metadata
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    created_by: str = Field(description="Creator")


class Detection(BaseModel):
    """Detection event from Detection Service."""

    detection_id: str
    timestamp: datetime
    ioc_value: str
    ioc_type: str
    threat_type: str
    severity: str
    confidence: float

    # Activity context
    activity_event_id: str
    activity_source: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    domain: Optional[str] = None
    url: Optional[str] = None
    hostname: Optional[str] = None
    user: Optional[str] = None
    process_name: Optional[str] = None
    file_hash: Optional[str] = None

    # Enrichment
    enrichment: Dict[str, Any] = Field(default_factory=dict)

    # Case management
    case_id: Optional[str] = None


class ResponseExecutionResult(BaseModel):
    """Result of executing a response action."""

    action_id: str
    status: ResponseStatus
    success: bool
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# Action-specific parameter models

class BlockIPParameters(BaseModel):
    """Parameters for blocking an IP address."""
    ip_address: str
    duration_hours: int = Field(default=24, description="How long to block (0 = permanent)")
    firewall_targets: List[str] = Field(
        default=["palo_alto", "fortigate"],
        description="Which firewalls to update"
    )
    direction: str = Field(default="both", description="inbound, outbound, or both")


class IsolateHostParameters(BaseModel):
    """Parameters for isolating a host."""
    hostname: str
    platform: str = Field(description="mde or crowdstrike")
    allow_communication: List[str] = Field(
        default_factory=list,
        description="IPs/domains to allow during isolation"
    )


class DisableUserParameters(BaseModel):
    """Parameters for disabling a user account."""
    username: str
    identity_provider: str = Field(default="active_directory", description="ad, okta, azure_ad")
    revoke_sessions: bool = Field(default=True)
    notify_user: bool = Field(default=False)


class QuarantineFileParameters(BaseModel):
    """Parameters for quarantining a file."""
    file_hash: str
    hash_type: str = Field(default="sha256")
    platform: str = Field(description="mde or crowdstrike")
    scope: str = Field(default="all", description="all, specific_host, or specific_group")
