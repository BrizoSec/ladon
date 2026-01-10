"""
Tests for Response Engine
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import Mock, AsyncMock

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../src'))

from models import (
    Detection,
    ResponsePlaybook,
    ResponseActionType,
    ResponseStatus,
    ApprovalRequirement,
)
from response_engine import ResponseEngine
from action_executors.firewall import FirewallExecutor
from action_executors.edr import EDRExecutor
from action_executors.identity import IdentityExecutor
from action_executors.notification import NotificationExecutor


@pytest.fixture
def mock_executors():
    """Create mock executors."""
    return {
        "firewall": Mock(spec=FirewallExecutor),
        "edr": Mock(spec=EDRExecutor),
        "identity": Mock(spec=IdentityExecutor),
        "notification": Mock(spec=NotificationExecutor),
    }


@pytest.fixture
def response_engine(mock_executors):
    """Create response engine with mock executors."""
    engine = ResponseEngine(
        firewall_executor=mock_executors["firewall"],
        edr_executor=mock_executors["edr"],
        identity_executor=mock_executors["identity"],
        notification_executor=mock_executors["notification"],
    )
    return engine


@pytest.fixture
def sample_detection():
    """Create a sample detection event."""
    return Detection(
        detection_id="det_test123",
        timestamp=datetime.now(timezone.utc),
        ioc_value="192.0.2.100",
        ioc_type="ip",
        threat_type="c2",
        severity="CRITICAL",
        confidence=0.9,
        activity_event_id="act_test123",
        activity_source="proxy",
        src_ip="10.1.2.3",
        dst_ip="192.0.2.100",
        domain="malicious.example.com",
        hostname="workstation-01",
        user="john.doe",
    )


def test_register_playbook(response_engine):
    """Test playbook registration."""
    playbook = ResponsePlaybook(
        playbook_id="test_playbook",
        name="Test Playbook",
        description="Test description",
        trigger_severity=["HIGH"],
        actions=[],
        created_by="test",
    )

    response_engine.register_playbook(playbook)

    assert "test_playbook" in response_engine.playbooks
    assert response_engine.playbooks["test_playbook"].name == "Test Playbook"


def test_match_playbook_by_severity(response_engine, sample_detection):
    """Test playbook matching by severity."""
    playbook = ResponsePlaybook(
        playbook_id="critical_playbook",
        name="Critical Playbook",
        description="Handles critical threats",
        trigger_severity=["CRITICAL"],
        trigger_threat_types=[],
        trigger_ioc_types=[],
        actions=[],
        enabled=True,
        created_by="test",
    )
    response_engine.register_playbook(playbook)

    matching = response_engine._match_playbooks(sample_detection)

    assert len(matching) == 1
    assert matching[0].playbook_id == "critical_playbook"


def test_match_playbook_by_threat_type(response_engine, sample_detection):
    """Test playbook matching by threat type."""
    playbook = ResponsePlaybook(
        playbook_id="c2_playbook",
        name="C2 Playbook",
        description="Handles C2 detections",
        trigger_severity=["CRITICAL", "HIGH"],
        trigger_threat_types=["c2"],
        trigger_ioc_types=[],
        actions=[],
        enabled=True,
        created_by="test",
    )
    response_engine.register_playbook(playbook)

    matching = response_engine._match_playbooks(sample_detection)

    assert len(matching) == 1
    assert matching[0].playbook_id == "c2_playbook"


def test_no_match_disabled_playbook(response_engine, sample_detection):
    """Test that disabled playbooks don't match."""
    playbook = ResponsePlaybook(
        playbook_id="disabled_playbook",
        name="Disabled Playbook",
        description="Should not match",
        trigger_severity=["CRITICAL"],
        actions=[],
        enabled=False,  # Disabled
        created_by="test",
    )
    response_engine.register_playbook(playbook)

    matching = response_engine._match_playbooks(sample_detection)

    assert len(matching) == 0


def test_generate_block_ip_action(response_engine, sample_detection):
    """Test generating block IP action."""
    playbook = ResponsePlaybook(
        playbook_id="block_ip_playbook",
        name="Block IP",
        description="Block malicious IPs",
        trigger_severity=["CRITICAL"],
        trigger_threat_types=["c2"],
        actions=[
            {
                "action_type": "block_ip",
                "parameters": {
                    "duration_hours": 24,
                    "firewall_targets": ["palo_alto"],
                },
                "approval_required": "none",
            }
        ],
        enabled=True,
        auto_approve=True,
        created_by="test",
    )
    response_engine.register_playbook(playbook)

    actions = response_engine.process_detection(sample_detection)

    assert len(actions) == 1
    assert actions[0].action_type == ResponseActionType.BLOCK_IP
    assert actions[0].status == ResponseStatus.APPROVED  # Auto-approved
    assert actions[0].parameters["ip_address"] == "192.0.2.100"  # Auto-populated


def test_action_requires_approval(response_engine, sample_detection):
    """Test action requiring approval."""
    playbook = ResponsePlaybook(
        playbook_id="isolate_playbook",
        name="Isolate Host",
        description="Isolate compromised hosts",
        trigger_severity=["CRITICAL"],
        actions=[
            {
                "action_type": "isolate_host",
                "parameters": {"platform": "mde"},
                "approval_required": "soc_lead",
            }
        ],
        enabled=True,
        auto_approve=False,  # Requires manual approval
        created_by="test",
    )
    response_engine.register_playbook(playbook)

    actions = response_engine.process_detection(sample_detection)

    assert len(actions) == 1
    assert actions[0].action_type == ResponseActionType.ISOLATE_HOST
    assert actions[0].status == ResponseStatus.PENDING
    assert actions[0].approval_required == ApprovalRequirement.SOC_LEAD


def test_approve_action(response_engine, sample_detection):
    """Test approving a pending action."""
    playbook = ResponsePlaybook(
        playbook_id="test_playbook",
        name="Test",
        description="Test",
        trigger_severity=["CRITICAL"],
        actions=[
            {
                "action_type": "isolate_host",
                "approval_required": "soc_analyst",
            }
        ],
        enabled=True,
        auto_approve=False,
        created_by="test",
    )
    response_engine.register_playbook(playbook)

    actions = response_engine.process_detection(sample_detection)
    action_id = actions[0].action_id

    # Approve the action
    success = response_engine.approve_action(action_id, "john.doe@company.com")

    assert success is True
    action = response_engine.get_action_status(action_id)
    assert action.status == ResponseStatus.APPROVED
    assert action.approved_by == "john.doe@company.com"


def test_reject_action(response_engine, sample_detection):
    """Test rejecting a pending action."""
    playbook = ResponsePlaybook(
        playbook_id="test_playbook",
        name="Test",
        description="Test",
        trigger_severity=["CRITICAL"],
        actions=[
            {
                "action_type": "block_ip",
                "approval_required": "soc_analyst",
            }
        ],
        enabled=True,
        auto_approve=False,
        created_by="test",
    )
    response_engine.register_playbook(playbook)

    actions = response_engine.process_detection(sample_detection)
    action_id = actions[0].action_id

    # Reject the action
    success = response_engine.reject_action(action_id, "False positive")

    assert success is True
    action = response_engine.get_action_status(action_id)
    assert action.status == ResponseStatus.REJECTED
    assert "False positive" in action.error_message


def test_get_pending_actions(response_engine, sample_detection):
    """Test retrieving pending actions."""
    playbook = ResponsePlaybook(
        playbook_id="test_playbook",
        name="Test",
        description="Test",
        trigger_severity=["CRITICAL"],
        actions=[
            {"action_type": "block_ip", "approval_required": "soc_analyst"},
            {"action_type": "isolate_host", "approval_required": "soc_lead"},
        ],
        enabled=True,
        auto_approve=False,
        created_by="test",
    )
    response_engine.register_playbook(playbook)

    response_engine.process_detection(sample_detection)

    pending = response_engine.get_pending_actions()

    assert len(pending) == 2
    assert all(a.status == ResponseStatus.PENDING for a in pending)


@pytest.mark.asyncio
async def test_execute_action_without_approval_fails(response_engine, sample_detection):
    """Test that executing an unapproved action fails."""
    playbook = ResponsePlaybook(
        playbook_id="test_playbook",
        name="Test",
        description="Test",
        trigger_severity=["CRITICAL"],
        actions=[
            {"action_type": "block_ip", "approval_required": "soc_analyst"}
        ],
        enabled=True,
        auto_approve=False,
        created_by="test",
    )
    response_engine.register_playbook(playbook)

    actions = response_engine.process_detection(sample_detection)
    action_id = actions[0].action_id

    # Try to execute without approval
    result = await response_engine.execute_action(action_id)

    assert result.success is False
    assert "requires approval" in result.message.lower()


@pytest.mark.asyncio
async def test_execute_approved_action(response_engine, mock_executors, sample_detection):
    """Test executing an approved action."""
    # Mock the firewall executor to return success
    mock_executors["firewall"].execute = AsyncMock(
        return_value=Mock(success=True, message="IP blocked")
    )

    playbook = ResponsePlaybook(
        playbook_id="test_playbook",
        name="Test",
        description="Test",
        trigger_severity=["CRITICAL"],
        actions=[
            {"action_type": "block_ip", "approval_required": "soc_analyst"}
        ],
        enabled=True,
        auto_approve=False,
        created_by="test",
    )
    response_engine.register_playbook(playbook)

    actions = response_engine.process_detection(sample_detection)
    action_id = actions[0].action_id

    # Approve and execute
    response_engine.approve_action(action_id, "admin")
    result = await response_engine.execute_action(action_id)

    assert result.success is True
    action = response_engine.get_action_status(action_id)
    assert action.status == ResponseStatus.COMPLETED
