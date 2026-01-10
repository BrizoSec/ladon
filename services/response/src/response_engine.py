"""
Response Engine - Automated Response Execution

Executes automated response actions based on detections and playbooks.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional
import uuid

from models import (
    Detection,
    ResponseAction,
    ResponseActionType,
    ResponseStatus,
    ResponsePlaybook,
    ResponseExecutionResult,
    ApprovalRequirement,
    BlockIPParameters,
    IsolateHostParameters,
    DisableUserParameters,
    QuarantineFileParameters,
)
from action_executors.firewall import FirewallExecutor
from action_executors.edr import EDRExecutor
from action_executors.identity import IdentityExecutor
from action_executors.notification import NotificationExecutor

logger = logging.getLogger(__name__)


class ResponseEngine:
    """
    Core engine for automated response execution.

    Responsibilities:
    - Match detections to playbooks
    - Generate response actions
    - Execute actions with approval workflow
    - Track action status and results
    - Support rollback operations
    """

    def __init__(
        self,
        firewall_executor: FirewallExecutor,
        edr_executor: EDRExecutor,
        identity_executor: IdentityExecutor,
        notification_executor: NotificationExecutor,
    ):
        self.firewall_executor = firewall_executor
        self.edr_executor = edr_executor
        self.identity_executor = identity_executor
        self.notification_executor = notification_executor

        # In-memory playbook storage (would be Firestore in production)
        self.playbooks: Dict[str, ResponsePlaybook] = {}

        # Action history
        self.actions: Dict[str, ResponseAction] = {}

        logger.info("Response Engine initialized")

    def register_playbook(self, playbook: ResponsePlaybook) -> None:
        """Register a response playbook."""
        self.playbooks[playbook.playbook_id] = playbook
        logger.info(f"Registered playbook: {playbook.playbook_id} - {playbook.name}")

    def process_detection(self, detection: Detection) -> List[ResponseAction]:
        """
        Process a detection and generate appropriate response actions.

        Args:
            detection: Detection event from Detection Service

        Returns:
            List of response actions to execute
        """
        logger.info(
            f"Processing detection {detection.detection_id} "
            f"(severity: {detection.severity}, threat: {detection.threat_type})"
        )

        # Find matching playbooks
        matching_playbooks = self._match_playbooks(detection)

        if not matching_playbooks:
            logger.info(f"No playbooks matched detection {detection.detection_id}")
            return []

        # Generate actions from all matching playbooks
        actions = []
        for playbook in matching_playbooks:
            playbook_actions = self._generate_actions_from_playbook(
                detection, playbook
            )
            actions.extend(playbook_actions)

        logger.info(
            f"Generated {len(actions)} actions for detection {detection.detection_id}"
        )

        return actions

    def _match_playbooks(self, detection: Detection) -> List[ResponsePlaybook]:
        """Find playbooks that match the detection criteria."""
        matching = []

        for playbook in self.playbooks.values():
            if not playbook.enabled:
                continue

            # Check severity match
            if detection.severity not in playbook.trigger_severity:
                continue

            # Check threat type match (if specified)
            if playbook.trigger_threat_types:
                if detection.threat_type not in playbook.trigger_threat_types:
                    continue

            # Check IOC type match (if specified)
            if playbook.trigger_ioc_types:
                if detection.ioc_type not in playbook.trigger_ioc_types:
                    continue

            matching.append(playbook)

        return matching

    def _generate_actions_from_playbook(
        self, detection: Detection, playbook: ResponsePlaybook
    ) -> List[ResponseAction]:
        """Generate response actions from a playbook."""
        actions = []

        for action_config in playbook.actions:
            action_type = ResponseActionType(action_config["action_type"])

            # Build parameters from detection context
            parameters = self._build_action_parameters(
                action_type, detection, action_config.get("parameters", {})
            )

            # Determine approval requirement
            approval = action_config.get("approval_required", ApprovalRequirement.NONE)
            if playbook.auto_approve and approval == ApprovalRequirement.NONE:
                status = ResponseStatus.APPROVED
            else:
                status = ResponseStatus.PENDING

            action = ResponseAction(
                action_id=f"act_{uuid.uuid4().hex[:12]}",
                action_type=action_type,
                detection_id=detection.detection_id,
                severity=detection.severity,
                parameters=parameters,
                approval_required=ApprovalRequirement(approval),
                status=status,
                playbook_id=playbook.playbook_id,
            )

            actions.append(action)
            self.actions[action.action_id] = action

        return actions

    def _build_action_parameters(
        self,
        action_type: ResponseActionType,
        detection: Detection,
        config_params: Dict,
    ) -> Dict:
        """Build action parameters from detection context and config."""
        params = config_params.copy()

        # Auto-populate from detection context
        if action_type == ResponseActionType.BLOCK_IP:
            if "ip_address" not in params:
                # Block the destination IP (usually the malicious one)
                params["ip_address"] = detection.dst_ip or detection.src_ip

        elif action_type == ResponseActionType.BLOCK_DOMAIN:
            if "domain" not in params:
                params["domain"] = detection.domain

        elif action_type == ResponseActionType.ISOLATE_HOST:
            if "hostname" not in params:
                params["hostname"] = detection.hostname

        elif action_type == ResponseActionType.DISABLE_USER:
            if "username" not in params:
                params["username"] = detection.user

        elif action_type == ResponseActionType.QUARANTINE_FILE:
            if "file_hash" not in params:
                params["file_hash"] = detection.file_hash

        return params

    async def execute_action(self, action_id: str) -> ResponseExecutionResult:
        """
        Execute a response action.

        Args:
            action_id: ID of the action to execute

        Returns:
            Execution result
        """
        action = self.actions.get(action_id)
        if not action:
            return ResponseExecutionResult(
                action_id=action_id,
                status=ResponseStatus.FAILED,
                success=False,
                message=f"Action {action_id} not found",
            )

        # Check approval status
        if action.approval_required != ApprovalRequirement.NONE:
            if action.status != ResponseStatus.APPROVED:
                return ResponseExecutionResult(
                    action_id=action_id,
                    status=ResponseStatus.PENDING,
                    success=False,
                    message="Action requires approval before execution",
                )

        # Update status
        action.status = ResponseStatus.IN_PROGRESS
        action.executed_at = datetime.now(timezone.utc)

        logger.info(
            f"Executing action {action_id}: {action.action_type} "
            f"(detection: {action.detection_id})"
        )

        try:
            # Route to appropriate executor
            result = await self._route_action(action)

            # Update action with result
            action.status = ResponseStatus.COMPLETED if result.success else ResponseStatus.FAILED
            action.completed_at = datetime.now(timezone.utc)
            action.result = result.details
            if not result.success:
                action.error_message = result.message

            return result

        except Exception as e:
            logger.error(f"Error executing action {action_id}: {e}", exc_info=True)
            action.status = ResponseStatus.FAILED
            action.error_message = str(e)
            action.completed_at = datetime.now(timezone.utc)

            return ResponseExecutionResult(
                action_id=action_id,
                status=ResponseStatus.FAILED,
                success=False,
                message=f"Execution failed: {e}",
            )

    async def _route_action(self, action: ResponseAction) -> ResponseExecutionResult:
        """Route action to the appropriate executor."""

        # Network actions
        if action.action_type in [
            ResponseActionType.BLOCK_IP,
            ResponseActionType.BLOCK_DOMAIN,
            ResponseActionType.BLOCK_URL,
        ]:
            return await self.firewall_executor.execute(action)

        # Endpoint actions
        elif action.action_type in [
            ResponseActionType.ISOLATE_HOST,
            ResponseActionType.UNISOLATE_HOST,
            ResponseActionType.KILL_PROCESS,
            ResponseActionType.QUARANTINE_FILE,
            ResponseActionType.COLLECT_FORENSICS,
            ResponseActionType.CAPTURE_MEMORY,
        ]:
            return await self.edr_executor.execute(action)

        # Identity actions
        elif action.action_type in [
            ResponseActionType.DISABLE_USER,
            ResponseActionType.RESET_PASSWORD,
            ResponseActionType.REVOKE_SESSION,
        ]:
            return await self.identity_executor.execute(action)

        # Notification actions
        elif action.action_type in [
            ResponseActionType.NOTIFY_SLACK,
            ResponseActionType.NOTIFY_EMAIL,
            ResponseActionType.CREATE_TICKET,
        ]:
            return await self.notification_executor.execute(action)

        else:
            return ResponseExecutionResult(
                action_id=action.action_id,
                status=ResponseStatus.FAILED,
                success=False,
                message=f"Unknown action type: {action.action_type}",
            )

    async def rollback_action(self, action_id: str) -> ResponseExecutionResult:
        """
        Rollback a previously executed action.

        Args:
            action_id: ID of the action to rollback

        Returns:
            Rollback result
        """
        action = self.actions.get(action_id)
        if not action:
            return ResponseExecutionResult(
                action_id=action_id,
                status=ResponseStatus.FAILED,
                success=False,
                message=f"Action {action_id} not found",
            )

        if action.status != ResponseStatus.COMPLETED:
            return ResponseExecutionResult(
                action_id=action_id,
                status=ResponseStatus.FAILED,
                success=False,
                message="Only completed actions can be rolled back",
            )

        logger.info(f"Rolling back action {action_id}: {action.action_type}")

        try:
            # Create rollback action based on original action type
            rollback_result = await self._execute_rollback(action)

            if rollback_result.success:
                action.status = ResponseStatus.ROLLED_BACK
                action.rolled_back_at = datetime.now(timezone.utc)

            return rollback_result

        except Exception as e:
            logger.error(f"Error rolling back action {action_id}: {e}", exc_info=True)
            return ResponseExecutionResult(
                action_id=action_id,
                status=ResponseStatus.FAILED,
                success=False,
                message=f"Rollback failed: {e}",
            )

    async def _execute_rollback(self, action: ResponseAction) -> ResponseExecutionResult:
        """Execute rollback for a specific action type."""

        # Network actions - remove blocks
        if action.action_type == ResponseActionType.BLOCK_IP:
            return await self.firewall_executor.rollback_block_ip(action)

        # Endpoint actions - unisolate hosts
        elif action.action_type == ResponseActionType.ISOLATE_HOST:
            return await self.edr_executor.unisolate_host(action)

        # Identity actions - re-enable users
        elif action.action_type == ResponseActionType.DISABLE_USER:
            return await self.identity_executor.enable_user(action)

        else:
            return ResponseExecutionResult(
                action_id=action.action_id,
                status=ResponseStatus.COMPLETED,
                success=True,
                message=f"No rollback needed for action type: {action.action_type}",
            )

    def approve_action(self, action_id: str, approver: str) -> bool:
        """
        Approve a pending action.

        Args:
            action_id: ID of the action to approve
            approver: Username of approver

        Returns:
            True if approved successfully
        """
        action = self.actions.get(action_id)
        if not action:
            logger.warning(f"Cannot approve: action {action_id} not found")
            return False

        if action.status != ResponseStatus.PENDING:
            logger.warning(
                f"Cannot approve: action {action_id} is not pending (status: {action.status})"
            )
            return False

        action.status = ResponseStatus.APPROVED
        action.approved_by = approver
        action.approved_at = datetime.now(timezone.utc)

        logger.info(f"Action {action_id} approved by {approver}")
        return True

    def reject_action(self, action_id: str, reason: str) -> bool:
        """Reject a pending action."""
        action = self.actions.get(action_id)
        if not action:
            return False

        if action.status != ResponseStatus.PENDING:
            return False

        action.status = ResponseStatus.REJECTED
        action.error_message = f"Rejected: {reason}"
        action.completed_at = datetime.now(timezone.utc)

        logger.info(f"Action {action_id} rejected: {reason}")
        return True

    def get_action_status(self, action_id: str) -> Optional[ResponseAction]:
        """Get the current status of an action."""
        return self.actions.get(action_id)

    def get_pending_actions(self) -> List[ResponseAction]:
        """Get all actions pending approval."""
        return [
            action
            for action in self.actions.values()
            if action.status == ResponseStatus.PENDING
        ]
