# Response Service

Automated security response and remediation service for the LADON platform.

## Overview

The Response Service executes automated response actions based on security detections. It provides:

- **Automated Response**: Execute actions automatically based on playbooks
- **Approval Workflow**: Route high-impact actions through SOC approval
- **Multi-Platform Support**: Integrate with firewalls, EDR, IAM, and other security tools
- **Action Tracking**: Full audit trail of all actions taken
- **Rollback Support**: Undo actions if needed

## Architecture

```
Detection Event → Response Engine → Playbook Matcher → Action Executor → External System
                                         ↓
                                  Approval Workflow (if required)
```

## Supported Actions

### Network Response
- **Block IP**: Block malicious IP addresses on firewalls
- **Block Domain**: Block domains via DNS/URL filtering
- **Block URL**: Block specific URLs

### Endpoint Response
- **Isolate Host**: Network isolate compromised endpoints
- **Quarantine File**: Quarantine malicious files across endpoints
- **Kill Process**: Terminate running processes
- **Collect Forensics**: Gather memory/disk evidence

### Identity Response
- **Disable User**: Disable compromised user accounts
- **Reset Password**: Force password reset
- **Revoke Sessions**: Invalidate active sessions

### Investigation
- **Capture Memory**: Create memory dumps
- **Capture Network**: Capture network traffic

### Notification
- **Slack Alerts**: Send alerts to Slack channels
- **Email Notifications**: Send email alerts
- **ServiceNow Tickets**: Create incidents

## Supported Platforms

### Firewalls
- Palo Alto Networks PAN-OS
- Fortinet FortiGate
- GCP Firewall Rules
- AWS Security Groups (planned)

### EDR Platforms
- Microsoft Defender for Endpoint (MDE)
- CrowdStrike Falcon
- SentinelOne (planned)
- Carbon Black (planned)

### Identity Providers
- Active Directory
- Azure AD / Entra ID
- Okta
- Google Workspace (planned)

## Response Playbooks

Playbooks define automated response workflows triggered by specific detection criteria.

### Example Playbook: Block Malicious IP

```python
playbook = ResponsePlaybook(
    playbook_id="playbook_block_malicious_ip",
    name="Block Malicious IP",
    description="Auto-block IPs associated with C2, malware, or ransomware",

    # Trigger conditions
    trigger_severity=["CRITICAL", "HIGH"],
    trigger_threat_types=["c2", "malware", "ransomware"],
    trigger_ioc_types=["ip"],

    # Actions to execute
    actions=[
        {
            "action_type": "block_ip",
            "parameters": {
                "duration_hours": 24,
                "firewall_targets": ["palo_alto", "gcp_firewall"],
            },
            "approval_required": "none",  # Auto-execute
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
```

### Example Playbook: Isolate Compromised Host

```python
playbook = ResponsePlaybook(
    playbook_id="playbook_isolate_compromised_host",
    name="Isolate Compromised Host",
    description="Isolate hosts showing signs of ransomware or C2",

    trigger_severity=["CRITICAL"],
    trigger_threat_types=["ransomware", "c2"],

    actions=[
        {
            "action_type": "isolate_host",
            "parameters": {"platform": "mde"},
            "approval_required": "soc_lead",  # Requires approval
        },
        {
            "action_type": "collect_forensics",
            "parameters": {"evidence_types": ["memory", "disk"]},
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
```

## Approval Workflow

Actions can require different levels of approval:

- **None**: Auto-execute immediately
- **SOC Analyst**: Any SOC analyst can approve
- **SOC Lead**: SOC lead approval required
- **Security Manager**: Manager approval required

### Approval Process

1. Detection triggers playbook
2. Response Engine generates actions
3. Actions requiring approval enter PENDING state
4. SOC analyst reviews via API or UI
5. Analyst approves or rejects action
6. Approved actions execute
7. Results tracked in action history

## API Endpoints

### Action Management

```bash
# List all actions
GET /actions?status=pending&limit=100

# Get action details
GET /actions/{action_id}

# Approve action
POST /actions/{action_id}/approve
{
  "approver": "john.doe@company.com"
}

# Reject action
POST /actions/{action_id}/reject
{
  "reason": "False positive - whitelisted IP"
}

# Rollback action
POST /actions/{action_id}/rollback
```

### Playbook Management

```bash
# List playbooks
GET /playbooks

# Create playbook
POST /playbooks
{
  "playbook_id": "custom_playbook",
  "name": "Custom Response",
  ...
}
```

### Health & Metrics

```bash
# Health check
GET /health

# Prometheus metrics
GET /metrics
```

## Configuration

### Environment Variables

```bash
# GCP Configuration
GCP_PROJECT_ID=ladon-production
DETECTION_TOPIC=detection-events
DETECTION_SUBSCRIPTION=response-service-detections

# Firewall Configuration
PALO_ALTO_ENABLED=true
PALO_ALTO_API_KEY=secret://palo-alto-api-key
PALO_ALTO_HOST=firewall.company.com

FORTIGATE_ENABLED=true
FORTIGATE_API_KEY=secret://fortigate-api-key
FORTIGATE_HOST=fortigate.company.com

# EDR Configuration
MDE_ENABLED=true
MDE_TENANT_ID=your-tenant-id
MDE_CLIENT_ID=your-client-id
MDE_CLIENT_SECRET=secret://mde-client-secret

CROWDSTRIKE_ENABLED=true
CROWDSTRIKE_CLIENT_ID=your-client-id
CROWDSTRIKE_CLIENT_SECRET=secret://crowdstrike-secret
CROWDSTRIKE_BASE_URL=https://api.crowdstrike.com

# Identity Configuration
AD_ENABLED=true
AD_LDAP_SERVER=ldap://dc.company.com
AD_BIND_DN=CN=svc-ladon,OU=Service Accounts,DC=company,DC=com
AD_BIND_PASSWORD=secret://ad-bind-password

AZURE_AD_ENABLED=true
AZURE_AD_TENANT_ID=your-tenant-id
AZURE_AD_CLIENT_ID=your-client-id
AZURE_AD_CLIENT_SECRET=secret://azure-ad-secret

# Notification Configuration
SLACK_ENABLED=true
SLACK_WEBHOOK_URL=secret://slack-webhook-url
SLACK_CHANNEL=#security-alerts

EMAIL_ENABLED=true
EMAIL_SMTP_HOST=smtp.gmail.com
EMAIL_SMTP_PORT=587
EMAIL_FROM=security-alerts@company.com
EMAIL_PASSWORD=secret://email-password

SERVICENOW_ENABLED=true
SERVICENOW_INSTANCE=company.service-now.com
SERVICENOW_USERNAME=svc-ladon
SERVICENOW_PASSWORD=secret://servicenow-password
```

## Deployment

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run service
python src/main.py
```

### Docker

```bash
# Build image
docker build -t response-service:latest .

# Run container
docker run -p 8080:8080 \
  -e GCP_PROJECT_ID=ladon-dev \
  -e DETECTION_TOPIC=detection-events \
  response-service:latest
```

### Kubernetes

```bash
# Deploy to dev
kubectl apply -k k8s/overlays/dev/

# Deploy to production
kubectl apply -k k8s/overlays/production/

# Check deployment
kubectl get pods -n ladon -l app=response-service
kubectl logs -n ladon -l app=response-service -f
```

## Testing

### Unit Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest --cov=src --cov-report=html tests/

# Run specific test
pytest tests/test_response_engine.py::test_block_ip
```

### Integration Tests

```bash
# Test with mock executors
pytest tests/integration/

# Test with real APIs (requires credentials)
INTEGRATION_TEST=true pytest tests/integration/
```

## Monitoring

### Metrics

The service exposes Prometheus metrics:

```
# Action metrics
response_actions_total{status="completed"} 150
response_actions_total{status="failed"} 5
response_actions_total{status="pending"} 3

# Action execution time
response_action_duration_seconds{action_type="block_ip",quantile="0.95"} 0.8

# Playbook metrics
response_playbooks_triggered_total{playbook_id="playbook_block_ip"} 25

# Executor metrics
response_executor_calls_total{executor="firewall",success="true"} 100
response_executor_calls_total{executor="edr",success="false"} 2
```

### Logging

Structured JSON logs:

```json
{
  "timestamp": "2026-01-09T12:00:00Z",
  "severity": "INFO",
  "service": "response",
  "message": "Action executed successfully",
  "action_id": "act_abc123def456",
  "action_type": "block_ip",
  "detection_id": "det_xyz789",
  "executor": "firewall",
  "duration_ms": 850,
  "success": true
}
```

## Security Considerations

### Credentials Management
- Store all credentials in Google Secret Manager
- Never commit secrets to git
- Use Workload Identity for GCP access
- Rotate credentials regularly

### Audit Logging
- All actions logged with full context
- 7-year retention for compliance
- Immutable audit trail in BigQuery

### Rate Limiting
- Prevent action storms from runaway automation
- Max 100 actions per minute per playbook
- Circuit breakers for external APIs

### Approval Requirements
- High-impact actions require manual approval
- Multi-level approval hierarchy
- Approval bypass only for critical threats

## Troubleshooting

### Action Stuck in Pending

```bash
# Check action status
curl http://localhost:8080/actions/act_abc123

# Manually approve if needed
curl -X POST http://localhost:8080/actions/act_abc123/approve \
  -H "Content-Type: application/json" \
  -d '{"approver": "admin@company.com"}'
```

### Executor Failing

```bash
# Check executor logs
kubectl logs -n ladon -l app=response-service | grep executor

# Test executor connectivity
python -c "
from action_executors.firewall import FirewallExecutor
executor = FirewallExecutor(config)
# Test connection
"
```

### Rollback Action

```bash
# Rollback a completed action
curl -X POST http://localhost:8080/actions/act_abc123/rollback
```

## Development

### Adding a New Action Type

1. Add action type to `models.py`:
   ```python
   class ResponseActionType(str, Enum):
       NEW_ACTION = "new_action"
   ```

2. Create executor method:
   ```python
   async def _new_action(self, action: ResponseAction) -> ResponseExecutionResult:
       # Implementation
   ```

3. Add routing in `response_engine.py`:
   ```python
   elif action.action_type == ResponseActionType.NEW_ACTION:
       return await self.custom_executor.execute(action)
   ```

4. Add tests:
   ```python
   def test_new_action():
       # Test implementation
   ```

### Adding a New Platform

1. Create executor class in `action_executors/`:
   ```python
   class NewPlatformExecutor:
       async def execute(self, action: ResponseAction):
           # Implementation
   ```

2. Initialize in `main.py`:
   ```python
   new_platform_executor = NewPlatformExecutor(config)
   ```

3. Add platform-specific configuration

4. Update documentation

## References

- [Architecture Diagrams](../../docs/ARCHITECTURE_DIAGRAMS.md)
- [Project Plan](../../docs/ladon_project_plan.md)
- [CLAUDE.md](../../CLAUDE.md)

## License

Copyright © 2026 LADON Platform
