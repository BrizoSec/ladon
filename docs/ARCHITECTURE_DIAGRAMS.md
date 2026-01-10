# LADON Threat XDR - Architecture Diagrams

This document provides comprehensive diagrams of the LADON Threat XDR platform architecture, with detailed focus on the Collection Service.

## Table of Contents
- [Overall System Architecture](#overall-system-architecture)
- [Lambda Architecture Pattern](#lambda-architecture-pattern)
- [Collection Service Architecture](#collection-service-architecture)
- [Data Flow Diagrams](#data-flow-diagrams)
- [Kubernetes Deployment Architecture](#kubernetes-deployment-architecture)
- [Service Communication Patterns](#service-communication-patterns)

---

## Overall System Architecture

```mermaid
graph TB
    subgraph "External Threat Intelligence Feeds"
        AV[AlienVault OTX]
        AC[abuse.ch]
        MISP[MISP]
    end

    subgraph "Activity Log Sources"
        TRINO[Trino Proxy/DNS]
        BQ_MDE[BigQuery MDE]
        BQ_CS[BigQuery CrowdStrike]
        BQ_SINK[BigQuery Sinkhole]
    end

    subgraph "Collection Service (GKE)"
        CS[Collection Service]
        subgraph "IOC Collectors"
            AV_COL[AlienVault Collector]
            AC_COL[abuse.ch Collector]
            MISP_COL[MISP Collector]
        end
        subgraph "Activity Collectors"
            TRINO_COL[Trino Collector]
            BQ_COL[BigQuery Collector]
        end
        subgraph "Threat Extractors"
            TE[Threat Extractors]
        end
    end

    subgraph "Pub/Sub Topics"
        RAW_IOC[raw-ioc-events]
        RAW_ACT[raw-activity-events]
        RAW_THR[raw-threat-events]
        NORM_IOC[normalized-ioc-events]
        NORM_ACT[normalized-activity-events]
        NORM_THR[normalized-threat-events]
    end

    subgraph "Normalization Service (Cloud Run)"
        NS[Normalization Service]
    end

    subgraph "Storage Layer"
        STORAGE[Storage Service]
        BQ[(BigQuery)]
        REDIS[(Redis Cache)]
    end

    subgraph "Fast Path - Real-time Detection"
        DETECT[Detection Service]
        SCORE[Scoring Service]
        RESPONSE[Response Service]
        NOTIFY[Notification Service]
    end

    subgraph "Slow Path - Deep Analytics"
        BEACON[Beaconing Detection]
        DGA[DGA Detection]
        LATERAL[Lateral Movement]
        HUNT[Threat Hunting]
    end

    subgraph "External Systems"
        SNOW[ServiceNow]
        SLACK[Slack]
        VT[VirusTotal]
        PT[PassiveTotal]
    end

    subgraph "Response Targets"
        FW[Firewalls<br/>Palo Alto, FortiGate]
        EDR[EDR Platforms<br/>MDE, CrowdStrike]
        IAM[Identity Providers<br/>AD, Azure AD, Okta]
    end

    %% IOC Flow
    AV -->|API| AV_COL
    AC -->|API| AC_COL
    MISP -->|API| MISP_COL
    AV_COL -->|Publish| RAW_IOC
    AC_COL -->|Publish| RAW_IOC
    MISP_COL -->|Publish| RAW_IOC

    %% Activity Flow
    TRINO -->|SQL Query| TRINO_COL
    BQ_MDE -->|SQL Query| BQ_COL
    BQ_CS -->|SQL Query| BQ_COL
    BQ_SINK -->|SQL Query| BQ_COL
    TRINO_COL -->|Publish| RAW_ACT
    BQ_COL -->|Publish| RAW_ACT

    %% Threat Flow
    AV_COL --> TE
    AC_COL --> TE
    MISP_COL --> TE
    TE -->|Publish| RAW_THR

    %% Normalization
    RAW_IOC -->|Subscribe| NS
    RAW_ACT -->|Subscribe| NS
    RAW_THR -->|Subscribe| NS
    NS -->|Publish| NORM_IOC
    NS -->|Publish| NORM_ACT
    NS -->|Publish| NORM_THR

    %% Storage
    NORM_IOC -->|Subscribe| STORAGE
    NORM_ACT -->|Subscribe| STORAGE
    NORM_THR -->|Subscribe| STORAGE
    STORAGE -->|Write| BQ
    STORAGE -->|Cache Hot IOCs| REDIS

    %% Fast Path
    NORM_ACT -->|Subscribe| DETECT
    DETECT <-->|Read Hot IOCs| REDIS
    DETECT -->|Detections| SCORE
    SCORE -->|Scored Detections| RESPONSE
    RESPONSE -->|Block IP/Domain| FW
    RESPONSE -->|Isolate Host, Quarantine File| EDR
    RESPONSE -->|Disable User, Revoke Sessions| IAM
    RESPONSE -->|Notifications| NOTIFY
    NOTIFY -->|Create Cases| SNOW
    NOTIFY -->|Alerts| SLACK

    %% Slow Path
    BQ -->|Daily Jobs| BEACON
    BQ -->|Daily Jobs| DGA
    BQ -->|Daily Jobs| LATERAL
    BQ -->|Ad-hoc Queries| HUNT

    %% Enrichment
    DETECT -.->|Enrich| VT
    DETECT -.->|Enrich| PT

    style CS fill:#e1f5ff
    style STORAGE fill:#fff4e1
    style DETECT fill:#ffe1e1
    style RESPONSE fill:#ffe1f5
    style BQ fill:#e1ffe1
    style REDIS fill:#ffe1f5
```

---

## Lambda Architecture Pattern

```mermaid
graph LR
    subgraph "Data Sources"
        FEEDS[Threat Feeds]
        LOGS[Activity Logs]
    end

    subgraph "Ingestion Layer"
        COLLECT[Collection Service]
    end

    subgraph "Fast Path - Real-time <5 min"
        CACHE[(Redis Cache<br/>Hot IOCs)]
        DETECT[Detection Engine]
        ALERT[Alerting]
    end

    subgraph "Slow Path - Batch Analytics"
        DWH[(BigQuery<br/>Data Warehouse)]
        ANALYTICS[Analytics Jobs]
        HUNT[Threat Hunting]
    end

    subgraph "Serving Layer"
        API[API Gateway]
        UI[Web UI]
    end

    FEEDS --> COLLECT
    LOGS --> COLLECT
    COLLECT -->|Streaming| CACHE
    COLLECT -->|Streaming| DWH

    CACHE --> DETECT
    DETECT --> ALERT
    ALERT --> API

    DWH --> ANALYTICS
    DWH --> HUNT
    ANALYTICS --> API
    HUNT --> API

    API --> UI

    style CACHE fill:#ffe1e1
    style DWH fill:#e1ffe1
    style DETECT fill:#ffe1e1
    style ANALYTICS fill:#e1f5ff
```

**Key Characteristics:**

- **Fast Path**: Real-time IOC correlation with <5 minute latency
  - Uses Redis cache for hot IOCs (last 48 hours, confidence >0.7)
  - Processes 10M+ events/day
  - Target: <100ms detection latency per batch

- **Slow Path**: Deep behavioral analytics running daily/weekly
  - Beaconing detection, DGA analysis, lateral movement
  - Full historical data analysis in BigQuery
  - Complex queries across billions of records

---

## Collection Service Architecture

```mermaid
graph TB
    subgraph "Collection Service Pod"
        MAIN[main.py<br/>FastAPI Application]

        subgraph "IOC Collectors"
            AV_C[AlienVault Collector]
            AC_C[abuse.ch Collector]
            MISP_C[MISP Collector]
        end

        subgraph "Activity Collectors"
            TRINO_C[Trino Collector<br/>Proxy/DNS]
            BQ_C[BigQuery Collector<br/>MDE/CS/Sinkhole]
        end

        subgraph "Threat Extractors"
            BASE_TE[BaseThreatExtractor]
            AV_TE[AlienVault Extractor]
            AC_TE[abuse.ch Extractor]
            MISP_TE[MISP Extractor]
        end

        subgraph "Core Components"
            WM[Watermark Manager]
            PUB[Pub/Sub Publisher]
            CONFIG[Config Loader]
        end

        subgraph "Health & Metrics"
            HEALTH[/health endpoint]
            METRICS[/metrics endpoint<br/>Prometheus]
        end
    end

    subgraph "ConfigMap"
        CM_ENV[Environment Variables]
        CM_YAML[config.yaml]
    end

    subgraph "Secrets"
        API_KEYS[API Keys]
        GCP_SA[GCP Service Account]
    end

    subgraph "Firestore"
        WM_STORE[(Watermark Storage)]
    end

    subgraph "Pub/Sub"
        T1[raw-ioc-events]
        T2[raw-activity-events]
        T3[raw-threat-events]
    end

    %% Configuration
    CM_ENV --> CONFIG
    CM_YAML --> CONFIG
    API_KEYS --> CONFIG
    GCP_SA --> CONFIG

    CONFIG --> MAIN

    %% Main orchestration
    MAIN -->|Start Background Tasks| AV_C
    MAIN -->|Start Background Tasks| AC_C
    MAIN -->|Start Background Tasks| MISP_C
    MAIN -->|Start Background Tasks| TRINO_C
    MAIN -->|Start Background Tasks| BQ_C

    %% IOC Collection
    AV_C -->|Check Watermark| WM
    AC_C -->|Check Watermark| WM
    MISP_C -->|Check Watermark| WM

    WM <-->|Read/Write| WM_STORE

    AV_C -->|Publish IOCs| PUB
    AC_C -->|Publish IOCs| PUB
    MISP_C -->|Publish IOCs| PUB

    %% Threat Extraction
    AV_C -->|Raw Data| AV_TE
    AC_C -->|Raw Data| AC_TE
    MISP_C -->|Raw Data| MISP_TE

    AV_TE -.->|Inherits| BASE_TE
    AC_TE -.->|Inherits| BASE_TE
    MISP_TE -.->|Inherits| BASE_TE

    AV_TE -->|Publish Threats| PUB
    AC_TE -->|Publish Threats| PUB
    MISP_TE -->|Publish Threats| PUB

    %% Activity Collection
    TRINO_C -->|Check Watermark| WM
    BQ_C -->|Check Watermark| WM
    TRINO_C -->|Publish Activities| PUB
    BQ_C -->|Publish Activities| PUB

    %% Publishing
    PUB --> T1
    PUB --> T2
    PUB --> T3

    %% Health
    MAIN --> HEALTH
    MAIN --> METRICS

    style MAIN fill:#e1f5ff
    style WM fill:#fff4e1
    style PUB fill:#ffe1e1
    style BASE_TE fill:#e1ffe1
```

### Component Details

**Collectors** (5 total):
- **AlienVault OTX**: Pulses API, 1-hour interval
- **abuse.ch**: Multiple feeds (URLhaus, ThreatFox, etc.), 1-hour interval
- **MISP**: Events API, 1-hour interval
- **Trino**: Proxy/DNS logs, 15-minute interval
- **BigQuery**: MDE/CrowdStrike/Sinkhole, 15-minute interval

**Threat Extractors** (3 total):
- Extract threat actors, campaigns, malware families
- Generate threat IDs and IOC associations
- Normalize threat data across different feed formats

**Watermark Manager**:
- Tracks last successful collection timestamp per source
- Stored in Firestore for persistence
- Enables incremental collection and failure recovery

---

## Data Flow Diagrams

### IOC Collection Flow

```mermaid
sequenceDiagram
    participant AV as AlienVault OTX API
    participant COL as Collection Service
    participant WM as Watermark Manager
    participant FS as Firestore
    participant TE as Threat Extractor
    participant PS as Pub/Sub
    participant NORM as Normalization Service
    participant STOR as Storage Service
    participant BQ as BigQuery
    participant REDIS as Redis Cache

    loop Every 1 hour
        COL->>WM: Get last watermark
        WM->>FS: Read watermark
        FS-->>WM: Return timestamp
        WM-->>COL: Last collection: 2026-01-09T10:00:00Z

        COL->>AV: GET /api/v1/pulses/subscribed?modified_since=2026-01-09T10:00:00Z
        AV-->>COL: Return 50 new pulses

        COL->>TE: Extract threats from pulses
        TE-->>COL: Return normalized threats

        par Publish Events
            COL->>PS: Publish to raw-ioc-events (150 IOCs)
        and Publish Threats
            COL->>PS: Publish to raw-threat-events (5 threats)
        end

        COL->>WM: Update watermark to 2026-01-09T11:00:00Z
        WM->>FS: Write new watermark

        PS-->>NORM: Subscribe to raw-ioc-events
        NORM->>NORM: Normalize IOCs
        NORM->>PS: Publish to normalized-ioc-events

        PS-->>STOR: Subscribe to normalized-ioc-events
        STOR->>BQ: MERGE into iocs table
        STOR->>REDIS: Cache if hot (last 48h, confidence >0.7)
    end
```

### Activity Collection Flow

```mermaid
sequenceDiagram
    participant TRINO as Trino (Proxy Logs)
    participant COL as Collection Service
    participant WM as Watermark Manager
    participant FS as Firestore
    participant PS as Pub/Sub
    participant NORM as Normalization Service
    participant STOR as Storage Service
    participant BQ as BigQuery
    participant DET as Detection Service
    participant REDIS as Redis Cache

    loop Every 15 minutes
        COL->>WM: Get last watermark
        WM->>FS: Read watermark
        FS-->>WM: Return timestamp
        WM-->>COL: Last collection: 2026-01-09T10:45:00Z

        COL->>TRINO: SELECT * FROM proxy_logs WHERE timestamp > '2026-01-09T10:45:00Z' LIMIT 100000
        TRINO-->>COL: Return 50,000 proxy events

        COL->>PS: Publish to raw-activity-events (batches of 1000)

        COL->>WM: Update watermark to 2026-01-09T11:00:00Z
        WM->>FS: Write new watermark

        PS-->>NORM: Subscribe to raw-activity-events
        NORM->>NORM: Normalize activities
        NORM->>PS: Publish to normalized-activity-events

        par Storage Path
            PS-->>STOR: Subscribe to normalized-activity-events
            STOR->>BQ: Insert into activity_logs table
        and Detection Path
            PS-->>DET: Subscribe to normalized-activity-events
            DET->>REDIS: Check domain/IP against IOC cache
            alt IOC Match Found
                REDIS-->>DET: Return matching IOC
                DET->>PS: Publish to detection-events
            else No Match
                DET->>DET: Discard (no detection)
            end
        end
    end
```

### Real-time Detection Flow

```mermaid
sequenceDiagram
    participant ACT as Activity Event
    participant DET as Detection Service
    participant REDIS as Redis Cache
    participant ENR as Enrichment Service
    participant VT as VirusTotal API
    participant SCORE as Scoring Service
    participant RESP as Response Service
    participant FW as Firewall
    participant EDR as EDR Platform
    participant NOTIFY as Notification Service
    participant SNOW as ServiceNow
    participant SLACK as Slack

    ACT->>DET: Normalized activity event
    Note over ACT,DET: domain: evil.example.com<br/>src_ip: 10.1.2.3<br/>user: john.doe

    DET->>REDIS: GET ioc:domain:evil.example.com
    REDIS-->>DET: Found IOC (confidence: 0.85, type: c2)

    DET->>DET: Create detection event

    DET->>ENR: Enrich detection
    ENR->>VT: Get domain report
    VT-->>ENR: Return reputation data
    ENR->>ENR: Lookup user/asset in CMDB
    ENR-->>DET: Enrichment data

    DET->>SCORE: Calculate severity score
    Note over SCORE: base_score = 0.85 * 100 = 85<br/>threat_type: c2 (1.5x)<br/>asset_criticality: high (1.3x)<br/>final_score = 85 * 1.5 * 1.3 = 165
    SCORE-->>DET: CRITICAL (score: 165)

    DET->>RESP: Send detection for response
    RESP->>RESP: Match detection to playbooks
    Note over RESP: Playbook: "Block Malicious IP"<br/>Actions: block_ip, notify_slack

    alt Auto-Approved Actions
        RESP->>FW: Block IP 10.1.2.3 on firewalls
        FW-->>RESP: IP blocked (rule: deny-10.1.2.3)
        RESP->>RESP: Action completed
    else Manual Approval Required
        RESP->>RESP: Queue action for SOC approval
        Note over RESP: Action: isolate_host<br/>Status: Pending approval
    end

    RESP->>NOTIFY: Send notification with action results

    par Create ServiceNow Case
        NOTIFY->>SNOW: Create incident
        SNOW-->>NOTIFY: Case INC0012345
    and Send Slack Alert
        NOTIFY->>SLACK: Send message to #security-alerts<br/>"IP 10.1.2.3 blocked automatically"
        SLACK-->>NOTIFY: Message sent
    end

    NOTIFY-->>RESP: Notification sent

    Note over ACT,SLACK: Total time: <2 minutes (with auto-response)
```

### Response Service Architecture

```mermaid
graph TB
    subgraph "Response Service"
        MAIN[main.py<br/>FastAPI Application]

        subgraph "Core Components"
            ENGINE[Response Engine]
            PLAYBOOK_MATCHER[Playbook Matcher]
            APPROVAL[Approval Workflow]
        end

        subgraph "Action Executors"
            FW_EXEC[Firewall Executor]
            EDR_EXEC[EDR Executor]
            IAM_EXEC[Identity Executor]
            NOTIF_EXEC[Notification Executor]
        end

        subgraph "Playbook Storage"
            PLAYBOOKS[(Registered Playbooks)]
        end

        subgraph "Action History"
            ACTIONS[(Action Tracking)]
        end

        subgraph "Health & Metrics"
            HEALTH[/health endpoint]
            METRICS[/metrics endpoint]
            API[REST API<br/>approve, reject, rollback]
        end
    end

    subgraph "Input - Detection Events"
        PS_DET[detection-events<br/>Pub/Sub Topic]
    end

    subgraph "External Systems - Firewalls"
        PALO[Palo Alto PAN-OS]
        FORTI[Fortinet FortiGate]
        GCP_FW[GCP Firewall Rules]
    end

    subgraph "External Systems - EDR"
        MDE[Microsoft Defender]
        CS[CrowdStrike]
    end

    subgraph "External Systems - Identity"
        AD[Active Directory]
        AZURE_AD[Azure AD]
        OKTA[Okta]
    end

    subgraph "Notifications"
        SLACK_N[Slack]
        EMAIL[Email]
        SNOW_N[ServiceNow]
    end

    %% Detection Input
    PS_DET -->|Subscribe| MAIN
    MAIN --> ENGINE

    %% Playbook Matching
    ENGINE --> PLAYBOOK_MATCHER
    PLAYBOOK_MATCHER <--> PLAYBOOKS
    PLAYBOOK_MATCHER --> ENGINE

    %% Approval Workflow
    ENGINE --> APPROVAL
    APPROVAL -->|Auto-Approved| ENGINE
    APPROVAL -->|Pending| API
    API -->|Approve/Reject| APPROVAL
    APPROVAL -->|Approved| ENGINE

    %% Action Execution
    ENGINE --> FW_EXEC
    ENGINE --> EDR_EXEC
    ENGINE --> IAM_EXEC
    ENGINE --> NOTIF_EXEC

    %% Firewall Actions
    FW_EXEC -->|Block IP/Domain| PALO
    FW_EXEC -->|Block IP/Domain| FORTI
    FW_EXEC -->|Create Rules| GCP_FW

    %% EDR Actions
    EDR_EXEC -->|Isolate Host| MDE
    EDR_EXEC -->|Isolate Host| CS
    EDR_EXEC -->|Quarantine File| MDE
    EDR_EXEC -->|Kill Process| CS

    %% Identity Actions
    IAM_EXEC -->|Disable User| AD
    IAM_EXEC -->|Disable User| AZURE_AD
    IAM_EXEC -->|Suspend User| OKTA
    IAM_EXEC -->|Revoke Sessions| AZURE_AD

    %% Notifications
    NOTIF_EXEC --> SLACK_N
    NOTIF_EXEC --> EMAIL
    NOTIF_EXEC --> SNOW_N

    %% Action Tracking
    ENGINE -->|Record Actions| ACTIONS
    ACTIONS -->|Query Status| API

    %% Health
    MAIN --> HEALTH
    MAIN --> METRICS

    style ENGINE fill:#ffe1e1
    style PLAYBOOK_MATCHER fill:#e1f5ff
    style APPROVAL fill:#fff4e1
    style FW_EXEC fill:#e1ffe1
    style EDR_EXEC fill:#e1ffe1
    style IAM_EXEC fill:#e1ffe1
    style NOTIF_EXEC fill:#e1ffe1
```

**Response Playbook Example:**

```yaml
playbook_id: "playbook_block_malicious_ip"
name: "Block Malicious IP"
description: "Auto-block IPs associated with C2, malware, or ransomware"

trigger_conditions:
  severity: [CRITICAL, HIGH]
  threat_types: [c2, malware, ransomware]
  ioc_types: [ip]

actions:
  - action_type: block_ip
    parameters:
      duration_hours: 24
      firewall_targets: [palo_alto, gcp_firewall]
      direction: both
    approval_required: none  # Auto-execute

  - action_type: notify_slack
    parameters:
      channel: "#security-alerts"
      message: "Malicious IP blocked automatically"
    approval_required: none

enabled: true
auto_approve: true
```

**Approval Workflow:**

```mermaid
stateDiagram-v2
    [*] --> Pending: Action Created

    Pending --> Approved: SOC Analyst Approves
    Pending --> Rejected: SOC Analyst Rejects

    Approved --> InProgress: Execute Action
    InProgress --> Completed: Success
    InProgress --> Failed: Error

    Completed --> RolledBack: Manual Rollback

    Rejected --> [*]
    Failed --> [*]
    RolledBack --> [*]
    Completed --> [*]
```

**Supported Response Actions:**

| Category | Action | Description | Approval Level |
|----------|--------|-------------|----------------|
| Network | `block_ip` | Block IP address on firewalls | Auto / None |
| Network | `block_domain` | Block domain via DNS/URL filtering | Auto / None |
| Network | `block_url` | Block specific URL | Auto / None |
| Endpoint | `isolate_host` | Network isolate endpoint | SOC Lead |
| Endpoint | `quarantine_file` | Quarantine malicious file | SOC Analyst |
| Endpoint | `kill_process` | Terminate running process | SOC Analyst |
| Endpoint | `collect_forensics` | Collect memory/disk forensics | SOC Lead |
| Identity | `disable_user` | Disable user account | SOC Analyst |
| Identity | `reset_password` | Force password reset | SOC Analyst |
| Identity | `revoke_session` | Invalidate active sessions | Auto / None |
| Investigation | `capture_memory` | Capture memory dump | SOC Lead |
| Investigation | `capture_network` | Capture network traffic | SOC Analyst |
| Notification | `notify_slack` | Send Slack alert | Auto / None |
| Notification | `notify_email` | Send email notification | Auto / None |
| Notification | `create_ticket` | Create ServiceNow ticket | Auto / None |

---

## Kubernetes Deployment Architecture

```mermaid
graph TB
    subgraph "GKE Cluster"
        subgraph "ladon Namespace"
            subgraph "collection-service Deployment"
                POD1[Pod 1<br/>collection-service]
                POD2[Pod 2<br/>collection-service]
                POD3[Pod 3<br/>collection-service]
            end

            SVC[Service<br/>collection-service<br/>ClusterIP]

            CM1[ConfigMap<br/>collection-config]
            CM2[ConfigMap<br/>collection-config-yaml]
            SECRET[Secret<br/>collection-secrets]

            SA[ServiceAccount<br/>collection-service]
            HPA[HPA<br/>2-10 replicas]
            PDB[PodDisruptionBudget<br/>minAvailable: 1]
            NP[NetworkPolicy]
            SM[ServiceMonitor<br/>Prometheus]
        end

        subgraph "Monitoring"
            PROM[Prometheus]
            GRAF[Grafana]
        end

        subgraph "kube-system"
            DNS[CoreDNS]
            INGRESS[Ingress Controller]
        end
    end

    subgraph "GCP Services"
        PUBSUB[Cloud Pub/Sub]
        FIRESTORE[Firestore]
        GCS[Cloud Storage]
        SECRETMGR[Secret Manager]
        WORKLOAD[Workload Identity]
        GSA[GCP Service Account<br/>collection-sa]
    end

    subgraph "External APIs"
        AV[AlienVault OTX]
        AC[abuse.ch]
        MISP_EXT[MISP]
        TRINO_EXT[Trino]
        BQ_EXT[BigQuery]
    end

    %% Configuration
    CM1 --> POD1
    CM1 --> POD2
    CM1 --> POD3
    CM2 --> POD1
    CM2 --> POD2
    CM2 --> POD3
    SECRET --> POD1
    SECRET --> POD2
    SECRET --> POD3

    %% Service Account
    SA --> POD1
    SA --> POD2
    SA --> POD3
    SA -->|Workload Identity| WORKLOAD
    WORKLOAD --> GSA

    %% Service
    SVC --> POD1
    SVC --> POD2
    SVC --> POD3

    %% HPA
    HPA -.->|Scale| POD1
    HPA -.->|Scale| POD2
    HPA -.->|Scale| POD3

    %% Monitoring
    SM --> POD1
    SM --> POD2
    SM --> POD3
    PROM -->|Scrape| SM
    GRAF -->|Query| PROM

    %% GCP Access
    POD1 -->|Publish| PUBSUB
    POD2 -->|Publish| PUBSUB
    POD3 -->|Publish| PUBSUB
    POD1 -->|Read/Write| FIRESTORE
    POD2 -->|Read/Write| FIRESTORE
    POD3 -->|Read/Write| FIRESTORE

    %% External APIs
    POD1 -->|Collect| AV
    POD1 -->|Collect| AC
    POD1 -->|Collect| MISP_EXT
    POD2 -->|Collect| TRINO_EXT
    POD3 -->|Collect| BQ_EXT

    %% Network Policy
    NP -.->|Allow Egress| POD1
    NP -.->|Allow Egress| POD2
    NP -.->|Allow Egress| POD3

    style POD1 fill:#e1f5ff
    style POD2 fill:#e1f5ff
    style POD3 fill:#e1f5ff
    style SVC fill:#fff4e1
    style HPA fill:#ffe1e1
    style SA fill:#e1ffe1
```

### Kubernetes Resource Hierarchy

```mermaid
graph TB
    NS[Namespace: ladon]

    NS --> SA[ServiceAccount<br/>collection-service]
    NS --> ROLE[Role<br/>collection-role]
    NS --> RB[RoleBinding<br/>collection-rolebinding]

    NS --> CM1[ConfigMap<br/>collection-config<br/>Environment Variables]
    NS --> CM2[ConfigMap<br/>collection-config-yaml<br/>config.yaml File]
    NS --> SECRET[Secret<br/>collection-secrets<br/>API Keys]

    NS --> DEPLOY[Deployment<br/>collection-service]
    NS --> SVC[Service<br/>collection-service]
    NS --> HPA[HPA<br/>collection-service-hpa]
    NS --> PDB[PodDisruptionBudget<br/>collection-service-pdb]
    NS --> NP[NetworkPolicy<br/>collection-service-netpol]
    NS --> SM[ServiceMonitor<br/>collection-service]

    DEPLOY --> RS[ReplicaSet]
    RS --> POD1[Pod 1]
    RS --> POD2[Pod 2]
    RS --> POD3[Pod 3]

    SA -.->|Used by| POD1
    SA -.->|Used by| POD2
    SA -.->|Used by| POD3

    CM1 -.->|Env Vars| POD1
    CM1 -.->|Env Vars| POD2
    CM1 -.->|Env Vars| POD3

    CM2 -.->|Volume Mount| POD1
    CM2 -.->|Volume Mount| POD2
    CM2 -.->|Volume Mount| POD3

    SECRET -.->|Env Vars| POD1
    SECRET -.->|Env Vars| POD2
    SECRET -.->|Env Vars| POD3

    HPA -.->|Controls| RS
    PDB -.->|Protects| POD1
    PDB -.->|Protects| POD2
    PDB -.->|Protects| POD3

    NP -.->|Governs| POD1
    NP -.->|Governs| POD2
    NP -.->|Governs| POD3

    style NS fill:#e1f5ff
    style DEPLOY fill:#fff4e1
    style POD1 fill:#ffe1e1
    style POD2 fill:#ffe1e1
    style POD3 fill:#ffe1e1
```

---

## Service Communication Patterns

### Async Messaging (Primary Pattern)

```mermaid
graph LR
    subgraph "Publisher Services"
        COLLECT[Collection Service]
        NORM[Normalization Service]
    end

    subgraph "Cloud Pub/Sub"
        T1[raw-ioc-events<br/>Push Subscription]
        T2[raw-activity-events<br/>Pull Subscription]
        T3[normalized-ioc-events<br/>Pull Subscription]
        DLQ[dead-letter-queue<br/>Failed Messages]
    end

    subgraph "Subscriber Services"
        NORM2[Normalization Service]
        STORAGE[Storage Service]
        DETECT[Detection Service]
    end

    COLLECT -->|Publish| T1
    COLLECT -->|Publish| T2

    T1 -->|Push| NORM2
    T2 -->|Pull| NORM2

    NORM -->|Publish| T3
    T3 -->|Pull| STORAGE
    T3 -->|Pull| DETECT

    T1 -.->|Max retries| DLQ
    T2 -.->|Max retries| DLQ
    T3 -.->|Max retries| DLQ

    style T1 fill:#ffe1e1
    style T2 fill:#ffe1e1
    style T3 fill:#e1ffe1
    style DLQ fill:#fff4e1
```

**Key Characteristics:**
- **Decoupling**: Services don't need to know about each other
- **Reliability**: Messages persisted, auto-retry on failure
- **Scalability**: Subscribers can scale independently
- **Dead Letter Queue**: Failed messages after max retries

### Sync API Calls (Secondary Pattern)

```mermaid
graph LR
    subgraph "Detection Service"
        DET[Detection Logic]
        CB[Circuit Breaker]
        RL[Rate Limiter]
    end

    subgraph "External APIs"
        VT[VirusTotal<br/>4 req/min]
        PT[PassiveTotal<br/>60 req/min]
        OTX[AlienVault OTX<br/>10 req/min]
    end

    subgraph "Caching Layer"
        REDIS[(Redis<br/>7-day TTL)]
    end

    DET -->|Check Cache| REDIS
    REDIS -.->|Cache Miss| DET

    DET --> RL
    RL --> CB

    CB -->|API Call| VT
    CB -->|API Call| PT
    CB -->|API Call| OTX

    VT -.->|Response| CB
    PT -.->|Response| CB
    OTX -.->|Response| CB

    CB -.->|Cache Result| REDIS

    style CB fill:#ffe1e1
    style RL fill:#fff4e1
    style REDIS fill:#e1ffe1
```

**Key Characteristics:**
- **Circuit Breaker**: Prevents cascading failures (5 failures → 60s timeout)
- **Rate Limiting**: Respects API quotas
- **Caching**: 7-day TTL for enrichment data
- **Exponential Backoff**: Retry with increasing delays

---

## Collection Service Internal Flow

```mermaid
stateDiagram-v2
    [*] --> Starting
    Starting --> LoadConfig: Load config.yaml + env vars
    LoadConfig --> InitClients: Initialize Pub/Sub, Firestore
    InitClients --> StartCollectors: Start background tasks

    state StartCollectors {
        [*] --> AlienVault
        [*] --> AbuseChannel
        [*] --> MISP
        [*] --> Trino
        [*] --> BigQuery
    }

    StartCollectors --> Running

    state Running {
        [*] --> CheckWatermark
        CheckWatermark --> FetchData: Get last timestamp
        FetchData --> ProcessData: Query external source
        ProcessData --> ExtractThreats: Parse response
        ExtractThreats --> PublishEvents: Normalize data
        PublishEvents --> UpdateWatermark: Send to Pub/Sub
        UpdateWatermark --> Sleep: Save timestamp
        Sleep --> CheckWatermark: Wait interval
    }

    Running --> HealthCheck: /health endpoint
    HealthCheck --> Running

    Running --> Metrics: /metrics endpoint
    Metrics --> Running

    Running --> Shutdown: SIGTERM received
    Shutdown --> GracefulStop: Stop accepting requests
    GracefulStop --> DrainTasks: Wait 30s for tasks
    DrainTasks --> [*]
```

---

## Monitoring & Observability

### Metrics Collection Flow

```mermaid
graph TB
    subgraph "Collection Service Pods"
        POD1[Pod 1<br/>/metrics endpoint]
        POD2[Pod 2<br/>/metrics endpoint]
        POD3[Pod 3<br/>/metrics endpoint]
    end

    subgraph "Prometheus"
        PROM[Prometheus Server]
        subgraph "Service Monitors"
            SM[ServiceMonitor<br/>collection-service]
        end
    end

    subgraph "Grafana"
        DASH1[Collection Dashboard]
        DASH2[Detection Dashboard]
        DASH3[System Overview]
    end

    subgraph "Alertmanager"
        AM[Alertmanager]
        subgraph "Alert Rules"
            R1[High Error Rate]
            R2[Low Collection Rate]
            R3[High Memory Usage]
        end
    end

    subgraph "Notification Channels"
        SLACK2[Slack #ops-alerts]
        PAGE[PagerDuty]
        EMAIL[Email]
    end

    SM -->|Scrape every 30s| POD1
    SM -->|Scrape every 30s| POD2
    SM -->|Scrape every 30s| POD3

    POD1 -.->|collection_events_total<br/>collection_errors_total<br/>collection_latency_seconds| PROM
    POD2 -.->|Metrics| PROM
    POD3 -.->|Metrics| PROM

    PROM -->|PromQL Queries| DASH1
    PROM -->|PromQL Queries| DASH2
    PROM -->|PromQL Queries| DASH3

    PROM -->|Evaluate Rules| R1
    PROM -->|Evaluate Rules| R2
    PROM -->|Evaluate Rules| R3

    R1 --> AM
    R2 --> AM
    R3 --> AM

    AM -->|Critical| PAGE
    AM -->|Warning| SLACK2
    AM -->|Info| EMAIL

    style PROM fill:#ffe1e1
    style AM fill:#fff4e1
```

### Key Metrics

**Collection Metrics:**
- `collection_events_total` - Total events collected per source
- `collection_errors_total` - Errors during collection
- `collection_latency_seconds` - Time to complete collection cycle
- `watermark_lag_seconds` - Time between current time and last watermark

**Resource Metrics:**
- `container_cpu_usage_seconds_total` - CPU usage
- `container_memory_working_set_bytes` - Memory usage
- `process_resident_memory_bytes` - Process memory

**Pub/Sub Metrics:**
- `pubsub_publish_latency_seconds` - Time to publish messages
- `pubsub_publish_errors_total` - Failed publishes
- `pubsub_message_size_bytes` - Message size distribution

---

## Deployment Environments

```mermaid
graph TB
    subgraph "Development"
        DEV_CLUSTER[GKE Cluster: dev]
        subgraph "dev overlay"
            DEV_NS[Namespace: ladon-dev]
            DEV_DEPLOY[Deployment: dev-collection-service<br/>1 replica<br/>250m CPU, 512Mi RAM]
            DEV_CONFIG[ConfigMap with DEBUG logs<br/>Mock Pub/Sub]
        end
    end

    subgraph "Staging"
        STG_CLUSTER[GKE Cluster: staging]
        subgraph "staging overlay"
            STG_NS[Namespace: ladon-staging]
            STG_DEPLOY[Deployment: staging-collection-service<br/>2 replicas<br/>1000m CPU, 2Gi RAM]
            STG_CONFIG[ConfigMap with INFO logs<br/>Real Pub/Sub]
        end
    end

    subgraph "Production"
        PROD_CLUSTER[GKE Cluster: production]
        subgraph "production overlay"
            PROD_NS[Namespace: ladon]
            PROD_DEPLOY[Deployment: prod-collection-service<br/>3-10 replicas HPA<br/>1500m CPU, 3Gi RAM]
            PROD_CONFIG[ConfigMap with INFO logs<br/>Real Pub/Sub<br/>Node Affinity]
        end
    end

    CODE[Git Repository] -->|kubectl apply -k overlays/dev| DEV_CLUSTER
    CODE -->|kubectl apply -k overlays/staging| STG_CLUSTER
    CODE -->|kubectl apply -k overlays/production| PROD_CLUSTER

    style DEV_DEPLOY fill:#e1f5ff
    style STG_DEPLOY fill:#fff4e1
    style PROD_DEPLOY fill:#ffe1e1
```

---

## Summary

This architecture provides:

1. **Scalability**: Horizontal pod autoscaling, Cloud Pub/Sub decoupling
2. **Reliability**: Pod disruption budgets, health checks, graceful shutdown
3. **Security**: RBAC, Workload Identity, network policies, secret management
4. **Observability**: Prometheus metrics, structured logging, distributed tracing
5. **Maintainability**: Kustomize overlays, GitOps workflows, declarative configuration

**Key Performance Targets:**
- Detection Latency: <5 minutes (p95)
- Throughput: 10M+ events/day
- Uptime: 99.9%
- False Positive Rate: <5% for high-severity alerts
