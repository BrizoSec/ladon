# Threat XDR Platform - Project Plan

**Version:** 1.0  
**Date:** January 1, 2026  
**Project Owner:** Chase (VP, Goldman Sachs Technology Risk Division)  
**Duration:** 18 months (MVP in 6 months)

---

## Executive Summary

Threat XDR is an enterprise threat detection and response platform that correlates Indicators of Compromise (IOCs) from multiple open-source feeds against organizational activity logs (Proxy, DNS, Sinkhole, MDE, CrowdStrike) to identify potential security incidents. The platform uses a Lambda architecture with fast-path real-time detection (3-minute SLA) and slow-path deep analytics for behavioral threat hunting.

**Key Objectives:**
- Reduce mean time to detect (MTTD) from days to <5 minutes for known IOCs
- Enable proactive threat hunting with ad-hoc query capabilities
- Provide automated case management integration with ServiceNow
- Scale to process millions of events/day across 5 data sources

**Success Metrics:**
- Process 10M+ events/day with <5 min detection latency
- <5% false positive rate on high-severity alerts
- 90% automated IOC enrichment coverage
- 99.9% platform uptime

---

## Table of Contents

1. [Project Phases & Timeline](#project-phases--timeline)
2. [Phase 1: MVP - Core Detection (Months 1-6)](#phase-1-mvp---core-detection-months-1-6)
3. [Phase 2: Intelligence & Analytics (Months 7-10)](#phase-2-intelligence--analytics-months-7-10)
4. [Phase 3: Operations & Scale (Months 11-14)](#phase-3-operations--scale-months-11-14)
5. [Phase 4: Advanced Features (Months 15-18)](#phase-4-advanced-features-months-15-18)
6. [Detailed Service Specifications](#detailed-service-specifications)
7. [Technology Stack](#technology-stack)
8. [Risk Register](#risk-register)
9. [Dependencies & Prerequisites](#dependencies--prerequisites)
10. [Success Criteria by Phase](#success-criteria-by-phase)

---

## Project Phases & Timeline

```
Month 1-6:   Phase 1 - MVP (Core Detection)
Month 7-10:  Phase 2 - Intelligence & Analytics
Month 11-14: Phase 3 - Operations & Scale
Month 15-18: Phase 4 - Advanced Features
```

**Milestones:**
- **M1 (Month 2):** Infrastructure provisioned, dev environment ready
- **M2 (Month 4):** MVP internal alpha with single data source
- **M3 (Month 6):** MVP production release with all 5 data sources
- **M4 (Month 10):** Full analytics suite operational
- **M5 (Month 14):** Production-hardened, auto-scaling enabled
- **M6 (Month 18):** V1.0 complete with ML capabilities

---

## Phase 1: MVP - Core Detection (Months 1-6)

**Goal:** Build minimal viable platform that detects known IOCs in real-time and creates ServiceNow cases.

### Services to Build (8 services)

#### 1. API Gateway Service
**Purpose:** Single entry point for all client requests, handles routing, rate limiting, and initial request validation.

**Tech Stack:**
- **GCP:** Cloud Endpoints + Cloud Armor (DDoS protection)
- **AWS:** API Gateway + WAF
- **Open Source Alternative:** Kong or Envoy

**Features:**
- Request routing to backend services
- Rate limiting (per API key: 1000 req/min)
- Request/response logging
- CORS handling
- API versioning (/v1, /v2)

**API Endpoints:**
```
POST   /v1/ioc/submit
GET    /v1/detections
POST   /v1/config/whitelist
GET    /v1/health
```

**Development:**
- **Week 1-2:** Infrastructure setup, OpenAPI spec
- **Week 3-4:** Implementation, rate limiting config
- **Week 5-6:** Testing, security review

**Risks:**
- **HIGH:** Rate limiting misconfiguration could allow abuse
- **MEDIUM:** API versioning strategy unclear - risk of breaking changes
- **MITIGATION:** Implement conservative rate limits initially, use semantic versioning

---

#### 2. Authentication & Authorization Service
**Purpose:** Manage user authentication, service-to-service auth, and RBAC policies.

**Tech Stack:**
- **Primary:** Cloud IAM (GCP/AWS) + OAuth 2.0
- **User Management:** Okta or Auth0 integration
- **Service-to-Service:** JWT tokens with short TTL (15 min)
- **Secrets:** Google Secret Manager / AWS Secrets Manager

**Features:**
- SSO integration (SAML 2.0)
- Service account management
- Role-based access control (Analyst, Admin, API User)
- API key generation and rotation
- Audit logging of all auth events

**Roles:**
```
- Analyst: Read detections, run hunts, view dashboards
- SOC Lead: All analyst + approve whitelists, manage cases
- Admin: All + service configuration, user management
- API User: Programmatic access with scoped permissions
```

**Development:**
- **Week 1-2:** SSO integration, role definitions
- **Week 3-4:** JWT implementation, service accounts
- **Week 5-6:** RBAC enforcement, audit logging

**Risks:**
- **CRITICAL:** Privilege escalation vulnerability
- **HIGH:** Token leakage in logs or error messages
- **MEDIUM:** SSO misconfiguration blocks all users
- **MITIGATION:** Penetration testing before prod, token rotation, fallback local auth

---

#### 3. Collection Service
**Purpose:** Pull data from external sources (IOC feeds, activity logs) on a schedule.

**Tech Stack:**
- **Runtime:** Cloud Run (GCP) / Fargate (AWS) - serverless containers
- **Language:** Python 3.11+ (asyncio for concurrent requests)
- **Scheduling:** Cloud Scheduler
- **Libraries:** 
  - `aiohttp` for async HTTP requests
  - `google-cloud-bigquery` for BQ interaction
  - `trino-python-client` for Trino queries

**Data Sources:**
| Source | Frequency | Volume | Protocol |
|--------|-----------|--------|----------|
| AlienVault OTX | 30 min | ~50K IOCs/day | REST API |
| abuse.ch | 15 min | ~10K IOCs/day | REST API |
| MISP Feeds | 30 min | ~100K IOCs/day | REST API |
| Proxy Logs (Trino) | 3 min | ~2M events/day | SQL |
| DNS Logs (Trino) | 3 min | ~5M events/day | SQL |
| Sinkhole Logs (Trino) | 3 min | ~100K events/day | SQL |
| MDE Logs (BigQuery) | 3 min | ~500K events/day | SQL |
| CrowdStrike (BigQuery) | 3 min | ~300K events/day | SQL |

**Features:**
- Watermark-based incremental collection
- Retry logic with exponential backoff
- Parallel collection across sources
- Error handling and dead letter queue
- Collection metrics (events/sec, success rate)

**Collection Pattern:**
```python
def collect_activity_logs(source_config):
    # Get last successful watermark
    watermark = get_watermark(source_config.id)
    
    # Query for new data
    query = f"""
        SELECT * FROM {source_config.table}
        WHERE timestamp > '{watermark.last_successful}'
        AND timestamp <= CURRENT_TIMESTAMP()
        ORDER BY timestamp
        LIMIT 100000
    """
    
    events = execute_query(query)
    
    if events:
        # Send to normalization
        publish_to_pubsub(topic='raw-events', data=events)
        
        # Update watermark
        update_watermark(source_config.id, max(e.timestamp for e in events))
```

**Development:**
- **Week 1-3:** IOC feed integration (3 feeds)
- **Week 4-6:** Trino connector, watermark logic
- **Week 7-9:** BigQuery connector, error handling
- **Week 10-12:** Performance tuning, monitoring

**Risks:**
- **HIGH:** Source API rate limits cause collection failures
- **HIGH:** Watermark corruption leads to duplicate/missing data
- **MEDIUM:** Large query results cause memory issues
- **LOW:** Source schema changes break parsing
- **MITIGATION:** Respect API limits with backoff, atomic watermark updates, streaming results, schema validation

---

#### 4. Normalization Service
**Purpose:** Transform diverse data formats into unified schema for processing.

**Tech Stack:**
- **Runtime:** Cloud Run
- **Language:** Python (using Pydantic for validation)
- **Message Queue:** Cloud Pub/Sub / AWS SQS
- **Schema:** JSON Schema for validation

**Normalization Rules:**

**IOC Normalization:**
```python
# Input: Various IOC feed formats
# Output: Unified IOC schema

@dataclass
class NormalizedIOC:
    ioc_value: str          # IP, domain, hash, etc.
    ioc_type: str           # ip, domain, url, hash_md5, hash_sha256
    threat_type: str        # malware, c2, phishing, exploit
    confidence: float       # 0.0-1.0
    source: str             # Feed name
    first_seen: datetime
    last_seen: datetime
    tags: List[str]
    metadata: Dict
```

**Activity Normalization:**
```python
@dataclass
class NormalizedActivity:
    event_id: str
    timestamp: datetime
    source: str             # proxy, dns, mde, crowdstrike, sinkhole
    event_type: str         # dns_query, http_request, process_create
    
    # Network fields (when applicable)
    src_ip: Optional[str]
    dst_ip: Optional[str]
    domain: Optional[str]
    url: Optional[str]
    
    # Host fields (when applicable)
    hostname: Optional[str]
    user: Optional[str]
    process_name: Optional[str]
    file_hash: Optional[str]
    
    # Common
    raw_event: Dict         # Original event for reference
```

**Development:**
- **Week 1-2:** Schema design, validation logic
- **Week 3-4:** IOC normalizers (per feed)
- **Week 5-6:** Activity normalizers (per source)
- **Week 7-8:** Testing with real data, edge cases

**Risks:**
- **MEDIUM:** Normalization bugs cause data loss
- **MEDIUM:** Performance bottleneck on high volume
- **LOW:** Schema changes require reprocessing
- **MITIGATION:** Comprehensive unit tests, preserve raw_event field, versioned schemas

---

#### 5. Storage Service
**Purpose:** Abstract data persistence layer for IOCs, activity logs, and detections.

**Tech Stack:**
- **BigQuery:** Primary analytical storage
  - IOC repository (partitioned by date)
  - Activity logs (partitioned by date, clustered by source)
  - Detection results
- **Redis:** Hot IOC cache (Cloud Memorystore)
- **Firestore:** Metadata, watermarks, configuration

**BigQuery Schema:**

**IOCs Table:**
```sql
CREATE TABLE threat_xdr.iocs (
    ioc_value STRING NOT NULL,
    ioc_type STRING NOT NULL,
    threat_type STRING,
    confidence FLOAT64,
    source STRING,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    tags ARRAY<STRING>,
    enrichment JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP()
)
PARTITION BY DATE(first_seen)
CLUSTER BY ioc_type, source;
```

**Activity Logs Table:**
```sql
CREATE TABLE threat_xdr.activity_logs (
    event_id STRING NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    source STRING NOT NULL,
    event_type STRING,
    src_ip STRING,
    dst_ip STRING,
    domain STRING,
    url STRING,
    hostname STRING,
    user STRING,
    process_name STRING,
    file_hash STRING,
    enrichment JSON,
    raw_event JSON
)
PARTITION BY DATE(timestamp)
CLUSTER BY source, event_type;
```

**Detections Table:**
```sql
CREATE TABLE threat_xdr.detections (
    detection_id STRING NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    ioc_value STRING,
    ioc_type STRING,
    activity_event_id STRING,
    activity_source STRING,
    severity STRING,
    confidence FLOAT64,
    enrichment JSON,
    case_id STRING,
    status STRING,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP()
)
PARTITION BY DATE(timestamp)
CLUSTER BY severity, status;
```

**Redis Cache Strategy:**
```python
# Cache hot IOCs (last 48 hours + high confidence)
cache_key = f"ioc:{ioc_type}:{ioc_value}"
cache_ttl = 86400  # 24 hours

# Cache structure
{
    "ioc_value": "malicious.com",
    "ioc_type": "domain",
    "threat_type": "c2",
    "confidence": 0.95,
    "source": "alienvault",
    "metadata": {...}
}
```

**Development:**
- **Week 1-2:** BigQuery schema design, partitioning strategy
- **Week 3-4:** Redis setup, cache policies
- **Week 5-6:** Firestore setup, CRUD operations
- **Week 7-8:** Performance testing, query optimization

**Risks:**
- **HIGH:** BigQuery costs exceed budget on high volume
- **MEDIUM:** Cache invalidation bugs cause stale data
- **MEDIUM:** Partition pruning not working, slow queries
- **MITIGATION:** Set query/storage quotas, TTL-based cache expiry, test partition filters

---

#### 6. Detection Service (Fast Path)
**Purpose:** Real-time correlation of activity logs against IOC cache to identify threats.

**Tech Stack:**
- **Runtime:** Cloud Run with min instances for low latency
- **Language:** Python or Go (Go preferred for performance)
- **Cache:** Redis for IOC lookups
- **Concurrency:** Async/parallel processing

**Detection Logic:**
```python
def correlate_events(events: List[NormalizedActivity]) -> List[Detection]:
    detections = []
    
    for event in events:
        # Extract IOC candidates from event
        candidates = extract_ioc_candidates(event)
        
        # Check each candidate against cache
        for candidate in candidates:
            ioc = redis.get(f"ioc:{candidate.type}:{candidate.value}")
            
            if ioc:
                # Match found
                detection = Detection(
                    ioc_value=candidate.value,
                    ioc_type=candidate.type,
                    activity_event_id=event.event_id,
                    severity=calculate_severity(ioc, event),
                    confidence=ioc.confidence,
                    timestamp=event.timestamp
                )
                detections.append(detection)
    
    return detections

def calculate_severity(ioc, event):
    # Scoring logic
    score = ioc.confidence * 100
    
    # Adjust based on context
    if event.source == "mde":  # Endpoint detection more serious
        score *= 1.5
    if ioc.threat_type == "ransomware":
        score *= 2.0
    
    if score >= 80: return "CRITICAL"
    elif score >= 60: return "HIGH"
    elif score >= 40: return "MEDIUM"
    else: return "LOW"
```

**Matching Strategies:**

| Event Type | IOC Type | Match Method |
|------------|----------|--------------|
| DNS Query | Domain | Exact + subdomain match |
| HTTP Request | URL/IP | Exact match |
| Process Create | Hash | Exact match |
| Network Connection | IP | Exact + CIDR match |

**Performance:**
- Target: Process 10K events/min
- Latency: <100ms per batch (1000 events)
- Cache hit rate: >95%

**Development:**
- **Week 1-3:** Core correlation engine
- **Week 4-5:** Severity scoring logic
- **Week 6-7:** Performance optimization
- **Week 8-9:** Testing with real data volume

**Risks:**
- **CRITICAL:** False positive rate too high, SOC overwhelmed
- **HIGH:** Performance degrades under load
- **MEDIUM:** Cache misses cause slow lookups
- **MITIGATION:** Conservative scoring initially, load testing, cache warming strategy

---

#### 7. Scoring Service
**Purpose:** Calculate threat severity and filter low-confidence detections.

**Tech Stack:**
- **Runtime:** Cloud Run
- **Language:** Python
- **Rules Engine:** JSON-based rules for flexibility

**Scoring Factors:**
```python
def score_detection(detection, ioc, event):
    base_score = ioc.confidence * 100
    
    # Factor 1: IOC source reputation
    source_multipliers = {
        'alienvault': 1.0,
        'abuse.ch': 1.2,  # Higher confidence
        'custom_feed': 0.8
    }
    base_score *= source_multipliers.get(ioc.source, 1.0)
    
    # Factor 2: Threat type severity
    threat_severity = {
        'ransomware': 2.0,
        'c2': 1.5,
        'malware': 1.3,
        'phishing': 1.1,
        'suspicious': 0.8
    }
    base_score *= threat_severity.get(ioc.threat_type, 1.0)
    
    # Factor 3: Activity source criticality
    if event.source == "mde":
        base_score *= 1.5  # Endpoint detection
    elif event.source == "sinkhole":
        base_score *= 1.8  # Already suspicious
    
    # Factor 4: Asset criticality (from enrichment)
    if event.enrichment.get('asset_criticality') == 'high':
        base_score *= 1.3
    
    # Cap at 100
    return min(base_score, 100)

def apply_filters(detections):
    # Filter 1: Whitelist
    detections = [d for d in detections if not is_whitelisted(d)]
    
    # Filter 2: Minimum confidence
    detections = [d for d in detections if d.score >= 40]
    
    # Filter 3: Deduplication (same IOC + host in 1 hour)
    detections = deduplicate(detections, window='1h')
    
    return detections
```

**Development:**
- **Week 1-2:** Scoring algorithm design
- **Week 3-4:** Rules engine implementation
- **Week 5-6:** Whitelist management
- **Week 7-8:** Tuning with real data

**Risks:**
- **HIGH:** Scoring too aggressive, miss threats
- **HIGH:** Scoring too lenient, too many alerts
- **MEDIUM:** Whitelist management becomes complex
- **MITIGATION:** A/B test scoring rules, analyst feedback loop, whitelist audit logs

---

#### 8. Notification Service
**Purpose:** Send alerts to ServiceNow, email, Slack for high-severity detections.

**Tech Stack:**
- **Runtime:** Cloud Run
- **Integrations:**
  - ServiceNow REST API
  - SendGrid (email)
  - Slack API
- **Templating:** Jinja2 for message formatting
- **Queue:** Pub/Sub for async delivery

**ServiceNow Integration:**
```python
def create_snow_case(detection):
    case_data = {
        "short_description": f"IOC Detection: {detection.ioc_value}",
        "description": f"""
            Threat Detection Alert
            
            IOC: {detection.ioc_value} ({detection.ioc_type})
            Threat Type: {detection.threat_type}
            Severity: {detection.severity}
            Confidence: {detection.confidence}
            
            Activity:
            - Source: {detection.activity_source}
            - Timestamp: {detection.timestamp}
            - Host: {detection.hostname}
            - User: {detection.user}
            
            Enrichment:
            {format_enrichment(detection.enrichment)}
            
            Link: https://threat-xdr.example.com/detection/{detection.id}
        """,
        "urgency": map_severity_to_urgency(detection.severity),
        "category": "Security",
        "assignment_group": "SOC Tier 1"
    }
    
    response = requests.post(
        f"{SNOW_URL}/api/now/table/incident",
        auth=(SNOW_USER, SNOW_PASS),
        json=case_data
    )
    
    return response.json()['result']['number']
```

**Notification Rules:**
```yaml
rules:
  - name: "Critical alerts to Slack and ServiceNow"
    condition: severity == "CRITICAL"
    actions:
      - type: "servicenow"
        urgency: 1
      - type: "slack"
        channel: "#soc-critical"
        mention: "@soc-lead"
  
  - name: "High alerts to ServiceNow"
    condition: severity == "HIGH"
    actions:
      - type: "servicenow"
        urgency: 2
  
  - name: "Medium alerts to email"
    condition: severity == "MEDIUM"
    actions:
      - type: "email"
        recipients: ["soc@example.com"]
```

**Development:**
- **Week 1-2:** ServiceNow API integration
- **Week 3-4:** Email and Slack integration
- **Week 5-6:** Templating and rules engine
- **Week 7-8:** Testing and error handling

**Risks:**
- **HIGH:** ServiceNow API failures block alerting
- **MEDIUM:** Alert fatigue from too many notifications
- **LOW:** Email deliverability issues
- **MITIGATION:** Queue notifications for retry, notification throttling, secondary email provider

---

### Phase 1 Timeline (Months 1-6)

**Month 1: Foundation**
- Week 1-2: GCP project setup, networking, IAM
- Week 3-4: CI/CD pipeline, Git repo structure
- Week 5-6: Dev/staging environments, monitoring setup

**Month 2: Gateway & Auth**
- API Gateway Service (6 weeks)
- Authentication & Authorization Service (6 weeks)
- **Milestone M1:** Infrastructure ready

**Month 3-4: Data Ingestion**
- Collection Service (12 weeks)
- Normalization Service (8 weeks)
- Storage Service (8 weeks)

**Month 4: Detection Core**
- Detection Service (9 weeks)
- **Milestone M2:** MVP alpha with 1 data source

**Month 5: Alerting**
- Scoring Service (8 weeks)
- Notification Service (8 weeks)

**Month 6: MVP Launch**
- Integration testing all services
- Security audit and pen test
- Performance testing (10K events/min)
- **Milestone M3:** MVP production release

**Phase 1 Deliverables:**
- ✅ Real-time detection of known IOCs (<5 min SLA)
- ✅ 5 data sources integrated (Proxy, DNS, Sinkhole, MDE, CrowdStrike)
- ✅ 3 IOC feeds integrated (AlienVault, abuse.ch, MISP)
- ✅ ServiceNow case creation
- ✅ Basic web dashboard
- ✅ Processing 1M+ events/day

---

## Phase 2: Intelligence & Analytics (Months 7-10)

**Goal:** Add enrichment, deep analytics, and threat intelligence capabilities.

### Services to Build (7 services)

#### 9. Query Service
**Purpose:** Unified query interface across BigQuery, Redis, and Firestore.

**Tech Stack:**
- **Runtime:** Cloud Run
- **Language:** Python with SQLAlchemy
- **Query Parser:** Custom DSL → SQL translator
- **Caching:** Results cache for common queries

**Features:**
- Single API for querying all data stores
- Query optimization and rewriting
- Automatic routing to appropriate backend
- Result pagination and streaming
- Query result caching

**API:**
```python
POST /v1/query
{
    "query": "SELECT * FROM detections WHERE severity='CRITICAL' AND timestamp > '2026-01-01'",
    "limit": 1000,
    "offset": 0
}

# Simplified query DSL
POST /v1/query/simple
{
    "table": "detections",
    "filters": {
        "severity": "CRITICAL",
        "timestamp_gte": "2026-01-01"
    },
    "limit": 1000
}
```

**Development:** 4 weeks

**Risks:**
- **MEDIUM:** Query injection vulnerabilities
- **MEDIUM:** Expensive queries impact performance
- **MITIGATION:** Parameterized queries only, query cost estimation, timeouts

---

#### 10. Enrichment Service
**Purpose:** Add context to IOCs and activity events from external sources.

**Tech Stack:**
- **Runtime:** Cloud Run
- **APIs Integrated:**
  - VirusTotal API
  - PassiveTotal (RiskIQ)
  - WHOIS/RDAP
  - MaxMind GeoIP
  - Team Cymru IP-to-ASN
  - Shodan
- **Cache:** Redis for enrichment results (7 day TTL)
- **Rate Limiting:** Token bucket per API

**Enrichment Types:**

**IOC Enrichment:**
```python
def enrich_ioc(ioc_value, ioc_type):
    enrichment = {}
    
    if ioc_type == "domain":
        # WHOIS data
        whois = get_whois(ioc_value)
        enrichment['registrar'] = whois.registrar
        enrichment['creation_date'] = whois.creation_date
        enrichment['name_servers'] = whois.name_servers
        
        # PassiveTotal
        passive_dns = get_passive_dns(ioc_value)
        enrichment['historical_ips'] = passive_dns.ips
        enrichment['first_seen'] = passive_dns.first_seen
        
        # VirusTotal
        vt = get_virustotal_domain(ioc_value)
        enrichment['vt_detections'] = vt.positives
        enrichment['vt_total_scanners'] = vt.total
        
    elif ioc_type == "ip":
        # GeoIP
        geo = get_geoip(ioc_value)
        enrichment['country'] = geo.country
        enrichment['city'] = geo.city
        enrichment['asn'] = geo.asn
        enrichment['isp'] = geo.isp
        
        # Shodan
        shodan = get_shodan(ioc_value)
        enrichment['open_ports'] = shodan.ports
        enrichment['services'] = shodan.services
        
    elif ioc_type in ["hash_md5", "hash_sha256"]:
        # VirusTotal
        vt = get_virustotal_file(ioc_value)
        enrichment['vt_detections'] = vt.positives
        enrichment['file_type'] = vt.file_type
        enrichment['file_names'] = vt.names
        enrichment['malware_families'] = vt.families
    
    return enrichment
```

**Activity Enrichment:**
```python
def enrich_activity(event):
    enrichment = {}
    
    # GeoIP for IPs
    if event.src_ip:
        geo = get_geoip(event.src_ip)
        enrichment['src_geo'] = geo
    
    if event.dst_ip:
        geo = get_geoip(event.dst_ip)
        enrichment['dst_geo'] = geo
    
    # Asset context
    if event.hostname:
        asset = get_asset_db(event.hostname)
        enrichment['asset_criticality'] = asset.criticality
        enrichment['asset_owner'] = asset.owner
        enrichment['asset_department'] = asset.department
    
    # User context
    if event.user:
        user = get_user_db(event.user)
        enrichment['user_department'] = user.department
        enrichment['user_title'] = user.title
        enrichment['user_manager'] = user.manager
    
    return enrichment
```

**Rate Limiting Strategy:**
```python
# VirusTotal: 4 requests/min (free tier)
vt_limiter = RateLimiter(rate=4, per=60)

# Cache enrichment for 7 days
@cache(ttl=604800)  # 7 days
def get_virustotal_domain(domain):
    vt_limiter.acquire()
    return vt_api.get_domain(domain)
```

**Development:** 8 weeks

**Risks:**
- **HIGH:** API rate limits block enrichment
- **MEDIUM:** API costs exceed budget
- **MEDIUM:** External API downtime
- **MITIGATION:** Aggressive caching, tiered enrichment (basic vs. full), fallback strategies

---

#### 11. Deep Analytics Service
**Purpose:** Run scheduled analytics jobs for behavioral detection.

**Tech Stack:**
- **Orchestration:** Apache Airflow (Cloud Composer)
- **Compute:** BigQuery for analytics, Dataflow for streaming
- **Language:** Python + SQL
- **Notebooks:** Jupyter for development/testing

**Analytics Jobs:**

**1. Beaconing Detection (Daily)**
```sql
-- Find C2 beaconing patterns
WITH connection_intervals AS (
  SELECT 
    dst_ip,
    hostname,
    TIMESTAMP_DIFF(
      timestamp, 
      LAG(timestamp) OVER (PARTITION BY hostname, dst_ip ORDER BY timestamp),
      SECOND
    ) as interval_seconds
  FROM activity_logs
  WHERE source = 'proxy'
    AND DATE(timestamp) = CURRENT_DATE() - 1
)
SELECT 
  dst_ip,
  hostname,
  COUNT(*) as connection_count,
  AVG(interval_seconds) as avg_interval,
  STDDEV(interval_seconds) as stddev_interval,
  MIN(interval_seconds) as min_interval,
  MAX(interval_seconds) as max_interval
FROM connection_intervals
GROUP BY dst_ip, hostname
HAVING 
  connection_count > 100
  AND stddev_interval < 5  -- Very regular intervals
  AND avg_interval BETWEEN 60 AND 3600  -- 1 min to 1 hour
ORDER BY stddev_interval ASC
```

**2. DGA Detection (Daily)**
```sql
-- Find Domain Generation Algorithm patterns
SELECT 
  domain,
  COUNT(*) as query_count,
  AVG(LENGTH(domain)) as avg_length,
  -- Entropy calculation
  (SELECT -SUM(freq * LOG2(freq))
   FROM (
     SELECT COUNT(*)/LENGTH(domain) as freq
     FROM UNNEST(SPLIT(domain, '')) as char
     GROUP BY char
   )) as entropy
FROM activity_logs
WHERE source = 'dns'
  AND DATE(timestamp) = CURRENT_DATE() - 1
GROUP BY domain
HAVING 
  query_count < 10  -- Rare queries
  AND avg_length > 15  -- Long domains
  AND entropy > 3.5  -- High entropy (random-looking)
ORDER BY entropy DESC
```

**3. Lateral Movement Detection (Daily)**
```sql
-- Detect unusual authentication patterns
WITH user_auth_patterns AS (
  SELECT 
    user,
    hostname,
    COUNT(DISTINCT hostname) OVER (PARTITION BY user) as unique_hosts,
    COUNT(*) as auth_count
  FROM activity_logs
  WHERE source = 'mde'
    AND event_type = 'logon'
    AND DATE(timestamp) = CURRENT_DATE() - 1
)
SELECT * FROM user_auth_patterns
WHERE unique_hosts > 20  -- Accessed many hosts
  AND auth_count > 50  -- Many authentications
```

**Development:** 10 weeks (2 weeks per analytics job)

**Risks:**
- **MEDIUM:** Analytics jobs too slow, block daily runs
- **MEDIUM:** False positive rate high on behavioral detection
- **MITIGATION:** Optimize queries, tune thresholds with analyst feedback

---

#### 12. Threat Intelligence Service
**Purpose:** Curate and score IOCs based on multiple sources.

**Tech Stack:**
- **Runtime:** Cloud Run
- **Database:** BigQuery for IOC history
- **Language:** Python

**Features:**
- IOC reputation scoring across feeds
- Campaign attribution (cluster related IOCs)
- IOC aging (reduce confidence over time)
- Threat actor mapping

**Reputation Scoring:**
```python
def calculate_ioc_reputation(ioc_value):
    # Get all instances of this IOC across feeds
    instances = query_ioc_history(ioc_value)
    
    # Factor 1: Number of sources
    num_sources = len(set(i.source for i in instances))
    source_score = min(num_sources * 10, 40)  # Max 40 points
    
    # Factor 2: Source reputation
    source_weights = {
        'abuse.ch': 1.2,
        'alienvault': 1.0,
        'custom': 0.8
    }
    weighted_confidence = sum(
        i.confidence * source_weights.get(i.source, 1.0)
        for i in instances
    ) / len(instances)
    confidence_score = weighted_confidence * 30  # Max 30 points
    
    # Factor 3: Recency
    days_since_last_seen = (now() - max(i.last_seen for i in instances)).days
    recency_score = max(30 - days_since_last_seen, 0)  # Max 30 points
    
    total_score = source_score + confidence_score + recency_score
    return min(total_score, 100)
```

**Development:** 6 weeks

**Risks:**
- **MEDIUM:** Campaign attribution logic complex
- **LOW:** Reputation scores drift from reality
- **MITIGATION:** Start simple, iterate with analyst feedback

---

#### 13. Scheduling Service
**Purpose:** Manage job scheduling and dependencies.

**Tech Stack:**
- **Primary:** Cloud Composer (managed Airflow)
- **Alternative:** Kubernetes CronJobs
- **Monitoring:** Airflow UI + Cloud Monitoring

**DAG Structure:**
```python
# Daily analytics DAG
dag = DAG(
    'daily_analytics',
    schedule_interval='0 2 * * *',  # 2 AM daily
    default_args={
        'retries': 3,
        'retry_delay': timedelta(minutes=5)
    }
)

# Task dependencies
collect_data = PythonOperator(task_id='collect', dag=dag)
run_beaconing = BigQueryOperator(task_id='beaconing', dag=dag)
run_dga = BigQueryOperator(task_id='dga', dag=dag)
run_lateral_movement = BigQueryOperator(task_id='lateral_movement', dag=dag)
notify_results = PythonOperator(task_id='notify', dag=dag)

collect_data >> [run_beaconing, run_dga, run_lateral_movement] >> notify_results
```

**Development:** 4 weeks

**Risks:**
- **MEDIUM:** Job failures cascade
- **LOW:** Scheduling conflicts
- **MITIGATION:** Comprehensive retry logic, job monitoring alerts

---

#### 14. Configuration Service
**Purpose:** Centralized configuration and feature flags.

**Tech Stack:**
- **Storage:** Firestore for dynamic config
- **SDK:** Custom config client library
- **UI:** Admin console for config management

**Config Types:**
```yaml
# Feature flags
features:
  enrichment_enabled: true
  ml_scoring_enabled: false
  auto_whitelist: false

# Detection thresholds
thresholds:
  min_confidence: 40
  critical_score: 80
  high_score: 60

# Rate limits
rate_limits:
  api_requests_per_minute: 1000
  enrichment_batch_size: 100

# External APIs
external_apis:
  virustotal:
    enabled: true
    rate_limit: 4
  passivetotal:
    enabled: true
    rate_limit: 10
```

**Development:** 3 weeks

**Risks:**
- **LOW:** Config changes break services
- **MITIGATION:** Config validation, rollback capability

---

#### 15. Search Service
**Purpose:** Advanced search for threat hunting.

**Tech Stack:**
- **Primary:** BigQuery full-text search
- **Alternative:** Elasticsearch for complex queries
- **Language:** Python
- **UI:** Web-based query builder

**Search Capabilities:**
```python
# Full-text search
search_query = """
  SELECT * FROM activity_logs
  WHERE SEARCH(raw_event, 'powershell AND bypass')
    AND DATE(timestamp) BETWEEN '2026-01-01' AND '2026-01-31'
  LIMIT 1000
"""

# Regex search
search_query = """
  SELECT * FROM activity_logs
  WHERE REGEXP_CONTAINS(domain, r'.*[0-9]{8,}.*')  # Many numbers in domain
  LIMIT 1000
"""
```

**Development:** 5 weeks

**Risks:**
- **MEDIUM:** Search performance poor on large datasets
- **MITIGATION:** Proper indexing, query optimization, result limits

---

### Phase 2 Timeline (Months 7-10)

**Month 7:**
- Query Service (4 weeks)
- Enrichment Service start (8 weeks total)

**Month 8:**
- Enrichment Service completion
- Deep Analytics Service start (10 weeks total)

**Month 9:**
- Deep Analytics Service completion
- Threat Intel Service (6 weeks)
- Scheduling Service (4 weeks)

**Month 10:**
- Configuration Service (3 weeks)
- Search Service (5 weeks)
- Integration testing
- **Milestone M4:** Analytics operational

**Phase 2 Deliverables:**
- ✅ IOC and activity enrichment with 5+ external APIs
- ✅ 5+ deep analytics jobs (beaconing, DGA, etc.)
- ✅ Threat hunting with advanced search
- ✅ Centralized configuration management
- ✅ Processing 5M+ events/day

---

## Phase 3: Operations & Scale (Months 11-14)

**Goal:** Production-harden the platform with observability, resilience, and performance.

### Services to Build (6 services)

#### 16. Observability Service
**Purpose:** Centralized metrics, logging, and tracing.

**Tech Stack:**
- **Metrics:** Cloud Monitoring (Prometheus compatible)
- **Logging:** Cloud Logging (structured JSON logs)
- **Tracing:** Cloud Trace (OpenTelemetry)
- **Dashboards:** Grafana or Cloud Monitoring Dashboards
- **Alerting:** Cloud Alerting (PagerDuty integration)

**Key Metrics:**
```python
# Collection metrics
collection_events_per_second
collection_errors_total
collection_latency_seconds

# Detection metrics
detections_created_total
detection_latency_seconds
false_positive_rate

# Enrichment metrics
enrichment_api_calls_total
enrichment_cache_hit_rate
enrichment_latency_seconds

# System metrics
service_availability
api_request_duration
bigquery_slots_used
```

**Dashboards:**
1. **Platform Overview:** Service health, request rates, error rates
2. **Detection Performance:** Detections/hour, severity distribution, MTTD
3. **Data Pipeline:** Events ingested, processing lag, enrichment coverage
4. **Cost Monitoring:** BigQuery cost, API costs, compute costs

**Development:** 6 weeks

**Risks:**
- **MEDIUM:** Alert fatigue from too many alerts
- **LOW:** Metrics overhead impacts performance
- **MITIGATION:** Thoughtful alert thresholds, sampling for high-cardinality metrics

---

#### 17. Validation Service
**Purpose:** Enforce data quality at ingestion.

**Tech Stack:**
- **Runtime:** Cloud Run
- **Validation:** JSON Schema, Great Expectations
- **Language:** Python

**Validation Rules:**
```python
# IOC validation
ioc_schema = {
    "type": "object",
    "required": ["ioc_value", "ioc_type", "confidence"],
    "properties": {
        "ioc_value": {"type": "string", "minLength": 1},
        "ioc_type": {"enum": ["ip", "domain", "url", "hash_md5", "hash_sha256"]},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "threat_type": {"type": "string"}
    }
}

# Activity event validation
def validate_event(event):
    # Schema validation
    validate_schema(event, activity_schema)
    
    # Business rules
    if event.timestamp > now():
        raise ValidationError("Future timestamp")
    
    if event.source not in ALLOWED_SOURCES:
        raise ValidationError(f"Unknown source: {event.source}")
    
    # Data quality checks
    if event.src_ip and not is_valid_ip(event.src_ip):
        raise ValidationError(f"Invalid IP: {event.src_ip}")
```

**Development:** 4 weeks

**Risks:**
- **LOW:** Validation too strict, reject valid data
- **MITIGATION:** Comprehensive testing, validation metrics

---

#### 18. Health Check Service
**Purpose:** Monitor service health and manage circuit breakers.

**Tech Stack:**
- **Runtime:** Lightweight Cloud Function
- **Checks:** HTTP health endpoints
- **Circuit Breaker:** Custom implementation or Hystrix-like

**Health Checks:**
```python
def check_service_health(service_url):
    checks = {
        'http': check_http_endpoint(f"{service_url}/health"),
        'database': check_database_connection(),
        'cache': check_redis_connection(),
        'dependencies': check_external_apis()
    }
    
    return {
        'status': 'healthy' if all(checks.values()) else 'unhealthy',
        'checks': checks,
        'timestamp': now()
    }

# Circuit breaker for external APIs
class CircuitBreaker:
    def __init__(self, failure_threshold=5, timeout=60):
        self.failure_count = 0
        self.state = 'CLOSED'  # CLOSED, OPEN, HALF_OPEN
        
    def call(self, func, *args):
        if self.state == 'OPEN':
            raise CircuitOpenError()
        
        try:
            result = func(*args)
            self.on_success()
            return result
        except Exception as e:
            self.on_failure()
            raise
```

**Development:** 3 weeks

**Risks:**
- **LOW:** Health checks add latency
- **MITIGATION:** Async health checks, caching

---

#### 19. Audit Service
**Purpose:** Compliance logging and change tracking.

**Tech Stack:**
- **Storage:** BigQuery (append-only audit log)
- **Runtime:** Cloud Run
- **Retention:** 7 years for compliance

**Audit Events:**
```python
# Audit log schema
{
    "timestamp": "2026-01-01T12:00:00Z",
    "user": "analyst@example.com",
    "action": "whitelist_add",
    "resource": "ioc:malicious.com",
    "details": {
        "ioc_value": "malicious.com",
        "reason": "False positive - internal test domain"
    },
    "ip_address": "10.1.2.3",
    "user_agent": "Mozilla/5.0..."
}

# Tracked actions
- User login/logout
- Whitelist add/remove
- Detection status change
- Configuration changes
- Case creation/closure
- Hunt execution
- Backfill trigger
```

**Development:** 4 weeks

**Risks:**
- **LOW:** Audit log becomes very large
- **MITIGATION:** Partitioning, summarization for old data

---

#### 20. Watermark Manager
**Purpose:** Track collection progress for backfill.

**Tech Stack:**
- **Storage:** Firestore (strong consistency)
- **Runtime:** Part of Collection Service
- **Language:** Python

**Watermark Operations:**
```python
class WatermarkManager:
    def get_watermark(self, source_id):
        doc = firestore.collection('watermarks').document(source_id).get()
        return doc.to_dict() if doc.exists else None
    
    def update_watermark(self, source_id, timestamp, status, metadata):
        watermark = {
            'source_id': source_id,
            'last_attempt': timestamp,
            'status': status,
            'metadata': metadata,
            'updated_at': firestore.SERVER_TIMESTAMP
        }
        
        if status == 'success':
            watermark['last_success'] = timestamp
        else:
            # Track gap
            watermark['gaps'] = firestore.ArrayUnion([{
                'start': self.get_last_success(source_id),
                'end': timestamp
            }])
        
        firestore.collection('watermarks').document(source_id).set(
            watermark, merge=True
        )
```

**Development:** 3 weeks

**Risks:**
- **MEDIUM:** Race conditions on concurrent updates
- **MITIGATION:** Firestore transactions, idempotency

---

#### 21. Job Monitor
**Purpose:** Monitor scheduled jobs and trigger backfills.

**Tech Stack:**
- **Runtime:** Cloud Run (cron trigger)
- **Monitoring:** Airflow API
- **Language:** Python

**Monitoring Logic:**
```python
def monitor_collection_jobs():
    for source in SOURCES:
        watermark = get_watermark(source.id)
        
        # Check for staleness
        time_since_success = now() - watermark.last_success
        if time_since_success > source.sla:
            alert(f"Collection stale for {source.id}")
            
            # Auto-trigger backfill
            trigger_backfill(
                source=source.id,
                start=watermark.last_success,
                end=now(),
                priority='high'
            )
        
        # Check for gaps
        if watermark.gaps:
            for gap in watermark.gaps:
                trigger_backfill(
                    source=source.id,
                    start=gap.start,
                    end=gap.end,
                    priority='medium'
                )
```

**Development:** 4 weeks

**Risks:**
- **MEDIUM:** False positive backfill triggers
- **MITIGATION:** Backfill throttling, manual approval for large gaps

---

### Phase 3 Timeline (Months 11-14)

**Month 11:**
- Observability Service (6 weeks)
- Validation Service (4 weeks)

**Month 12:**
- Health Check Service (3 weeks)
- Audit Service (4 weeks)
- Watermark Manager (3 weeks)

**Month 13:**
- Job Monitor (4 weeks)
- Performance testing and optimization
- Security audit #2

**Month 14:**
- Load testing (10M events/day)
- Chaos engineering
- Disaster recovery testing
- **Milestone M5:** Production-hardened

**Phase 3 Deliverables:**
- ✅ Comprehensive observability (metrics, logs, traces)
- ✅ Data quality validation at ingestion
- ✅ Automated backfill for failed collections
- ✅ Audit logging for compliance
- ✅ 99.9% uptime SLA
- ✅ Processing 10M+ events/day

---

## Phase 4: Advanced Features (Months 15-18)

**Goal:** Add ML capabilities, playbooks, and advanced threat hunting.

### Services to Build (7 services)

#### 22. Threat Hunting Service
**Purpose:** Ad-hoc threat hunting with saved queries.

**Tech Stack:**
- **Runtime:** Cloud Run
- **Storage:** Firestore (saved hunts)
- **Query Engine:** BigQuery
- **UI:** React-based hunt console

**Features:**
- Visual query builder
- Saved hunt library
- Hunt scheduling
- Result sharing
- Export to CSV/JSON

**Hunt Query DSL:**
```yaml
name: "Find beaconing to new domains"
description: "Detect C2 beaconing to domains registered in last 30 days"
query:
  from: "dns_logs"
  join:
    - table: "ioc_enrichment"
      on: "dns_logs.domain = ioc_enrichment.domain"
  where:
    - "dns_logs.timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)"
    - "ioc_enrichment.domain_age_days < 30"
  group_by: ["domain", "src_ip"]
  having:
    - "COUNT(*) > 100"
    - "STDDEV_SAMP(interval_seconds) < 5"
```

**Development:** 8 weeks

**Risks:**
- **MEDIUM:** Complex queries timeout
- **MITIGATION:** Query cost estimation, timeouts, materialized views

---

#### 23. Backfill Service
**Purpose:** Handle data replay for gaps.

**Tech Stack:**
- **Runtime:** Cloud Run
- **Queue:** Cloud Tasks for job management
- **Language:** Python

**Features:**
- Gap detection
- Priority queuing
- Throttling
- Progress tracking
- Idempotency

**Development:** 6 weeks

**Risks:**
- **HIGH:** Backfill overwhelms sources
- **MITIGATION:** Rate limiting, backfill windows

---

#### 24. Ad-hoc Detection Service
**Purpose:** Run detection rules on historical data.

**Tech Stack:**
- **Runtime:** Dataflow (for large scans)
- **Language:** Python/Java

**Features:**
- Retroactive detection
- Custom detection rules
- Batch processing

**Development:** 5 weeks

**Risks:**
- **MEDIUM:** Large scans expensive
- **MITIGATION:** Cost estimation, user approval

---

#### 25. Case Manager
**Purpose:** Manage detection lifecycle.

**Tech Stack:**
- **Runtime:** Cloud Run
- **Storage:** BigQuery + Firestore
- **Integration:** ServiceNow bidirectional sync

**Features:**
- Case assignment
- Status tracking (New, Investigating, False Positive, Confirmed, Resolved)
- Notes and attachments
- Escalation workflows
- SLA tracking

**Development:** 6 weeks

---

#### 26. Feedback Service
**Purpose:** Analyst feedback loop for continuous improvement.

**Tech Stack:**
- **Runtime:** Cloud Run
- **Storage:** BigQuery
- **ML Pipeline:** Vertex AI

**Features:**
- Verdict tracking (True Positive, False Positive, Benign Positive)
- Detection rule tuning
- Whitelist recommendations
- Scoring model feedback

**Development:** 5 weeks

---

#### 27. Playbook Service (SOAR-lite)
**Purpose:** Automated response actions.

**Tech Stack:**
- **Runtime:** Cloud Run
- **Workflow:** Cloud Workflows or Temporal
- **Language:** Python

**Playbook Example:**
```yaml
name: "Ransomware Response"
trigger:
  - detection.threat_type == "ransomware"
  - detection.severity == "CRITICAL"

actions:
  - name: "Isolate host"
    service: "mde_api"
    action: "isolate_machine"
    params:
      hostname: "{{ detection.hostname }}"
  
  - name: "Create P1 case"
    service: "servicenow"
    action: "create_incident"
    params:
      urgency: 1
      assignment_group: "SOC Tier 2"
  
  - name: "Notify CISO"
    service: "email"
    params:
      to: ["ciso@example.com"]
      subject: "CRITICAL: Ransomware detected"
```

**Development:** 8 weeks

**Risks:**
- **CRITICAL:** Automated actions cause outage
- **MITIGATION:** Extensive testing, manual approval for destructive actions

---

#### 28. ML Service
**Purpose:** Machine learning for anomaly detection.

**Tech Stack:**
- **Platform:** Vertex AI (GCP) / SageMaker (AWS)
- **Framework:** TensorFlow / PyTorch
- **Feature Store:** Feast or custom
- **Language:** Python

**ML Models:**

**1. IOC Scoring Model**
- **Input:** IOC features (source, age, threat type, etc.)
- **Output:** Confidence score 0-1
- **Algorithm:** Gradient Boosting (XGBoost)

**2. Anomaly Detection**
- **Input:** User/host behavior features
- **Output:** Anomaly score
- **Algorithm:** Isolation Forest or Autoencoder

**3. False Positive Prediction**
- **Input:** Detection features + historical verdicts
- **Output:** Probability of false positive
- **Algorithm:** Random Forest

**Development:** 10 weeks

**Risks:**
- **HIGH:** Model drift degrades performance
- **MEDIUM:** ML adds latency
- **MITIGATION:** Model monitoring, A/B testing, async inference

---

### Phase 4 Timeline (Months 15-18)

**Month 15:**
- Threat Hunting Service (8 weeks)
- Backfill Service (6 weeks)

**Month 16:**
- Ad-hoc Detection Service (5 weeks)
- Case Manager (6 weeks)
- Feedback Service (5 weeks)

**Month 17:**
- Playbook Service (8 weeks)
- ML Service (10 weeks start)

**Month 18:**
- ML Service completion
- Final integration testing
- Documentation
- Training materials
- **Milestone M6:** V1.0 complete

**Phase 4 Deliverables:**
- ✅ Advanced threat hunting console
- ✅ Automated response playbooks
- ✅ ML-powered scoring and anomaly detection
- ✅ Complete case management
- ✅ Analyst feedback loop

---

## Detailed Service Specifications

[Previous service details from Phase 1-4 sections above provide the detailed specifications]

---

## Technology Stack

### Infrastructure Layer

**Cloud Platform:** Google Cloud Platform (Primary), AWS (Fallback)
- **Compute:** Cloud Run (serverless containers), GKE (Kubernetes for stateful services)
- **Storage:** BigQuery, Cloud Storage, Firestore
- **Caching:** Cloud Memorystore (Redis)
- **Networking:** Cloud Load Balancing, Cloud CDN, VPC
- **Security:** Cloud Armor, Secret Manager, Cloud KMS

### Application Layer

**Languages:**
- **Python 3.11+:** Primary language for most services
- **Go 1.21+:** Performance-critical services (Detection, Collection)
- **SQL:** BigQuery analytics, queries
- **JavaScript/TypeScript:** Web UI (React)

**Frameworks:**
- **FastAPI:** REST API services
- **Flask:** Simple services
- **gRPC:** Service-to-service communication
- **SQLAlchemy:** Database ORM

### Data Layer

**Databases:**
- **BigQuery:** Analytical data warehouse (IOCs, activity logs, detections)
- **Firestore:** Operational metadata (watermarks, config, user state)
- **Redis:** Hot cache (IOCs, enrichment results)

**Message Queue:**
- **Cloud Pub/Sub:** Event streaming, async messaging

**Data Pipeline:**
- **Dataflow:** Batch and streaming data processing
- **Cloud Composer (Airflow):** Workflow orchestration

### Observability Stack

**Monitoring:**
- **Cloud Monitoring:** Metrics collection and dashboards
- **Prometheus:** Alternative metrics (if on-prem)
- **Grafana:** Visualization

**Logging:**
- **Cloud Logging:** Centralized structured logging
- **Log severity levels:** DEBUG, INFO, WARNING, ERROR, CRITICAL

**Tracing:**
- **Cloud Trace:** Distributed tracing
- **OpenTelemetry:** Instrumentation

**Alerting:**
- **Cloud Alerting → PagerDuty:** On-call escalation
- **Slack:** Team notifications

### Security Stack

**Authentication:**
- **Cloud IAM:** Service-to-service auth
- **OAuth 2.0 / OIDC:** User authentication
- **Okta / Auth0:** Identity provider

**Secrets Management:**
- **Secret Manager:** API keys, credentials
- **KMS:** Encryption key management

**Network Security:**
- **Cloud Armor:** DDoS protection, WAF
- **VPC Service Controls:** Data exfiltration prevention
- **Cloud NAT:** Egress IP control

### Development Stack

**Version Control:**
- **Git:** Source control
- **GitHub / GitLab:** Code hosting, code review

**CI/CD:**
- **Cloud Build:** Build automation
- **GitHub Actions:** Alternative CI
- **Terraform:** Infrastructure as Code
- **Helm:** Kubernetes package management

**Testing:**
- **pytest:** Unit and integration tests
- **Locust:** Load testing
- **SonarQube:** Code quality

**Development:**
- **VS Code:** IDE
- **Docker:** Local development
- **pre-commit:** Code linting

### External Integrations

**Threat Intelligence:**
- **AlienVault OTX API**
- **abuse.ch API**
- **MISP API**
- **VirusTotal API**
- **PassiveTotal API**
- **Shodan API**

**Data Sources:**
- **Trino:** Proxy, DNS, Sinkhole logs
- **BigQuery:** MDE, CrowdStrike logs

**Ticketing:**
- **ServiceNow REST API**

**Communication:**
- **Slack API**
- **SendGrid (Email)**

**GeoIP:**
- **MaxMind GeoIP2**

---

## Risk Register

### Phase 1 Risks (Critical)

| Risk ID | Risk Description | Probability | Impact | Mitigation | Owner |
|---------|-----------------|-------------|--------|------------|-------|
| P1-R1 | BigQuery costs exceed budget due to poor query optimization | HIGH | HIGH | - Implement query cost estimation<br>- Set daily/monthly quotas<br>- Review expensive queries weekly | Platform Lead |
| P1-R2 | False positive rate >20%, SOC overwhelmed | MEDIUM | CRITICAL | - Conservative scoring initially<br>- Analyst feedback loop<br>- Tune thresholds weekly | Detection Lead |
| P1-R3 | External API rate limits block IOC collection | HIGH | HIGH | - Aggressive caching (7 day TTL)<br>- Respect API limits strictly<br>- Fallback to cached data | Integration Lead |
| P1-R4 | Security vulnerability in API Gateway allows unauthorized access | MEDIUM | CRITICAL | - Security audit before prod<br>- Penetration testing<br>- Regular security scans | Security Lead |
| P1-R5 | Collection watermark corruption causes duplicate/missing data | MEDIUM | HIGH | - Atomic watermark updates<br>- Watermark validation<br>- Manual override capability | Data Lead |
| P1-R6 | ServiceNow API failures prevent case creation | MEDIUM | HIGH | - Queue for retry<br>- Email fallback<br>- Alert on queue depth | Integration Lead |
| P1-R7 | Detection latency >10 minutes under load | MEDIUM | MEDIUM | - Load testing at 2x expected volume<br>- Auto-scaling configuration<br>- Cache optimization | Platform Lead |

### Phase 2 Risks

| Risk ID | Risk Description | Probability | Impact | Mitigation | Owner |
|---------|-----------------|-------------|--------|------------|-------|
| P2-R1 | Enrichment API costs exceed $10K/month | MEDIUM | MEDIUM | - Tier enrichment (basic vs full)<br>- Cache for 7 days<br>- Monitor costs weekly | FinOps |
| P2-R2 | Analytics jobs too slow, block daily schedule | MEDIUM | MEDIUM | - Optimize BigQuery queries<br>- Use materialized views<br>- Incremental processing | Analytics Lead |
| P2-R3 | Behavioral detection (beaconing, DGA) has high FP rate | HIGH | MEDIUM | - Tune thresholds with analyst input<br>- A/B test rules<br>- Allowlist known patterns | Detection Lead |
| P2-R4 | Threat intel scoring model doesn't improve accuracy | MEDIUM | LOW | - Validate against ground truth<br>- Compare to baseline<br>- Iterate model | Data Science |

### Phase 3 Risks

| Risk ID | Risk Description | Probability | Impact | Mitigation | Owner |
|---------|-----------------|-------------|--------|------------|-------|
| P3-R1 | Observability overhead impacts performance | LOW | MEDIUM | - Sample high-cardinality metrics<br>- Async logging<br>- Batch metrics | Platform Lead |
| P3-R2 | Backfill jobs overwhelm data sources | MEDIUM | HIGH | - Rate limit backfills<br>- Backfill windows (off-peak)<br>- Manual approval for large gaps | Data Lead |
| P3-R3 | False backfill triggers waste resources | MEDIUM | MEDIUM | - Validate gaps before backfill<br>- Backfill approval workflow<br>- Cost tracking | Operations |
| P3-R4 | Audit log becomes too large (>1TB/month) | MEDIUM | MEDIUM | - Partition by month<br>- Archive old data to cold storage<br>- Summarize instead of raw logs | Data Lead |

### Phase 4 Risks

| Risk ID | Risk Description | Probability | Impact | Mitigation | Owner |
|---------|-----------------|-------------|--------|------------|-------|
| P4-R1 | Automated playbooks cause production outage | LOW | CRITICAL | - Extensive testing in staging<br>- Manual approval for destructive actions<br>- Rollback capability | SOAR Lead |
| P4-R2 | ML model drift degrades detection accuracy | MEDIUM | HIGH | - Model monitoring<br>- Weekly performance review<br>- A/B testing new models | ML Lead |
| P4-R3 | Threat hunting queries timeout on large datasets | MEDIUM | MEDIUM | - Query cost estimation<br>- Timeouts (5 min max)<br>- Suggest using materialized views | Query Lead |
| P4-R4 | Case manager sync issues with ServiceNow | MEDIUM | MEDIUM | - Bidirectional sync validation<br>- Conflict resolution logic<br>- Manual override | Integration Lead |

### Technical Debt Risks

| Risk ID | Risk Description | Probability | Impact | Mitigation | Owner |
|---------|-----------------|-------------|--------|------------|-------|
| TD-R1 | Lack of automated testing slows development | HIGH | MEDIUM | - 80% code coverage target<br>- CI/CD gate on tests<br>- Integration test suite | QA Lead |
| TD-R2 | No disaster recovery plan | MEDIUM | CRITICAL | - Document DR procedures<br>- Quarterly DR tests<br>- Backup/restore automation | Platform Lead |
| TD-R3 | Poor documentation hinders onboarding | HIGH | MEDIUM | - Docs-as-code<br>- Runbook for each service<br>- Architecture diagrams | Tech Writer |
| TD-R4 | Monolithic services hard to scale | LOW | MEDIUM | - Service decomposition as needed<br>- Monitor service boundaries<br>- Refactor incrementally | Architect |

---

## Dependencies & Prerequisites

### Infrastructure Prerequisites
- **GCP Project:** Provisioned with billing enabled
- **Networking:** VPC, subnets, firewall rules configured
- **IAM:** Service accounts with least privilege
- **Quotas:** BigQuery slot reservation, API quotas increased
- **Cost:** $50K initial budget for infrastructure

### Data Source Access
- **Trino:** Read access to proxy, DNS, sinkhole tables
- **BigQuery:** Read access to MDE, CrowdStrike datasets
- **Credentials:** Service account keys for data sources

### External API Access
- **AlienVault OTX:** API key (free tier: 10K requests/day)
- **abuse.ch:** API access
- **MISP:** Instance URL and API key
- **VirusTotal:** API key (4 requests/min free, or paid tier)
- **PassiveTotal:** API key (paid)
- **MaxMind GeoIP:** License key
- **Shodan:** API key (paid)

### Integrations
- **ServiceNow:** Instance URL, credentials, API access
- **Slack:** Webhook URL or OAuth app
- **Email:** SendGrid API key or SMTP credentials
- **SSO:** Okta/Auth0 tenant and SAML configuration

### Team Prerequisites
- **Platform Engineer:** GCP/AWS experience, Python/Go
- **Security Engineer:** Threat detection expertise
- **Data Engineer:** BigQuery, data pipelines
- **ML Engineer:** (Phase 4) Model development
- **DevOps Engineer:** CI/CD, infrastructure
- **UI Developer:** React, web development

### Compliance & Security
- **Security Review:** Quarterly audits
- **Penetration Testing:** Before each phase goes to prod
- **Compliance:** SOC 2 Type II requirements (if applicable)
- **Data Retention:** Policy defined (7 years for audit logs)

---

## Success Criteria by Phase

### Phase 1 Success Criteria (MVP)
✅ **Functional:**
- Detect known IOCs with <5 min latency
- Ingest from all 5 data sources (Proxy, DNS, Sinkhole, MDE, CrowdStrike)
- Create ServiceNow cases automatically
- Web dashboard shows detections

✅ **Performance:**
- Process 1M events/day
- Detection latency <5 minutes (p95)
- API response time <500ms (p95)
- 99% uptime

✅ **Quality:**
- False positive rate <10%
- Zero critical security vulnerabilities
- Code coverage >70%

✅ **Operational:**
- Runbooks for each service
- On-call rotation established
- Monitoring dashboards deployed

### Phase 2 Success Criteria (Analytics)
✅ **Functional:**
- 5+ analytics jobs running daily
- IOC enrichment >80% coverage
- Advanced search capabilities
- Threat hunting console operational

✅ **Performance:**
- Process 5M events/day
- Analytics jobs complete in <2 hours
- Enrichment latency <1 second (cached)

✅ **Quality:**
- Behavioral detection FP rate <15%
- Enrichment accuracy >95%

### Phase 3 Success Criteria (Operations)
✅ **Functional:**
- Automated backfill for failed collections
- Comprehensive observability (metrics, logs, traces)
- Audit logging for compliance
- Circuit breakers for external APIs

✅ **Performance:**
- Process 10M events/day
- 99.9% uptime
- MTTD <5 minutes
- MTTR <30 minutes

✅ **Quality:**
- Zero data loss incidents
- All services auto-scaling
- Disaster recovery tested

### Phase 4 Success Criteria (Advanced)
✅ **Functional:**
- Ad-hoc threat hunting with saved queries
- Automated response playbooks (3+ playbooks)
- ML-powered scoring operational
- Case management with SLA tracking

✅ **Performance:**
- ML inference latency <200ms
- Threat hunt queries complete <60 seconds

✅ **Quality:**
- ML model AUC >0.85
- Playbook success rate >95%
- Analyst satisfaction score >4/5

---

## Budget Estimate

### Infrastructure Costs (Monthly)

**Compute:**
- Cloud Run: ~$2,000/month (average 20 services, 1GB memory each)
- GKE (if needed): ~$500/month (3 node cluster for stateful services)

**Storage:**
- BigQuery Storage: ~$2,000/month (10TB data)
- BigQuery Queries: ~$3,000/month (500GB processed/day)
- Cloud Storage: ~$100/month (backups, logs)
- Firestore: ~$200/month (metadata)
- Redis (Memorystore): ~$500/month (10GB)

**Networking:**
- Load Balancing: ~$200/month
- Egress: ~$500/month

**Observability:**
- Cloud Monitoring: ~$300/month
- Cloud Logging: ~$500/month

**Total Infrastructure:** ~$9,800/month → ~$120K/year

### External API Costs (Monthly)
- VirusTotal (paid tier): ~$500/month
- PassiveTotal: ~$1,000/month
- MaxMind GeoIP: ~$100/month
- Shodan: ~$50/month
- SendGrid (email): ~$50/month

**Total External APIs:** ~$1,700/month → ~$20K/year

### Personnel Costs (18 months)
Assuming team of 5:
- Platform Engineer: $200K/year
- Security Engineer: $180K/year
- Data Engineer: $180K/year
- DevOps Engineer: $160K/year
- UI Developer: $150K/year (Part-time, 50%)

**Total Personnel:** ~$870K/year × 1.5 years = ~$1.3M

### One-Time Costs
- Security audits: $50K
- Penetration testing: $30K
- Training/Certifications: $20K

**Total One-Time:** ~$100K

### Total Project Budget
- Infrastructure (18 months): $180K
- External APIs (18 months): $30K
- Personnel: $1.3M
- One-Time: $100K

**Total: ~$1.61M over 18 months**

---

## Project Governance

### Roles & Responsibilities

**Project Sponsor:** CISO / CTO
- Budget approval
- Resource allocation
- Strategic direction

**Project Lead:** VP Technology Risk (Chase)
- Overall project delivery
- Stakeholder management
- Risk management

**Technical Leads:**
- Platform Lead: Infrastructure, deployment
- Detection Lead: Detection logic, scoring
- Data Lead: Data pipelines, storage
- Security Lead: Security, compliance
- Integration Lead: External integrations

**Stakeholders:**
- SOC Team: End users, requirements input
- IT Security: Compliance, policies
- IT Operations: Infrastructure support
- Legal: Data privacy, compliance

### Decision Making

**Architecture Decisions:**
- Document in Architecture Decision Records (ADRs)
- Review by technical leads
- Final approval by Project Lead

**Prioritization:**
- Weekly backlog grooming
- Monthly roadmap review
- Quarterly OKR planning

### Communication

**Daily:**
- Standup (async via Slack)

**Weekly:**
- Technical sync (1 hour)
- Demo to stakeholders (30 min)

**Monthly:**
- Steering committee (exec update)
- Retrospective
- Metrics review

**Quarterly:**
- Roadmap planning
- Budget review
- Security review

---

## Conclusion

Threat XDR is an 18-month effort to build a comprehensive threat detection and response platform. With a team of 5 engineers and a budget of ~$1.6M, the platform will:

- Detect threats in real-time (<5 min MTTD)
- Process 10M+ events/day
- Automate case creation and response
- Enable proactive threat hunting
- Provide deep behavioral analytics

Success depends on:
✅ Strong partnership between Security and Engineering
✅ Iterative development with constant SOC feedback
✅ Rigorous testing and security practices
✅ Prudent cost management (especially BigQuery)
✅ Building for scale from day one

The phased approach allows for:
- **MVP in 6 months** - Start delivering value quickly
- **Analytics in 10 months** - Proactive threat detection
- **Production-hardened in 14 months** - Enterprise-grade reliability
- **V1.0 in 18 months** - Complete feature set with ML

**Next Steps:**
1. Secure budget approval
2. Hire core team (2 months)
3. Provision infrastructure (1 month)
4. Kickoff Phase 1 development

---

**Document Version:** 1.0  
**Last Updated:** January 1, 2026  
**Next Review:** February 1, 2026
