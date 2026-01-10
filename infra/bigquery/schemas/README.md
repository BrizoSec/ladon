# BigQuery Schema - Threat Intelligence Tables

This directory contains BigQuery DDL (Data Definition Language) scripts for LADON's threat intelligence tracking system.

## Tables

### 1. `threats` Table
Stores comprehensive threat intelligence including actors, campaigns, and malware families with associated MITRE ATT&CK TTPs.

**Key Features:**
- Partitioned by `last_seen` date for query performance
- Clustered by `threat_category`, `threat_type`, `is_active`
- Stores MITRE ATT&CK techniques as JSON
- Supports full threat actor/campaign/malware tracking

**Schema File:** `threats.sql`

### 2. `threat_ioc_associations` Table
Many-to-many relationship table linking threats to specific IOCs with relationship context.

**Key Features:**
- Partitioned by `last_seen` date
- Clustered by `threat_id`, `ioc_type`, `relationship_type`
- Tracks observation count and confidence
- Supports bidirectional lookup (threat→IOCs, IOC→threats)

**Schema File:** `threat_ioc_associations.sql`

## Deployment

### Prerequisites
- Google Cloud Project with BigQuery enabled
- `gcloud` CLI installed and authenticated
- BigQuery dataset `ladon` created

### Create Dataset (if not exists)
```bash
bq mk --dataset \
  --location=US \
  --description="LADON Platform - Threat Intelligence" \
  YOUR_PROJECT_ID:ladon
```

### Deploy Tables

#### Option 1: Using bq CLI
```bash
# Deploy threats table
bq query \
  --use_legacy_sql=false \
  --project_id=YOUR_PROJECT_ID \
  < threats.sql

# Deploy threat_ioc_associations table
bq query \
  --use_legacy_sql=false \
  --project_id=YOUR_PROJECT_ID \
  < threat_ioc_associations.sql
```

#### Option 2: Using the deployment script
```bash
./deploy_schemas.sh YOUR_PROJECT_ID
```

#### Option 3: Using Terraform
See `../terraform/modules/bigquery/` for Terraform configurations.

## Table Relationships

```
┌─────────────────────────────────────────┐
│            threats                       │
│  - threat_id (PK)                       │
│  - name                                 │
│  - threat_category (actor/campaign)     │
│  - threat_type (c2/malware/phishing)    │
│  - techniques (MITRE ATT&CK JSON)       │
│  - tactics (MITRE ATT&CK)               │
│  - severity, confidence                 │
│  - first_seen, last_seen                │
└─────────────────┬───────────────────────┘
                  │
                  │ 1:N
                  │
                  ↓
┌─────────────────────────────────────────┐
│     threat_ioc_associations             │
│  - threat_id (FK)                       │
│  - ioc_value                            │
│  - ioc_type                             │
│  - relationship_type                    │
│  - confidence                           │
│  - observation_count                    │
│  - first_seen, last_seen                │
└─────────────────┬───────────────────────┘
                  │
                  │ N:1
                  │
                  ↓
┌─────────────────────────────────────────┐
│              iocs                        │
│  - ioc_value                            │
│  - ioc_type                             │
│  - threat_type                          │
│  - confidence                           │
└─────────────────────────────────────────┘
```

## Views

### Active Threats View
```sql
SELECT * FROM `ladon.active_threats`
WHERE severity IN ('high', 'critical');
```

### APT Threats View
```sql
SELECT * FROM `ladon.apt_threats`
ORDER BY confidence DESC;
```

### High Confidence Associations
```sql
SELECT * FROM `ladon.high_confidence_associations`
WHERE ioc_type = 'domain';
```

### IOC-to-Threat Lookup
```sql
SELECT * FROM `ladon.ioc_threat_lookup`
WHERE ioc_value = 'malicious.com';
```

## Common Queries

### Get all IOCs for a threat
```sql
SELECT
  ioc_value,
  ioc_type,
  relationship_type,
  confidence
FROM `ladon.threat_ioc_associations`
WHERE threat_id = 'apt28_2026'
ORDER BY confidence DESC;
```

### Get all threats for an IOC
```sql
SELECT
  t.name,
  t.threat_category,
  t.severity,
  a.confidence,
  a.relationship_type
FROM `ladon.threat_ioc_associations` a
JOIN `ladon.threats` t ON a.threat_id = t.threat_id
WHERE a.ioc_value = 'evil.com'
  AND a.ioc_type = 'domain';
```

### Find infrastructure shared across threats
```sql
SELECT
  ioc_value,
  ioc_type,
  COUNT(DISTINCT threat_id) AS shared_count,
  ARRAY_AGG(DISTINCT threat_id) AS threats
FROM `ladon.threat_ioc_associations`
GROUP BY ioc_value, ioc_type
HAVING shared_count > 1
ORDER BY shared_count DESC;
```

### MITRE ATT&CK technique coverage
```sql
WITH techniques_expanded AS (
  SELECT
    JSON_EXTRACT_SCALAR(technique, '$.technique_id') AS technique_id,
    JSON_EXTRACT_SCALAR(technique, '$.technique_name') AS technique_name,
    JSON_EXTRACT_SCALAR(technique, '$.tactic') AS tactic
  FROM `ladon.threats`,
  UNNEST(JSON_EXTRACT_ARRAY(techniques)) AS technique
  WHERE is_active = TRUE
)
SELECT
  tactic,
  technique_id,
  technique_name,
  COUNT(*) AS threat_count
FROM techniques_expanded
GROUP BY tactic, technique_id, technique_name
ORDER BY threat_count DESC;
```

## Partitioning and Clustering

### Partitioning
Both tables are partitioned by date on the `last_seen` field:
- **Benefits:** Faster queries when filtering by date, lower costs
- **Retention:** Consider setting partition expiration for old data
- **Best Practice:** Always include partition filter in queries

```sql
-- Good: Uses partition filter
SELECT * FROM `ladon.threats`
WHERE DATE(last_seen) >= DATE_SUB(CURRENT_DATE(), INTERVAL 30 DAYS);

-- Bad: Full table scan
SELECT * FROM `ladon.threats`
WHERE name LIKE '%APT%';
```

### Clustering
Tables are clustered for optimal query performance:

**threats:** `threat_category`, `threat_type`, `is_active`
**threat_ioc_associations:** `threat_id`, `ioc_type`, `relationship_type`

Queries filtering/sorting by these fields will be faster.

## Cost Optimization

### Query Cost Estimation
```bash
# Estimate query cost before running
bq query --dry_run --use_legacy_sql=false 'YOUR_QUERY_HERE'
```

### Best Practices
1. **Always use partition filters** - Include `DATE(last_seen)` filter
2. **Select specific columns** - Avoid `SELECT *`
3. **Use clustering fields** - Filter/sort by clustered columns
4. **Materialize common queries** - Use materialized views for dashboards
5. **Set table expiration** - Archive old threat data after 2+ years

## Monitoring

### Table Size
```sql
SELECT
  table_name,
  ROUND(size_bytes / POW(10, 9), 2) AS size_gb,
  row_count
FROM `ladon.__TABLES__`
WHERE table_name IN ('threats', 'threat_ioc_associations');
```

### Query Performance
```sql
-- Check slow queries in logs
SELECT
  job_id,
  query,
  total_bytes_processed / POW(10, 9) AS gb_processed,
  total_slot_ms / 1000 AS execution_seconds
FROM `region-us`.INFORMATION_SCHEMA.JOBS_BY_PROJECT
WHERE creation_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
  AND state = 'DONE'
  AND LOWER(query) LIKE '%threat%'
ORDER BY total_slot_ms DESC
LIMIT 10;
```

## Data Retention

Recommended retention policies:
- **Active threats:** Indefinite
- **Inactive threats:** 2 years
- **Threat-IOC associations:** 1 year for inactive

Set partition expiration:
```sql
ALTER TABLE `ladon.threat_ioc_associations`
SET OPTIONS (partition_expiration_days=365);
```

## Backup and Recovery

### Export to Cloud Storage
```bash
bq extract \
  --destination_format=NEWLINE_DELIMITED_JSON \
  ladon.threats \
  gs://your-bucket/backups/threats/$(date +%Y%m%d)/*.json
```

### Import from Cloud Storage
```bash
bq load \
  --source_format=NEWLINE_DELIMITED_JSON \
  ladon.threats \
  gs://your-bucket/backups/threats/20260105/*.json
```

## Security

### IAM Permissions
Recommended roles:
- **Analysts:** `roles/bigquery.dataViewer` on dataset
- **Services:** `roles/bigquery.dataEditor` on dataset
- **Admins:** `roles/bigquery.admin` on project

### Row-Level Security
For sensitive threat intelligence:
```sql
-- Create policy (example)
CREATE ROW ACCESS POLICY sensitive_threats
ON `ladon.threats`
GRANT TO ("group:soc-team@example.com")
FILTER USING (severity IN ('high', 'critical'));
```

## Troubleshooting

### Common Issues

**Issue:** Query timeout on large date ranges
**Solution:** Add partition filter or reduce date range

**Issue:** High query costs
**Solution:** Use materialized views for aggregations

**Issue:** Slow threat lookups
**Solution:** Ensure queries use clustering fields

**Issue:** Duplicate threat-IOC associations
**Solution:** Use `MERGE` statements instead of `INSERT`

## Support

For issues or questions:
- Check query execution in BigQuery Console
- Review partition and clustering effectiveness
- Monitor costs in Cloud Console billing
