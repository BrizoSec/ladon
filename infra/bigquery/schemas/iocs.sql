-- =============================================================================
-- BigQuery Table: iocs
-- Description: Stores Indicators of Compromise (IOCs) from multiple threat
--              intelligence feeds with enrichment data
-- =============================================================================

CREATE TABLE IF NOT EXISTS `threat_xdr.iocs` (
  -- Core Identification
  ioc_id STRING NOT NULL OPTIONS(description="Unique identifier for the IOC (hash of value+type+source)"),
  ioc_value STRING NOT NULL OPTIONS(description="The IOC value (IP, domain, hash, URL, etc.)"),
  ioc_type STRING NOT NULL OPTIONS(description="Type: ipv4, ipv6, domain, url, hash_md5, hash_sha256, email, etc."),

  -- Classification
  threat_type STRING NOT NULL OPTIONS(description="Threat type: malware, c2, phishing, ransomware, exploit, etc."),
  threat_family STRING OPTIONS(description="Associated malware family or threat group"),

  -- Confidence and Severity
  confidence FLOAT64 NOT NULL OPTIONS(description="Confidence score (0.0-1.0)"),
  severity STRING OPTIONS(description="Severity level: low, medium, high, critical"),

  -- Source Information
  source STRING NOT NULL OPTIONS(description="Intelligence source: alienvault_otx, abuse_ch, misp, custom, etc."),
  source_reputation FLOAT64 OPTIONS(description="Reputation score of the source (0.0-1.0)"),

  -- Temporal Information
  first_seen TIMESTAMP NOT NULL OPTIONS(description="First time this IOC was observed"),
  last_seen TIMESTAMP NOT NULL OPTIONS(description="Most recent observation of this IOC"),
  expiration_date TIMESTAMP OPTIONS(description="When this IOC expires or is no longer valid"),

  -- Enrichment Data
  enrichment STRING OPTIONS(description="JSON object containing enrichment data from VirusTotal, PassiveTotal, etc."),

  -- Context
  description STRING OPTIONS(description="Description of the IOC and associated threat"),
  tags ARRAY<STRING> OPTIONS(description="Tags for categorization and filtering"),
  reference_urls ARRAY<STRING> OPTIONS(description="External references and reports"),

  -- Metadata
  metadata STRING OPTIONS(description="JSON object with additional custom metadata"),

  -- Cache Information
  is_cached BOOL DEFAULT FALSE OPTIONS(description="Whether this IOC is currently cached in Redis"),
  cache_ttl_hours INT64 OPTIONS(description="TTL for Redis cache in hours"),

  -- Status
  is_active BOOL DEFAULT TRUE OPTIONS(description="Whether IOC is currently active/relevant"),
  false_positive BOOL DEFAULT FALSE OPTIONS(description="Marked as false positive"),
  whitelist_reason STRING OPTIONS(description="Reason for whitelisting if applicable"),

  -- Detection Statistics
  detection_count INT64 DEFAULT 0 OPTIONS(description="Number of times this IOC triggered a detection"),
  last_detection_time TIMESTAMP OPTIONS(description="Last time this IOC triggered a detection"),

  -- Audit Fields
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP() OPTIONS(description="Record creation timestamp"),
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP() OPTIONS(description="Last update timestamp")
)
PARTITION BY DATE(last_seen)
CLUSTER BY ioc_type, threat_type, source, is_active
OPTIONS(
  description="Indicators of Compromise from multiple threat intelligence feeds",
  labels=[("service", "ladon-threat-xdr"), ("data_type", "ioc")]
);

-- =============================================================================
-- Index-like optimization: Create search-optimized clustering
-- BigQuery doesn't have traditional indexes, but clustering provides similar benefits
-- =============================================================================

-- =============================================================================
-- View: active_iocs
-- Description: Only active, non-false-positive IOCs
-- =============================================================================

CREATE OR REPLACE VIEW `threat_xdr.active_iocs` AS
SELECT
  ioc_id,
  ioc_value,
  ioc_type,
  threat_type,
  threat_family,
  confidence,
  severity,
  source,
  first_seen,
  last_seen,
  tags,
  reference_urls,
  detection_count,
  last_detection_time
FROM `threat_xdr.iocs`
WHERE is_active = TRUE
  AND false_positive = FALSE
  AND (expiration_date IS NULL OR expiration_date > CURRENT_TIMESTAMP());

-- =============================================================================
-- View: hot_iocs
-- Description: Recent, high-confidence IOCs for Redis caching
-- =============================================================================

CREATE OR REPLACE VIEW `threat_xdr.hot_iocs` AS
SELECT
  ioc_id,
  ioc_value,
  ioc_type,
  threat_type,
  threat_family,
  confidence,
  severity,
  source,
  first_seen,
  last_seen,
  tags,
  detection_count
FROM `threat_xdr.iocs`
WHERE is_active = TRUE
  AND false_positive = FALSE
  AND confidence >= 0.7
  AND last_seen >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 48 HOUR)
ORDER BY confidence DESC, last_seen DESC;

-- =============================================================================
-- View: critical_iocs
-- Description: Critical severity IOCs requiring immediate attention
-- =============================================================================

CREATE OR REPLACE VIEW `threat_xdr.critical_iocs` AS
SELECT
  ioc_id,
  ioc_value,
  ioc_type,
  threat_type,
  threat_family,
  confidence,
  source,
  first_seen,
  last_seen,
  description,
  tags,
  reference_urls,
  detection_count,
  last_detection_time
FROM `threat_xdr.iocs`
WHERE is_active = TRUE
  AND false_positive = FALSE
  AND severity = 'critical'
ORDER BY last_seen DESC;

-- =============================================================================
-- View: ioc_detections
-- Description: IOCs that have triggered detections
-- =============================================================================

CREATE OR REPLACE VIEW `threat_xdr.ioc_detections` AS
SELECT
  ioc_id,
  ioc_value,
  ioc_type,
  threat_type,
  threat_family,
  confidence,
  severity,
  source,
  detection_count,
  last_detection_time,
  first_seen,
  last_seen
FROM `threat_xdr.iocs`
WHERE detection_count > 0
ORDER BY detection_count DESC, last_detection_time DESC;

-- =============================================================================
-- View: iocs_by_source
-- Description: IOC counts grouped by source
-- =============================================================================

CREATE OR REPLACE VIEW `threat_xdr.iocs_by_source` AS
SELECT
  source,
  COUNT(*) as total_iocs,
  COUNT(CASE WHEN is_active = TRUE THEN 1 END) as active_iocs,
  COUNT(CASE WHEN false_positive = TRUE THEN 1 END) as false_positives,
  ROUND(AVG(confidence), 3) as avg_confidence,
  COUNT(CASE WHEN detection_count > 0 THEN 1 END) as iocs_with_detections,
  SUM(detection_count) as total_detections,
  MAX(last_seen) as latest_ioc_date
FROM `threat_xdr.iocs`
GROUP BY source
ORDER BY total_iocs DESC;

-- =============================================================================
-- Materialized View: ioc_stats_mv
-- Description: Pre-computed IOC statistics for dashboards
-- Refresh: Daily
-- =============================================================================

CREATE MATERIALIZED VIEW IF NOT EXISTS `threat_xdr.ioc_stats_mv`
PARTITION BY stats_date
CLUSTER BY ioc_type, threat_type
OPTIONS(
  enable_refresh=true,
  refresh_interval_minutes=1440,  -- 24 hours
  description="Daily IOC statistics materialized view"
)
AS
SELECT
  CURRENT_DATE() as stats_date,
  ioc_type,
  threat_type,
  source,
  COUNT(*) as total_count,
  COUNT(CASE WHEN is_active = TRUE THEN 1 END) as active_count,
  COUNT(CASE WHEN false_positive = TRUE THEN 1 END) as false_positive_count,
  ROUND(AVG(confidence), 3) as avg_confidence,
  MIN(confidence) as min_confidence,
  MAX(confidence) as max_confidence,
  COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_count,
  COUNT(CASE WHEN severity = 'high' THEN 1 END) as high_count,
  COUNT(CASE WHEN severity = 'medium' THEN 1 END) as medium_count,
  COUNT(CASE WHEN severity = 'low' THEN 1 END) as low_count,
  SUM(detection_count) as total_detections,
  COUNT(CASE WHEN detection_count > 0 THEN 1 END) as iocs_with_detections,
  MIN(first_seen) as earliest_first_seen,
  MAX(last_seen) as latest_last_seen
FROM `threat_xdr.iocs`
GROUP BY ioc_type, threat_type, source;

-- =============================================================================
-- Materialized View: ioc_trends_mv
-- Description: Daily IOC trends for time-series analysis
-- Refresh: Hourly
-- =============================================================================

CREATE MATERIALIZED VIEW IF NOT EXISTS `threat_xdr.ioc_trends_mv`
PARTITION BY trend_date
CLUSTER BY ioc_type
OPTIONS(
  enable_refresh=true,
  refresh_interval_minutes=60,  -- 1 hour
  description="Hourly IOC trends materialized view"
)
AS
SELECT
  DATE(last_seen) as trend_date,
  ioc_type,
  threat_type,
  COUNT(*) as ioc_count,
  COUNT(CASE WHEN is_active = TRUE THEN 1 END) as active_count,
  ROUND(AVG(confidence), 3) as avg_confidence,
  SUM(detection_count) as total_detections
FROM `threat_xdr.iocs`
WHERE last_seen >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 90 DAY)
GROUP BY trend_date, ioc_type, threat_type
ORDER BY trend_date DESC;

-- =============================================================================
-- Sample Queries
-- =============================================================================

-- Query 1: Get all active C2 IOCs from last 24 hours
-- SELECT * FROM `threat_xdr.active_iocs`
-- WHERE threat_type = 'c2'
--   AND last_seen >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
-- ORDER BY confidence DESC
-- LIMIT 100;

-- Query 2: Get IOCs that need to be cached (hot IOCs)
-- SELECT * FROM `threat_xdr.hot_iocs`
-- LIMIT 10000;

-- Query 3: Search for specific IOC value
-- SELECT * FROM `threat_xdr.iocs`
-- WHERE ioc_value = '192.0.2.1'
-- ORDER BY last_seen DESC;

-- Query 4: Get IOC statistics by type
-- SELECT * FROM `threat_xdr.ioc_stats_mv`
-- WHERE stats_date = CURRENT_DATE()
-- ORDER BY total_count DESC;

-- Query 5: Find IOCs with most detections
-- SELECT * FROM `threat_xdr.ioc_detections`
-- LIMIT 50;
