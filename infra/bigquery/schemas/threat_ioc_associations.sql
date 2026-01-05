-- =============================================================================
-- BigQuery Table: threat_ioc_associations
-- Description: Many-to-many relationship table linking threats to IOCs
--              Tracks which IOCs are associated with which threats
-- =============================================================================

CREATE TABLE IF NOT EXISTS `threat_xdr.threat_ioc_associations` (
  -- Association Keys
  threat_id STRING NOT NULL OPTIONS(description="Associated threat ID (FK to threats table)"),
  ioc_value STRING NOT NULL OPTIONS(description="Associated IOC value"),
  ioc_type STRING NOT NULL OPTIONS(description="IOC type (domain, ipv4, url, hash_md5, etc.)"),

  -- Relationship Context
  relationship_type STRING DEFAULT 'uses' OPTIONS(description="Type of relationship: uses, attributed_to, distributes, downloads, communicates_with"),
  confidence FLOAT64 DEFAULT 0.5 OPTIONS(description="Confidence in this association (0.0-1.0)"),

  -- Temporal Tracking
  first_seen TIMESTAMP NOT NULL OPTIONS(description="When this association was first observed"),
  last_seen TIMESTAMP NOT NULL OPTIONS(description="Most recent observation of this association"),
  observation_count INT64 DEFAULT 1 OPTIONS(description="Number of times this association was observed"),

  -- Intelligence Sources
  sources ARRAY<STRING> OPTIONS(description="Intelligence sources reporting this association"),
  reference_urls ARRAY<STRING> OPTIONS(description="URLs to threat reports mentioning this association"),

  -- Metadata
  notes STRING OPTIONS(description="Additional context or notes about the association"),
  tags ARRAY<STRING> OPTIONS(description="Classification tags for this association"),

  -- Audit Fields
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP() OPTIONS(description="Record creation timestamp"),
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP() OPTIONS(description="Last update timestamp")
)
PARTITION BY DATE(last_seen)
CLUSTER BY threat_id, ioc_type, relationship_type
OPTIONS(
  description="Association table linking threats to specific IOCs with relationship context",
  labels=[("service", "ladon-threat-xdr"), ("data_type", "threat_ioc_mapping")]
);

-- =============================================================================
-- Indexes and Views
-- =============================================================================

-- Create a view for high-confidence associations
CREATE OR REPLACE VIEW `threat_xdr.high_confidence_associations` AS
SELECT
  a.threat_id,
  t.name AS threat_name,
  t.threat_category,
  a.ioc_value,
  a.ioc_type,
  a.relationship_type,
  a.confidence,
  a.observation_count,
  a.last_seen,
  a.sources
FROM `threat_xdr.threat_ioc_associations` a
JOIN `threat_xdr.threats` t ON a.threat_id = t.threat_id
WHERE a.confidence >= 0.8
  AND t.is_active = TRUE
  AND DATE(a.last_seen) >= DATE_SUB(CURRENT_DATE(), INTERVAL 90 DAYS);

-- Create a view for IOC-to-threat reverse lookup
CREATE OR REPLACE VIEW `threat_xdr.ioc_threat_lookup` AS
SELECT
  a.ioc_value,
  a.ioc_type,
  COUNT(DISTINCT a.threat_id) AS associated_threat_count,
  ARRAY_AGG(STRUCT(
    t.threat_id,
    t.name,
    t.threat_category,
    t.severity,
    a.confidence,
    a.relationship_type
  ) ORDER BY a.confidence DESC LIMIT 10) AS threats,
  MAX(a.last_seen) AS last_associated
FROM `threat_xdr.threat_ioc_associations` a
JOIN `threat_xdr.threats` t ON a.threat_id = t.threat_id
WHERE t.is_active = TRUE
GROUP BY a.ioc_value, a.ioc_type;

-- Create a materialized view for association statistics
CREATE MATERIALIZED VIEW IF NOT EXISTS `threat_xdr.threat_ioc_stats_mv`
PARTITION BY stats_date
CLUSTER BY threat_id
AS
SELECT
  CURRENT_DATE() AS stats_date,
  threat_id,
  ioc_type,
  relationship_type,
  COUNT(*) AS association_count,
  COUNT(DISTINCT ioc_value) AS unique_iocs,
  AVG(confidence) AS avg_confidence,
  SUM(observation_count) AS total_observations,
  MAX(last_seen) AS most_recent_observation
FROM `threat_xdr.threat_ioc_associations`
WHERE DATE(last_seen) >= DATE_SUB(CURRENT_DATE(), INTERVAL 90 DAYS)
GROUP BY threat_id, ioc_type, relationship_type;

-- =============================================================================
-- Sample Queries
-- =============================================================================

-- Query 1: Get all IOCs for a specific threat
-- SELECT
--   ioc_value,
--   ioc_type,
--   relationship_type,
--   confidence,
--   observation_count,
--   last_seen,
--   sources
-- FROM `threat_xdr.threat_ioc_associations`
-- WHERE threat_id = 'threat_apt28_2026'
--   AND confidence >= 0.7
-- ORDER BY confidence DESC, last_seen DESC;

-- Query 2: Get all threats associated with a specific IOC
-- SELECT
--   t.threat_id,
--   t.name,
--   t.threat_category,
--   t.threat_type,
--   t.severity,
--   a.relationship_type,
--   a.confidence,
--   a.observation_count,
--   a.last_seen
-- FROM `threat_xdr.threat_ioc_associations` a
-- JOIN `threat_xdr.threats` t ON a.threat_id = t.threat_id
-- WHERE a.ioc_value = 'malicious.com'
--   AND a.ioc_type = 'domain'
--   AND t.is_active = TRUE
-- ORDER BY a.confidence DESC, a.last_seen DESC;

-- Query 3: Find IOCs shared across multiple threats (potential infrastructure reuse)
-- SELECT
--   ioc_value,
--   ioc_type,
--   COUNT(DISTINCT threat_id) AS threat_count,
--   ARRAY_AGG(DISTINCT threat_id) AS associated_threats,
--   AVG(confidence) AS avg_confidence,
--   MAX(last_seen) AS last_seen
-- FROM `threat_xdr.threat_ioc_associations`
-- WHERE DATE(last_seen) >= DATE_SUB(CURRENT_DATE(), INTERVAL 30 DAYS)
-- GROUP BY ioc_value, ioc_type
-- HAVING threat_count > 1
-- ORDER BY threat_count DESC, avg_confidence DESC;

-- Query 4: Get most prolific threats by IOC count
-- SELECT
--   a.threat_id,
--   t.name,
--   t.threat_category,
--   COUNT(DISTINCT a.ioc_value) AS unique_ioc_count,
--   COUNT(DISTINCT a.ioc_type) AS ioc_type_diversity,
--   AVG(a.confidence) AS avg_confidence,
--   MAX(a.last_seen) AS last_activity
-- FROM `threat_xdr.threat_ioc_associations` a
-- JOIN `threat_xdr.threats` t ON a.threat_id = t.threat_id
-- WHERE t.is_active = TRUE
-- GROUP BY a.threat_id, t.name, t.threat_category
-- ORDER BY unique_ioc_count DESC
-- LIMIT 20;

-- Query 5: Analyze relationship types distribution
-- SELECT
--   relationship_type,
--   COUNT(*) AS association_count,
--   COUNT(DISTINCT threat_id) AS threat_count,
--   COUNT(DISTINCT ioc_value) AS ioc_count,
--   AVG(confidence) AS avg_confidence
-- FROM `threat_xdr.threat_ioc_associations`
-- WHERE DATE(last_seen) >= DATE_SUB(CURRENT_DATE(), INTERVAL 90 DAYS)
-- GROUP BY relationship_type
-- ORDER BY association_count DESC;

-- Query 6: Time-series analysis of threat-IOC associations
-- SELECT
--   DATE(last_seen) AS observation_date,
--   threat_id,
--   COUNT(DISTINCT ioc_value) AS new_iocs,
--   SUM(observation_count) AS total_observations
-- FROM `threat_xdr.threat_ioc_associations`
-- WHERE DATE(last_seen) >= DATE_SUB(CURRENT_DATE(), INTERVAL 30 DAYS)
-- GROUP BY observation_date, threat_id
-- ORDER BY observation_date DESC, new_iocs DESC;
