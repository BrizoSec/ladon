-- =============================================================================
-- BigQuery Table: threats
-- Description: Stores threat actors, campaigns, and malware families with
--              associated TTPs (MITRE ATT&CK techniques)
-- =============================================================================

CREATE TABLE IF NOT EXISTS `threat_xdr.threats` (
  -- Core Identification
  threat_id STRING NOT NULL OPTIONS(description="Unique identifier for the threat"),
  name STRING NOT NULL OPTIONS(description="Primary threat name"),
  aliases ARRAY<STRING> OPTIONS(description="Alternative names and identifiers"),

  -- Classification
  threat_category STRING NOT NULL OPTIONS(description="Category: actor, campaign, malware_family, vulnerability"),
  threat_type STRING NOT NULL OPTIONS(description="Threat type: c2, malware, phishing, ransomware, etc."),

  -- Description and Context
  description STRING OPTIONS(description="Comprehensive threat description"),
  severity STRING OPTIONS(description="Severity level: low, medium, high, critical"),
  confidence FLOAT64 OPTIONS(description="Confidence in threat intelligence (0.0-1.0)"),

  -- TTPs (Tactics, Techniques, and Procedures)
  techniques STRING OPTIONS(description="JSON array of MITRE ATT&CK techniques with full details"),
  tactics ARRAY<STRING> OPTIONS(description="MITRE ATT&CK tactics (derived from techniques)"),

  -- Temporal Information
  first_seen TIMESTAMP NOT NULL OPTIONS(description="First observation of this threat"),
  last_seen TIMESTAMP NOT NULL OPTIONS(description="Most recent threat activity"),

  -- Intelligence Sources
  sources ARRAY<STRING> OPTIONS(description="Intelligence sources providing this threat data"),
  reference_urls ARRAY<STRING> OPTIONS(description="External references and threat reports"),

  -- Tags and Metadata
  tags ARRAY<STRING> OPTIONS(description="Classification and context tags"),
  metadata STRING OPTIONS(description="JSON object with additional custom metadata"),

  -- Status
  is_active BOOL DEFAULT TRUE OPTIONS(description="Whether threat is currently active"),

  -- Audit Fields
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP() OPTIONS(description="Record creation timestamp"),
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP() OPTIONS(description="Last update timestamp")
)
PARTITION BY DATE(last_seen)
CLUSTER BY threat_category, threat_type, is_active
OPTIONS(
  description="Threat actors, campaigns, and malware families with MITRE ATT&CK TTPs",
  labels=[("service", "ladon-threat-xdr"), ("data_type", "threat_intelligence")]
);

-- =============================================================================
-- Indexes and Views
-- =============================================================================

-- Create a view for active threats only
CREATE OR REPLACE VIEW `threat_xdr.active_threats` AS
SELECT
  threat_id,
  name,
  aliases,
  threat_category,
  threat_type,
  description,
  severity,
  confidence,
  tactics,
  first_seen,
  last_seen,
  sources,
  tags
FROM `threat_xdr.threats`
WHERE is_active = TRUE
  AND DATE(last_seen) >= DATE_SUB(CURRENT_DATE(), INTERVAL 90 DAYS);

-- Create a view for APT threats
CREATE OR REPLACE VIEW `threat_xdr.apt_threats` AS
SELECT
  threat_id,
  name,
  aliases,
  threat_type,
  description,
  severity,
  confidence,
  tactics,
  JSON_EXTRACT_ARRAY(techniques) AS techniques_array,
  first_seen,
  last_seen,
  sources,
  tags
FROM `threat_xdr.threats`
WHERE threat_category = 'actor'
  AND (
    LOWER(name) LIKE '%apt%'
    OR EXISTS(SELECT 1 FROM UNNEST(tags) AS tag WHERE LOWER(tag) LIKE '%apt%')
  )
  AND is_active = TRUE;

-- Create a materialized view for threat statistics
CREATE MATERIALIZED VIEW IF NOT EXISTS `threat_xdr.threat_stats_mv`
PARTITION BY stats_date
CLUSTER BY threat_category
AS
SELECT
  CURRENT_DATE() AS stats_date,
  threat_category,
  threat_type,
  severity,
  COUNT(*) AS threat_count,
  COUNT(DISTINCT name) AS unique_threats,
  AVG(confidence) AS avg_confidence,
  COUNTIF(is_active) AS active_count,
  MAX(last_seen) AS most_recent_activity
FROM `threat_xdr.threats`
GROUP BY threat_category, threat_type, severity;

-- =============================================================================
-- Sample Queries
-- =============================================================================

-- Query 1: Get all active APT threats with high confidence
-- SELECT threat_id, name, aliases, confidence, tactics
-- FROM `threat_xdr.threats`
-- WHERE threat_category = 'actor'
--   AND is_active = TRUE
--   AND confidence >= 0.8
--   AND DATE(last_seen) >= DATE_SUB(CURRENT_DATE(), INTERVAL 30 DAYS)
-- ORDER BY confidence DESC, last_seen DESC;

-- Query 2: Get threats by MITRE ATT&CK tactic
-- SELECT threat_id, name, threat_type, tactics
-- FROM `threat_xdr.threats`
-- WHERE 'Execution' IN UNNEST(tactics)
--   AND is_active = TRUE;

-- Query 3: Get threat activity timeline
-- SELECT
--   DATE(last_seen) AS activity_date,
--   threat_category,
--   COUNT(*) AS threat_count,
--   COUNT(DISTINCT threat_id) AS unique_threats
-- FROM `threat_xdr.threats`
-- WHERE DATE(last_seen) >= DATE_SUB(CURRENT_DATE(), INTERVAL 90 DAYS)
-- GROUP BY activity_date, threat_category
-- ORDER BY activity_date DESC;

-- Query 4: Get most common MITRE ATT&CK techniques across all threats
-- WITH techniques_expanded AS (
--   SELECT
--     threat_id,
--     name,
--     JSON_EXTRACT_SCALAR(technique, '$.technique_id') AS technique_id,
--     JSON_EXTRACT_SCALAR(technique, '$.technique_name') AS technique_name,
--     JSON_EXTRACT_SCALAR(technique, '$.tactic') AS tactic
--   FROM `threat_xdr.threats`,
--   UNNEST(JSON_EXTRACT_ARRAY(techniques)) AS technique
--   WHERE is_active = TRUE
-- )
-- SELECT
--   technique_id,
--   technique_name,
--   tactic,
--   COUNT(DISTINCT threat_id) AS threat_count
-- FROM techniques_expanded
-- GROUP BY technique_id, technique_name, tactic
-- ORDER BY threat_count DESC
-- LIMIT 20;
