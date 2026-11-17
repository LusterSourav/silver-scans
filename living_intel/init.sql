-- Living Threat Intelligence Platform Database Initialization
-- Run on PostgreSQL startup

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- Create schemas
CREATE SCHEMA IF NOT EXISTS threat_intel;
CREATE SCHEMA IF NOT EXISTS feeds;
CREATE SCHEMA IF NOT EXISTS audit;

-- Set search path
ALTER DATABASE living_intel SET search_path = threat_intel, feeds, audit, public;

-- Threat Intelligence Table
CREATE TABLE IF NOT EXISTS threat_intel.threat_intel (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    confidence REAL DEFAULT 0.5,
    severity TEXT DEFAULT 'UNKNOWN',
    source TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tags TEXT[] DEFAULT '{}',
    context JSONB DEFAULT '{}',
    tlp TEXT DEFAULT 'WHITE',
    expired BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for threat_intel
CREATE INDEX IF NOT EXISTS idx_threat_intel_value ON threat_intel.threat_intel(value);
CREATE INDEX IF NOT EXISTS idx_threat_intel_type ON threat_intel.threat_intel(type);
CREATE INDEX IF NOT EXISTS idx_threat_intel_source ON threat_intel.threat_intel(source);
CREATE INDEX IF NOT EXISTS idx_threat_intel_severity ON threat_intel.threat_intel(severity);
CREATE INDEX IF NOT EXISTS idx_threat_intel_last_seen ON threat_intel.threat_intel(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_threat_intel_tags ON threat_intel.threat_intel USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_threat_intel_context ON threat_intel.threat_intel USING GIN(context);
CREATE INDEX IF NOT EXISTS idx_threat_intel_tlp ON threat_intel.threat_intel(tlp);

-- Composite indexes for common queries
CREATE INDEX IF NOT EXISTS idx_threat_intel_type_value ON threat_intel.threat_intel(type, value);
CREATE INDEX IF NOT EXISTS idx_threat_intel_source_last_seen ON threat_intel.threat_intel(source, last_seen DESC);

-- Feed Sources Table
CREATE TABLE IF NOT EXISTS feeds.feed_sources (
    name TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    type TEXT NOT NULL,
    auth JSONB DEFAULT '{}',
    headers JSONB DEFAULT '{}',
    parser TEXT DEFAULT 'auto',
    enabled BOOLEAN DEFAULT TRUE,
    interval INTEGER DEFAULT 3600,
    tlp TEXT DEFAULT 'WHITE',
    tags TEXT[] DEFAULT '{}',
    filters JSONB DEFAULT '{}',
    last_update TIMESTAMPTZ,
    last_hash TEXT DEFAULT '',
    error_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for feed_sources
CREATE INDEX IF NOT EXISTS idx_feed_sources_enabled ON feeds.feed_sources(enabled);
CREATE INDEX IF NOT EXISTS idx_feed_sources_last_update ON feeds.feed_sources(last_update);

-- Feed Items Table (raw feed data)
CREATE TABLE IF NOT EXISTS feeds.feed_items (
    id TEXT PRIMARY KEY,
    feed_source TEXT NOT NULL REFERENCES feeds.feed_sources(name) ON DELETE CASCADE,
    item_id TEXT NOT NULL,
    data JSONB NOT NULL,
    ingested_at TIMESTAMPTZ DEFAULT NOW(),
    processed BOOLEAN DEFAULT FALSE,
    processed_at TIMESTAMPTZ
);

-- Indexes for feed_items
CREATE INDEX IF NOT EXISTS idx_feed_items_source ON feeds.feed_items(feed_source);
CREATE INDEX IF NOT EXISTS idx_feed_items_ingested ON feeds.feed_items(ingested_at DESC);
CREATE INDEX IF NOT EXISTS idx_feed_items_processed ON feeds.feed_items(processed);
CREATE INDEX IF NOT EXISTS idx_feed_items_data ON feeds.feed_items USING GIN(data);

-- Live Feed Events Table
CREATE TABLE IF NOT EXISTS feeds.live_feed_events (
    id TEXT PRIMARY KEY,
    feed_name TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_type TEXT,
    timestamp TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL,
    raw_data JSONB,
    processed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for live_feed_events
CREATE INDEX IF NOT EXISTS idx_live_feed_events_feed ON feeds.live_feed_events(feed_name);
CREATE INDEX IF NOT EXISTS idx_live_feed_events_timestamp ON feeds.live_feed_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_live_feed_events_type ON feeds.live_feed_events(event_type);
CREATE INDEX IF NOT EXISTS idx_live_feed_events_data ON feeds.live_feed_events USING GIN(data);

-- Enrichment Results Table
CREATE TABLE IF NOT EXISTS threat_intel.enrichment_results (
    id TEXT PRIMARY KEY,
    threat_intel_id TEXT NOT NULL REFERENCES threat_intel.threat_intel(id) ON DELETE CASCADE,
    plugin_name TEXT NOT NULL,
    result JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for enrichment_results
CREATE INDEX IF NOT EXISTS idx_enrichment_results_threat_intel ON threat_intel.enrichment_results(threat_intel_id);
CREATE INDEX IF NOT EXISTS idx_enrichment_results_plugin ON threat_intel.enrichment_results(plugin_name);

-- Plugins Table
CREATE TABLE IF NOT EXISTS feeds.plugins (
    name TEXT PRIMARY KEY,
    version TEXT DEFAULT '1.0.0',
    description TEXT,
    author TEXT,
    entry_point TEXT,
    config_schema JSONB DEFAULT '{}',
    dependencies TEXT[] DEFAULT '{}',
    enabled BOOLEAN DEFAULT TRUE,
    loaded_at TIMESTAMPTZ,
    health TEXT DEFAULT 'unknown',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Auto Updater Status Table
CREATE TABLE IF NOT EXISTS audit.updater_status (
    component TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    progress REAL DEFAULT 0.0,
    message TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error TEXT,
    current_version TEXT,
    latest_version TEXT
);

-- Audit Log Table
CREATE TABLE IF NOT EXISTS audit.audit_log (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    event_type TEXT NOT NULL,
    component TEXT,
    details JSONB,
    user_id TEXT,
    ip_address INET
);

-- Indexes for audit_log
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit.audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit.audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_log_component ON audit.audit_log(component);

-- Metrics Table
CREATE TABLE IF NOT EXISTS audit.metrics (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    metric_name TEXT NOT NULL,
    metric_value REAL NOT NULL,
    tags JSONB DEFAULT '{}'
);

-- Indexes for metrics
CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON audit.metrics(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_metrics_name ON audit.metrics(metric_name);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers for updated_at
DROP TRIGGER IF EXISTS update_threat_intel_updated_at ON threat_intel.threat_intel;
CREATE TRIGGER update_threat_intel_updated_at
    BEFORE UPDATE ON threat_intel.threat_intel
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_feed_sources_updated_at ON feeds.feed_sources;
CREATE TRIGGER update_feed_sources_updated_at
    BEFORE UPDATE ON feeds.feed_sources
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_plugins_updated_at ON feeds.plugins;
CREATE TRIGGER update_plugins_updated_at
    BEFORE UPDATE ON feeds.plugins
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Partitioning for large tables (optional, for high volume)
-- CREATE TABLE threat_intel.threat_intel_partitioned (LIKE threat_intel.threat_intel INCLUDING ALL) PARTITION BY RANGE (last_seen);
-- CREATE TABLE feeds.feed_items_partitioned (LIKE feeds.feed_items INCLUDING ALL) PARTITION BY RANGE (ingested_at);
-- CREATE TABLE feeds.live_feed_events_partitioned (LIKE feeds.live_feed_events INCLUDING ALL) PARTITION BY RANGE (timestamp);

-- Materialized view for dashboard statistics
CREATE MATERIALIZED VIEW IF NOT EXISTS threat_intel.dashboard_stats AS
SELECT 
    COUNT(*) as total_indicators,
    COUNT(*) FILTER (WHERE last_seen > NOW() - INTERVAL '24 hours') as recent_24h,
    COUNT(*) FILTER (WHERE last_seen > NOW() - INTERVAL '7 days') as recent_7d,
    COUNT(*) FILTER (WHERE severity = 'CRITICAL') as critical_count,
    COUNT(*) FILTER (WHERE severity = 'HIGH') as high_count,
    COUNT(*) FILTER (WHERE severity = 'MEDIUM') as medium_count,
    COUNT(*) FILTER (WHERE severity = 'LOW') as low_count,
    COUNT(DISTINCT source) as unique_sources,
    COUNT(DISTINCT type) as unique_types
FROM threat_intel.threat_intel
WHERE expired = FALSE;

CREATE UNIQUE INDEX IF NOT EXISTS idx_dashboard_stats ON threat_intel.dashboard_stats (total_indicators);

-- Function to refresh dashboard stats
CREATE OR REPLACE FUNCTION refresh_dashboard_stats()
RETURNS VOID AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY threat_intel.dashboard_stats;
END;
$$ LANGUAGE plpgsql;

-- Grant permissions
GRANT USAGE ON SCHEMA threat_intel TO living_intel;
GRANT USAGE ON SCHEMA feeds TO living_intel;
GRANT USAGE ON SCHEMA audit TO living_intel;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA threat_intel TO living_intel;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA feeds TO living_intel;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA audit TO living_intel;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA threat_intel TO living_intel;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA feeds TO living_intel;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA audit TO living_intel;

-- Default feed sources
INSERT INTO feeds.feed_sources (name, url, type, parser, enabled, interval, tags) VALUES
('alienvault_otx', 'https://otx.alienvault.com/api/v1/pulses/subscribed', 'json', 'alienvault_otx', TRUE, 3600, ARRAY['otx', 'pulses', 'ioc']),
('abuse_ch_sslbl', 'https://sslbl.abuse.ch/blacklist/sslipblacklist.csv', 'csv', 'abuse_ch_sslbl', TRUE, 3600, ARRAY['ssl', 'c2', 'malware']),
('abuse_ch_feodotracker', 'https://feodotracker.abuse.ch/downloads/ipblocklist.csv', 'csv', 'abuse_ch_feodo', TRUE, 3600, ARRAY['feodo', 'c2', 'banking']),
('abuse_ch_urlhaus', 'https://urlhaus.abuse.ch/downloads/csv/', 'csv', 'urlhaus', TRUE, 1800, ARRAY['urlhaus', 'malware', 'url']),
('blocklist_de', 'https://lists.blocklist.de/lists/all.txt', 'txt', 'blocklist_de', TRUE, 3600, ARRAY['blocklist', 'ssh', 'bruteforce']),
('spamhaus_drop', 'https://www.spamhaus.org/drop/drop.txt', 'txt', 'spamhaus_drop', TRUE, 86400, ARRAY['spamhaus', 'drop', 'network']),
('spamhaus_edrop', 'https://www.spamhaus.org/drop/edrop.txt', 'txt', 'spamhaus_edrop', TRUE, 86400, ARRAY['spamhaus', 'edrop', 'network']),
('emerging_threats', 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt', 'txt', 'emerging_threats', TRUE, 3600, ARRAY['emerging_threats', 'compromised']),
('tor_exit_nodes', 'https://check.torproject.org/torbulkexitlist', 'txt', 'tor_exit_nodes', TRUE, 3600, ARRAY['tor', 'exit_nodes', 'anonymity']),
('cisa_known_exploited', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', 'json', 'cisa_kev', TRUE, 86400, ARRAY['cisa', 'kev', 'exploited', 'vulnerability']),
('nvd_recent', 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz', 'json_gz', 'nvd_cve', TRUE, 3600, ARRAY['nvd', 'cve', 'vulnerability']),
('github_advisories', 'https://api.github.com/advisories', 'json', 'github_advisories', TRUE, 3600, ARRAY['github', 'advisory', 'vulnerability'])
ON CONFLICT (name) DO NOTHING;

-- Default plugins
INSERT INTO feeds.plugins (name, version, description, author, entry_point, enabled) VALUES
('GeoIPEnrichment', '1.0.0', 'Enrich IPs with GeoIP data', 'Living Intel Platform', 'living_intel.enrichment.GeoIPEnrichmentPlugin', TRUE),
('VirusTotalEnrichment', '1.0.0', 'Enrich with VirusTotal data', 'Living Intel Platform', 'living_intel.enrichment.VirusTotalEnrichmentPlugin', TRUE),
('ThreatFoxEnrichment', '1.0.0', 'Enrich with ThreatFox malware data', 'Living Intel Platform', 'living_intel.enrichment.ThreatFoxEnrichmentPlugin', TRUE),
('MISPEnrichment', '1.0.0', 'Enrich from MISP instance', 'Living Intel Platform', 'living_intel.enrichment.MISPEnrichmentPlugin', TRUE),
('AbuseCHEnrichment', '1.0.0', 'Enrich with abuse.ch threat intelligence', 'Living Intel Platform', 'living_intel.enrichment.AbuseCHEnrichmentPlugin', TRUE),
('HybridAnalysisEnrichment', '1.0.0', 'Enrich with Hybrid Analysis sandbox data', 'Living Intel Platform', 'living_intel.enrichment.HybridAnalysisEnrichmentPlugin', TRUE),
('GreyNoiseEnrichment', '1.0.0', 'Enrich with GreyNoise internet scanner data', 'Living Intel Platform', 'living_intel.enrichment.GreyNoiseEnrichmentPlugin', TRUE),
('ShodanEnrichment', '1.0.0', 'Enrich with Shodan internet scanning data', 'Living Intel Platform', 'living_intel.enrichment.ShodanEnrichmentPlugin', TRUE),
('PassiveTotalEnrichment', '1.0.0', 'Enrich with PassiveTotal passive DNS', 'Living Intel Platform', 'living_intel.enrichment.PassiveTotalEnrichmentPlugin', TRUE),
('AlienVaultOTXEnrichment', '1.0.0', 'Enrich with AlienVault OTX pulse data', 'Living Intel Platform', 'living_intel.enrichment.AlienVaultOTXEnrichmentPlugin', TRUE),
('CIRCLEnrichment', '1.0.0', 'Enrich with CIRCL services', 'Living Intel Platform', 'living_intel.enrichment.CIRCLEnrichmentPlugin', TRUE),
('CiscoTalosEnrichment', '1.0.0', 'Enrich with Cisco Talos reputation', 'Living Intel Platform', 'living_intel.enrichment.CiscoTalosEnrichmentPlugin', TRUE)
ON CONFLICT (name) DO NOTHING;