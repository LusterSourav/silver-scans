"""
Living Threat Intelligence Platform
Self-updating, plugin-based threat intelligence platform with live feeds
"""
import asyncio
import logging
import json
import hashlib
import os
import re
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path
import aiohttp
import asyncpg
import redis.asyncio as redis

logger = logging.getLogger(__name__)


def substitute_env_vars(obj: Any) -> Any:
    """Recursively substitute environment variables in ${VAR_NAME} format"""
    if isinstance(obj, str):
        # Replace ${VAR_NAME} with environment variable value
        def replace_var(match):
            var_name = match.group(1)
            return os.getenv(var_name, match.group(0))
        return re.sub(r'\$\{([^}]+)\}', replace_var, obj)
    elif isinstance(obj, dict):
        return {k: substitute_env_vars(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [substitute_env_vars(item) for item in obj]
    else:
        return obj


@dataclass
class ThreatIntelItem:
    """Universal threat intelligence item"""
    id: str
    type: str  # ioc, cve, malware, campaign, actor, tool, technique
    value: str
    confidence: float
    severity: str
    source: str
    first_seen: datetime
    last_seen: datetime
    tags: List[str] = field(default_factory=list)
    context: Dict = field(default_factory=dict)
    tlp: str = "WHITE"  # Traffic Light Protocol
    expired: bool = False


@dataclass
class FeedSource:
    """Threat intelligence feed source configuration"""
    name: str
    url: str
    type: str  # json, csv, stix, misp, opencti, taxii, rss
    auth: Dict = field(default_factory=dict)
    headers: Dict = field(default_factory=dict)
    parser: str = "auto"
    enabled: bool = True
    interval: int = 3600  # seconds
    tlp: str = "WHITE"
    tags: List[str] = field(default_factory=list)
    filters: Dict = field(default_factory=dict)
    last_update: Optional[datetime] = None
    last_hash: str = ""
    error_count: int = 0


class LivingIntelPlatform:
    """
    Living Threat Intelligence Platform
    Self-updating, plugin-based, real-time threat intelligence platform
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.running = False
        
        # Core components
        self.feed_manager = None
        self.plugin_manager = None
        self.auto_updater = None
        self.live_feed_manager = None
        
        # Storage
        self.db_pool = None
        self.redis = None
        
        # Runtime state
        self.threat_items: Dict[str, Any] = {}
        self.feed_sources: Dict[str, FeedSource] = {}
        self.plugins: Dict[str, Any] = {}
        
        # Background tasks
        self.background_tasks: List[asyncio.Task] = []
        
        # Metrics
        self.metrics = {
            "feeds_processed": 0,
            "items_ingested": 0,
            "alerts_generated": 0,
            "errors": 0,
            "last_update": None
        }
        
    async def initialize(self):
        """Initialize the platform"""
        logger.info("Initializing Living Intel Platform")
        
        # Initialize database connections
        await self._init_database()
        
        # Initialize components
        from .feeds import FeedManager
        from .plugins import PluginManager
        from .auto_updater import AutoUpdater
        from .live_feeds import LiveFeedManager
        from .enrichment import ENRICHMENT_PLUGINS
        
        self.feed_manager = FeedManager(self)
        self.plugin_manager = PluginManager(self)
        self.auto_updater = AutoUpdater(self)
        self.live_feed_manager = LiveFeedManager(self)
        self.enrichment_plugins = ENRICHMENT_PLUGINS
        
        # Load feed sources
        await self._load_feed_sources()
        
        # Load plugins
        await self.plugin_manager.load_plugins()
        
        # Start auto-updater
        await self.auto_updater.start()
        
        # Start live feed manager
        await self.live_feed_manager.start()
        
        # Register live feed event handler for auto-enrichment
        self.live_feed_manager.add_event_handler(self._enrich_and_ingest_event)
        
        # Start background tasks
        self.background_tasks = [
            asyncio.create_task(self._metrics_loop()),
            asyncio.create_task(self._health_check_loop()),
            asyncio.create_task(self._cleanup_loop())
        ]
        
        logger.info("Living Intel Platform initialized")
    
    async def _init_database(self):
        """Initialize database connections"""
        # PostgreSQL for persistent storage
        if self.config.get("postgres"):
            self.db_pool = await asyncpg.create_pool(
                self.config["postgres"],
                min_size=5,
                max_size=20
            )
            await self._init_schema()
        
        # Redis for caching and real-time
        if self.config.get("redis"):
            self.redis = redis.from_url(
                self.config["redis"],
                encoding="utf-8",
                decode_responses=True
            )
    
    async def _init_schema(self):
        """Initialize database schema"""
        async with self.db_pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_intel (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    confidence REAL,
                    severity TEXT,
                    source TEXT,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    tags TEXT[],
                    context JSONB,
                    tlp TEXT DEFAULT 'WHITE',
                    expired BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                );
                
                CREATE INDEX IF NOT EXISTS idx_threat_intel_value ON threat_intel(value);
                CREATE INDEX IF NOT EXISTS idx_threat_intel_type ON threat_intel(type);
                CREATE INDEX IF NOT EXISTS idx_threat_intel_source ON threat_intel(source);
                CREATE INDEX IF NOT EXISTS idx_threat_intel_last_seen ON threat_intel(last_seen);
                
                CREATE TABLE IF NOT EXISTS feed_sources (
                    name TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    type TEXT NOT NULL,
                    auth JSONB,
                    headers JSONB,
                    parser TEXT,
                    enabled BOOLEAN DEFAULT TRUE,
                    interval INTEGER DEFAULT 3600,
                    tlp TEXT DEFAULT 'WHITE',
                    tags TEXT[],
                    filters JSONB,
                    last_update TIMESTAMP,
                    last_hash TEXT,
                    error_count INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                );
                
                CREATE TABLE IF NOT EXISTS feed_items (
                    id TEXT PRIMARY KEY,
                    feed_source TEXT REFERENCES feed_sources(name),
                    item_id TEXT NOT NULL,
                    data JSONB NOT NULL,
                    ingested_at TIMESTAMP DEFAULT NOW(),
                    processed BOOLEAN DEFAULT FALSE
                );
                
                CREATE INDEX IF NOT EXISTS idx_feed_items_source ON feed_items(feed_source);
                CREATE INDEX IF NOT EXISTS idx_feed_items_ingested ON feed_items(ingested_at);
            """)
    
    async def _load_feed_sources(self):
        """Load feed sources from database and config"""
        # Built-in feed sources with environment variable placeholders
        default_feeds_raw = {
            "alienvault_otx": {
                "name": "alienvault_otx",
                "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
                "type": "json",
                "auth": {"api_key": "${OTX_API_KEY}"},
                "parser": "alienvault_otx",
                "interval": 3600,
                "tags": ["otx", "pulses", "ioc"]
            },
            "abuse_ch_sslbl": {
                "name": "abuse_ch_sslbl",
                "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
                "type": "csv",
                "parser": "abuse_ch_sslbl",
                "interval": 3600,
                "tags": ["ssl", "c2", "malware"]
            },
            "abuse_ch_feodotracker": {
                "name": "abuse_ch_feodotracker",
                "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
                "type": "csv",
                "parser": "abuse_ch_feodo",
                "interval": 3600,
                "tags": ["feodo", "c2", "banking"]
            },
            "abuse_ch_urlhaus": {
                "name": "abuse_ch_urlhaus",
                "url": "https://urlhaus-api.abuse.ch/v1/urls/recent/",
                "type": "json",
                "auth": {"api_key": "${URLHAUS_API_KEY}", "auth_type": "header_auth_key"},
                "parser": "urlhaus_api",
                "interval": 1800,
                "tags": ["urlhaus", "malware", "url"]
            },
            "blocklist_de": {
                "name": "blocklist_de",
                "url": "https://lists.blocklist.de/lists/all.txt",
                "type": "txt",
                "parser": "blocklist_de",
                "interval": 3600,
                "tags": ["blocklist", "ssh", "bruteforce"]
            },
            "spamhaus_drop": {
                "name": "spamhaus_drop",
                "url": "https://www.spamhaus.org/drop/drop.txt",
                "type": "txt",
                "parser": "spamhaus_drop",
                "interval": 86400,
                "tags": ["spamhaus", "drop", "network"]
            },
            "spamhaus_edrop": {
                "name": "spamhaus_edrop",
                "url": "https://www.spamhaus.org/drop/edrop.txt",
                "type": "txt",
                "parser": "spamhaus_edrop",
                "interval": 86400,
                "tags": ["spamhaus", "edrop", "network"]
            },
            "emerging_threats": {
                "name": "emerging_threats",
                "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                "type": "txt",
                "parser": "emerging_threats",
                "interval": 3600,
                "tags": ["emerging_threats", "compromised"]
            },
            "tor_exit_nodes": {
                "name": "tor_exit_nodes",
                "url": "https://check.torproject.org/torbulkexitlist",
                "type": "txt",
                "parser": "tor_exit_nodes",
                "interval": 3600,
                "tags": ["tor", "exit_nodes", "anonymity"]
            },
            "cisa_known_exploited": {
                "name": "cisa_known_exploited",
                "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                "type": "json",
                "parser": "cisa_kev",
                "interval": 86400,
                "tags": ["cisa", "kev", "exploited", "vulnerability"]
            },
            "nvd_recent": {
                "name": "nvd_recent",
                "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                "type": "json",
                "auth": {"api_key": "${NVD_API_KEY}"},
                "parser": "nvd_cve_api",
                "interval": 3600,
                "tags": ["nvd", "cve", "vulnerability"]
            },
            "github_advisories": {
                "name": "github_advisories",
                "url": "https://api.github.com/advisories",
                "type": "json",
                "auth": {"token": "${GITHUB_TOKEN}"},
                "parser": "github_advisories",
                "interval": 3600,
                "tags": ["github", "advisory", "vulnerability"]
            },
            "abuse_ch_sslbl": {
                "name": "abuse_ch_sslbl",
                "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
                "type": "csv",
                "parser": "abuse_ch_sslbl",
                "interval": 3600,
                "tags": ["ssl", "c2", "malware"]
            },
            "abuse_ch_feodotracker": {
                "name": "abuse_ch_feodotracker",
                "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
                "type": "csv",
                "parser": "abuse_ch_feodo",
                "interval": 3600,
                "tags": ["feodo", "c2", "banking"]
            },
            "abuse_ch_urlhaus": {
                "name": "abuse_ch_urlhaus",
                "url": "https://urlhaus-api.abuse.ch/v1/urls/recent/",
                "type": "json",
                "auth": {"api_key": "${URLHAUS_API_KEY}", "auth_type": "header_auth_key"},
                "parser": "urlhaus_api",
                "interval": 1800,
                "tags": ["urlhaus", "malware", "url"]
            },
            "blocklist_de": {
                "name": "blocklist_de",
                "url": "https://lists.blocklist.de/lists/all.txt",
                "type": "txt",
                "parser": "blocklist_de",
                "interval": 3600,
                "tags": ["blocklist", "ssh", "bruteforce"]
            },
            "spamhaus_drop": {
                "name": "spamhaus_drop",
                "url": "https://www.spamhaus.org/drop/drop.txt",
                "type": "txt",
                "parser": "spamhaus_drop",
                "interval": 86400,
                "tags": ["spamhaus", "drop", "network"]
            },
            "spamhaus_edrop": {
                "name": "spamhaus_edrop",
                "url": "https://www.spamhaus.org/drop/edrop.txt",
                "type": "txt",
                "parser": "spamhaus_edrop",
                "interval": 86400,
                "tags": ["spamhaus", "edrop", "network"]
            },
            "emerging_threats": {
                "name": "emerging_threats",
                "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                "type": "txt",
                "parser": "emerging_threats",
                "interval": 3600,
                "tags": ["emerging_threats", "compromised"]
            },
            "tor_exit_nodes": {
                "name": "tor_exit_nodes",
                "url": "https://check.torproject.org/torbulkexitlist",
                "type": "txt",
                "parser": "tor_exit_nodes",
                "interval": 3600,
                "tags": ["tor", "exit_nodes", "anonymity"]
            },
            "cisa_known_exploited": {
                "name": "cisa_known_exploited",
                "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                "type": "json",
                "parser": "cisa_kev",
                "interval": 86400,
                "tags": ["cisa", "kev", "exploited", "vulnerability"]
            },
            "nvd_recent": {
                "name": "nvd_recent",
                "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                "type": "json",
                "auth": {"api_key": "${NVD_API_KEY}"},
                "parser": "nvd_cve_api",
                "interval": 3600,
                "tags": ["nvd", "cve", "vulnerability"]
            },
            "github_advisories": {
                "name": "github_advisories",
                "url": "https://api.github.com/advisories",
                "type": "json",
                "auth": {"token": "${GITHUB_TOKEN}"},
                "parser": "github_advisories",
                "interval": 3600,
                "tags": ["github", "advisory", "vulnerability"]
            }
        }
        
        # Substitute environment variables in default feeds
        default_feeds_substituted = {}
        for name, feed_dict in default_feeds_raw.items():
            substituted = substitute_env_vars(feed_dict)
            default_feeds_substituted[name] = FeedSource(**substituted)
        
        default_feeds = default_feeds_substituted
        
        # Load from database
        if self.db_pool:
            async with self.db_pool.acquire() as conn:
                rows = await conn.fetch("SELECT * FROM feed_sources WHERE enabled = TRUE")
                for row in rows:
                    self.feed_sources[row["name"]] = FeedSource(
                        name=row["name"],
                        url=row["url"],
                        type=row["type"],
                        auth=row["auth"] or {},
                        headers=row["headers"] or {},
                        parser=row["parser"],
                        enabled=row["enabled"],
                        interval=row["interval"],
                        tlp=row["tlp"],
                        tags=row["tags"] or [],
                        filters=row["filters"] or {},
                        last_update=row["last_update"],
                        last_hash=row["last_hash"] or "",
                        error_count=row["error_count"] or 0
                    )
        
        # Add defaults for any missing
        for name, feed in default_feeds.items():
            if name not in self.feed_sources:
                self.feed_sources[name] = feed
    
    async def start(self):
        """Start the platform"""
        self.running = True
        logger.info("Living Intel Platform started")
        
        # Start feed processing
        asyncio.create_task(self.feed_manager.run_feeds())
        
        # Start live feeds
        await self.live_feed_manager.start()
    
    async def stop(self):
        """Stop the platform"""
        self.running = False
        
        for task in self.background_tasks:
            task.cancel()
        
        await asyncio.gather(*self.background_tasks, return_exceptions=True)
        
        # Stop live feed manager
        await self.live_feed_manager.stop()
        
        # Stop auto-updater
        self.auto_updater.stop()
        
        # Cleanup plugins
        await self.plugin_manager.cleanup()
        
        if self.db_pool:
            await self.db_pool.close()
        
        if self.redis:
            await self.redis.close()
        
        logger.info("Living Intel Platform stopped")
    
    async def _metrics_loop(self):
        """Collect and log metrics"""
        while True:
            await asyncio.sleep(300)
            logger.info(f"Platform Metrics: {self.metrics}")
    
    async def _health_check_loop(self):
        """Health check for all components"""
        while True:
            await asyncio.sleep(60)
            await self._check_health()
    
    async def _cleanup_loop(self):
        """Cleanup old data"""
        while True:
            await asyncio.sleep(3600)
            await self._cleanup_old_data()
    
    async def _check_health(self):
        """Check health of all components"""
        health = {
            "database": "ok" if self.db_pool else "not_configured",
            "redis": "ok" if self.redis else "not_configured",
            "feeds": len([f for f in self.feed_sources.values() if f.enabled]),
            "plugins": len(self.plugins),
            "metrics": self.metrics
        }
        
        # Store health in Redis
        if self.redis:
            await self.redis.setex(
                "living_intel:health",
                120,
                json.dumps(health, default=str)
            )
    
    async def _cleanup_old_data(self):
        """Clean up old threat intelligence data"""
        if not self.db_pool:
            return
        
        cutoff = datetime.now() - timedelta(days=90)
        async with self.db_pool.acquire() as conn:
            # Archive old items
            await conn.execute("""
                DELETE FROM threat_intel 
                WHERE last_seen < $1 AND expired = TRUE
            """, datetime.now() - timedelta(days=365))
            
            # Clean old feed items
            await conn.execute("""
                DELETE FROM feed_items 
                WHERE ingested_at < $1
            """, datetime.now() - timedelta(days=30))
    
    async def ingest_threat_item(self, item: ThreatIntelItem) -> bool:
        """Ingest a threat intelligence item"""
        if not self.db_pool:
            return False
        
        try:
            async with self.db_pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO threat_intel (id, type, value, confidence, severity, source, first_seen, last_seen, tags, context, tlp, expired)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                    ON CONFLICT (id) DO UPDATE SET
                        last_seen = EXCLUDED.last_seen,
                        confidence = GREATEST(threat_intel.confidence, EXCLUDED.confidence),
                        tags = threat_intel.tags || EXCLUDED.tags,
                        context = threat_intel.context || EXCLUDED.context,
                        updated_at = NOW()
                """, 
                item.id, item.type, item.value, item.confidence, item.severity,
                item.source, item.first_seen, item.last_seen,
                item.tags, json.dumps(item.context), item.tlp, item.expired
                )
            
            self.metrics["items_ingested"] += 1
            return True
        except Exception as e:
            logger.error(f"Failed to ingest threat item: {e}")
            self.metrics["errors"] += 1
            return False
    
    async def query_threat_intel(self, query: Dict) -> List[Dict]:
        """Query threat intelligence"""
        if not self.db_pool:
            return []
        
        conditions = []
        params = []
        param_idx = 1
        
        if "type" in query:
            conditions.append(f"type = ${param_idx}")
            params.append(query["type"])
            param_idx += 1
        
        if "value" in query:
            conditions.append(f"value ILIKE ${param_idx}")
            params.append(f"%{query['value']}%")
            param_idx += 1
        
        if "source" in query:
            conditions.append(f"source = ${param_idx}")
            params.append(query["source"])
            param_idx += 1
        
        if "severity" in query:
            conditions.append(f"severity = ${param_idx}")
            params.append(query["severity"])
            param_idx += 1
        
        if "tags" in query:
            conditions.append(f"tags && ${param_idx}")
            params.append(query["tags"])
            param_idx += 1
        
        if "since" in query:
            conditions.append(f"last_seen > ${param_idx}")
            params.append(query["since"])
            param_idx += 1
        
        where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
        
        query_sql = f"""
            SELECT * FROM threat_intel 
            {where_clause}
            ORDER BY last_seen DESC
            LIMIT 1000
        """
        
        async with self.db_pool.acquire() as conn:
            rows = await conn.fetch(query_sql, *params)
            return [dict(row) for row in rows]
    
    async def search_iocs(self, ioc_type: str, value: str) -> List[Dict]:
        """Search for specific IOC"""
        return await self.query_threat_intel({
            "type": ioc_type,
            "value": value
        })
    
    def get_metrics(self) -> Dict:
        return self.metrics.copy()
    
    def get_feed_status(self) -> Dict:
        return {
            name: {
                "enabled": feed.enabled,
                "last_update": feed.last_update.isoformat() if feed.last_update else None,
                "error_count": feed.error_count,
                "interval": feed.interval
            }
            for name, feed in self.feed_sources.items()
        }
    
    async def _enrich_and_ingest_event(self, item: 'ThreatIntelItem'):
        """Enrich and ingest a threat intelligence item from live feeds"""
        # Run enrichment plugins
        for plugin_class in self.enrichment_plugins.values():
            try:
                plugin = plugin_class(self)
                await plugin.initialize()
                item = await plugin.enrich(item)
            except Exception as e:
                logger.error(f"Enrichment error in {plugin_class.__name__}: {e}")
        
        # Also run plugin manager enrichment
        item = await self.plugin_manager.enrich_item(item)
        
        # Ingest into platform
        await self.ingest_threat_item(item)
    
    def get_live_feed_status(self) -> Dict:
        """Get live feed manager status"""
        return self.live_feed_manager.get_feed_status()
    
    def get_live_feed_metrics(self) -> Dict:
        """Get live feed manager metrics"""
        return self.live_feed_manager.get_metrics()
    
    async def add_live_feed(self, feed):
        """Add a new live feed"""
        await self.live_feed_manager.add_feed(feed)
    
    async def remove_live_feed(self, name: str):
        """Remove a live feed"""
        await self.live_feed_manager.remove_feed(name)
    
    def get_enrichment_plugins(self) -> List[str]:
        """Get list of available enrichment plugins"""
        return list(self.enrichment_plugins.keys())
    
    def get_metrics(self) -> Dict:
        base_metrics = self.metrics.copy()
        base_metrics["live_feeds"] = self.live_feed_manager.get_metrics()
        return base_metrics

    async def delete_user_intel(self, user_id: str):
        """Delete user's threat intelligence data"""
        if not self.db_pool:
            return
        async with self.db_pool.acquire() as conn:
            await conn.execute(
                "DELETE FROM threat_intel WHERE context->>'user_id' = $1",
                user_id
            )
            await conn.execute(
                "DELETE FROM feed_items WHERE data->>'user_id' = $1",
                user_id
            )


class ThreatIntelPlugin:
    """Base class for threat intelligence plugins"""
    
    def __init__(self, platform: 'LivingIntelPlatform'):
        self.platform = platform
        self.name = self.__class__.__name__
        self.enabled = True
    
    async def initialize(self):
        """Initialize plugin"""
        pass
    
    async def process(self, item: ThreatIntelItem) -> Optional[ThreatIntelItem]:
        """Process a threat intelligence item"""
        return item
    
    async def enrich(self, item: ThreatIntelItem) -> ThreatIntelItem:
        """Enrich threat intelligence item"""
        return item
    
    async def hunt(self, query: Dict) -> List[ThreatIntelItem]:
        """Threat hunting query"""
        return []
    
    async def cleanup(self):
        """Cleanup resources"""
        pass


# Built-in enrichment plugins
class GeoIPEnrichmentPlugin(ThreatIntelPlugin):
    """Enrich IPs with GeoIP data"""
    
    def __init__(self, platform):
        super().__init__(platform)
        self.name = "GeoIPEnrichment"
        self.geoip_db = None
    
    async def initialize(self):
        try:
            import geoip2.database
            self.geoip_db = geoip2.database.Reader('/usr/share/GeoIP/GeoLite2-City.mmdb')
        except:
            logger.warning("GeoIP database not found")
    
    async def enrich(self, item: ThreatIntelItem) -> ThreatIntelItem:
        if item.type == "ip" and self.geoip_db:
            try:
                response = self.geoip_db.city(item.value)
                item.context["geoip"] = {
                    "country": response.country.name,
                    "country_code": response.country.iso_code,
                    "city": response.city.name,
                    "latitude": response.location.latitude,
                    "longitude": response.location.longitude,
                    "asn": response.traits.autonomous_system_number,
                    "isp": response.traits.autonomous_system_organization
                }
            except:
                pass
        return item


class VirusTotalEnrichmentPlugin(ThreatIntelPlugin):
    """Enrich with VirusTotal data"""
    
    def __init__(self, platform):
        super().__init__(platform)
        self.name = "VirusTotalEnrichment"
        self.api_key = None
        self.session = None
    
    async def initialize(self):
        self.api_key = self.platform.config.get("virustotal_api_key")
        if self.api_key:
            self.session = aiohttp.ClientSession()
    
    async def enrich(self, item: ThreatIntelItem) -> ThreatIntelItem:
        if not self.api_key or not self.session:
            return item
        
        if item.type in ["hash", "url", "domain", "ip"]:
            try:
                url = f"https://www.virustotal.com/api/v3/{item.type}s/{item.value}"
                headers = {"x-apikey": self.api_key}
                
                async with self.session.get(url, headers={"x-apikey": self.api_key}) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        item.context["virustotal"] = data
            except Exception as e:
                logger.error(f"VirusTotal enrichment error: {e}")
        return item


class ThreatFoxEnrichmentPlugin(ThreatIntelPlugin):
    """Enrich with ThreatFox malware data"""
    
    def __init__(self, platform):
        super().__init__(platform)
        self.name = "ThreatFoxEnrichment"
    
    async def enrich(self, item: ThreatIntelItem) -> ThreatIntelItem:
        if item.type in ["ip", "domain", "hash"]:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        "https://threatfox-api.abuse.ch/api/v1/",
                        json={"query": "search_ioc", "search_term": item.value}
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if data.get("data"):
                                item.context["threatfox"] = data["data"]
            except Exception as e:
                logger.error(f"ThreatFox enrichment error: {e}")
        return item


class MISPEnrichmentPlugin(ThreatIntelPlugin):
    """Enrich from MISP instance"""
    
    def __init__(self, platform):
        super().__init__(platform)
        self.name = "MISPEnrichment"
        self.misp_url = None
        self.misp_key = None
    
    async def initialize(self):
        self.misp_url = self.platform.config.get("misp_url")
        self.misp_key = self.platform.config.get("misp_key")
    
    async def enrich(self, item: ThreatIntelItem) -> ThreatIntelItem:
        if not self.misp_url or not self.misp_key:
            return item
        
        try:
            async with aiohttp.ClientSession() as session:
                headers = {"Authorization": self.misp_key, "Accept": "application/json"}
                async with session.post(
                    f"{self.misp_url}/attributes/restSearch",
                    headers=headers,
                    json={"value": item.value, "type": item.type}
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        item.context["misp"] = data
        except Exception as e:
            logger.error(f"MISP enrichment error: {e}")
        return item