# Living Threat Intelligence Platform

A self-updating, plugin-based threat intelligence platform with real-time live feeds, automatic enrichment, and REST API.

## Features

### Live Threat Intelligence Feeds
- **12+ Built-in Feeds**: AlienVault OTX, Abuse.ch (SSLBL, Feodo, URLhaus), Blocklist.de, Spamhaus (DROP/EDROP), Emerging Threats, Tor Exit Nodes, CISA KEV, NVD CVE, GitHub Advisories
- **Real-time Protocols**: HTTP polling, Server-Sent Events (SSE), WebSocket, TAXII 2.1
- **Auto-refresh**: Configurable intervals per feed (5 min to 24 hours)
- **Change Detection**: SHA-256 content hashing to avoid duplicate processing

### Automatic Enrichment (12 Plugins)
- **GeoIP**: MaxMind GeoLite2 City + ASN databases
- **VirusTotal v3**: File, URL, domain, IP reputation
- **ThreatFox**: Malware IOCs from abuse.ch
- **MISP**: Full MISP instance integration
- **Abuse.ch**: SSLBL, Feodo Tracker, URLhaus
- **Hybrid Analysis**: Falcon Sandbox behavioral analysis
- **GreyNoise**: Internet background noise classification
- **Shodan**: Internet scanning intelligence
- **PassiveTotal**: RiskIQ passive DNS
- **AlienVault OTX**: Pulse-based threat intelligence
- **CIRCL**: Passive DNS, malware, CVE data
- **Cisco Talos**: IP/domain reputation

### Self-Updating Architecture
- **CVE Database**: Daily sync from NVD
- **Threat Feeds**: Hourly refresh with change detection
- **GeoIP Databases**: Weekly MaxMind GeoLite2 updates
- **Platform Updates**: GitHub releases monitoring
- **Plugin Updates**: PyPI version checking

### REST API
- Threat intelligence queries with filtering
- Feed management (CRUD, enable/disable, refresh)
- Live feed monitoring and metrics
- Single and bulk IOC enrichment
- Threat hunting across all plugins
- Export: STIX 2.1, MISP, CSV

### Storage
- **PostgreSQL**: Persistent threat intelligence with full-text search
- **Redis**: Caching, real-time events, session management
- **Partitioning Ready**: Large volume support with table partitioning

## Quick Start

### Prerequisites
- Docker & Docker Compose
- PostgreSQL 16+
- Redis 7+
- API keys for enrichment services (optional but recommended)

### 1. Configure Environment
```bash
cd living_intel
cp .env.example .env
# Edit .env with your API keys
```

### 2. Start Platform
```bash
docker-compose up -d
```

### 3. Verify Health
```bash
curl http://localhost:8080/api/v1/health
```

### 4. Query Threat Intelligence
```bash
# Search for an IP
curl "http://localhost:8080/api/v1/threat-intel/search/ipv4/1.2.3.4"

# Query with filters
curl -X POST http://localhost:8080/api/v1/threat-intel/query \
  -H "Content-Type: application/json" \
  -d '{"type": "ipv4", "severity": "HIGH", "since": "2024-01-01"}'

# Enrich an IOC
curl -X POST http://localhost:8080/api/v1/enrich \
  -H "Content-Type: application/json" \
  -d '{"type": "domain", "value": "example.com"}'
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Living Intel Platform                     │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ Feed Manager│  │ Live Feeds  │  │  Auto Updater       │  │
│  │ (Polling)   │  │ (Streaming) │  │  (CVE, GeoIP, etc)  │  │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
│         │                │                     │             │
│         └────────────────┼─────────────────────┘             │
│                          ▼                                   │
│              ┌───────────────────────┐                       │
│              │   Enrichment Pipeline │                       │
│              │  (12+ Plugins)        │                       │
│              └───────────┬───────────┘                       │
│                          ▼                                   │
│              ┌───────────────────────┐                       │
│              │   PostgreSQL + Redis  │                       │
│              └───────────┬───────────┘                       │
│                          ▼                                   │
│              ┌───────────────────────┐                       │
│              │      REST API         │                       │
│              └───────────────────────┘                       │
└─────────────────────────────────────────────────────────────┘
```

## API Endpoints

### Health & Metrics
- `GET /api/v1/health` - Platform health status
- `GET /api/v1/metrics` - Platform metrics

### Threat Intelligence
- `POST /api/v1/threat-intel/query` - Query with filters
- `GET /api/v1/threat-intel/search/{type}/{value}` - Search IOC
- `GET /api/v1/threat-intel/stats` - Database statistics

### Feed Management
- `GET /api/v1/feeds` - List all feeds
- `GET /api/v1/feeds/{name}` - Get feed details
- `POST /api/v1/feeds` - Create feed
- `PUT /api/v1/feeds/{name}` - Update feed
- `DELETE /api/v1/feeds/{name}` - Delete feed
- `POST /api/v1/feeds/{name}/enable` - Enable feed
- `POST /api/v1/feeds/{name}/disable` - Disable feed
- `POST /api/v1/feeds/{name}/refresh` - Manual refresh

### Live Feeds
- `GET /api/v1/live-feeds` - List live feeds
- `GET /api/v1/live-feeds/metrics` - Live feed metrics
- `POST /api/v1/live-feeds` - Create live feed
- `DELETE /api/v1/live-feeds/{name}` - Delete live feed

### Enrichment
- `POST /api/v1/enrich` - Enrich single IOC
- `POST /api/v1/enrich/bulk` - Bulk enrichment
- `GET /api/v1/enrich/plugins` - List enrichment plugins

### Auto-Updater
- `GET /api/v1/updates` - Check for updates
- `POST /api/v1/updates/{component}` - Apply update
- `GET /api/v1/updates/status` - Update status

### Plugins
- `GET /api/v1/plugins` - List plugins
- `POST /api/v1/plugins/{name}/enable` - Enable plugin
- `POST /api/v1/plugins/{name}/disable` - Disable plugin
- `POST /api/v1/plugins/{name}/reload` - Hot reload plugin

### Threat Hunting
- `POST /api/v1/hunt` - Run threat hunt query

### Export
- `GET /api/v1/export/stix` - Export as STIX 2.1 bundle
- `GET /api/v1/export/misp` - Export as MISP format
- `GET /api/v1/export/csv` - Export as CSV

## Configuration

### Feed Source Configuration
```json
{
  "name": "custom_feed",
  "url": "https://example.com/feed.json",
  "type": "json",
  "parser": "auto",
  "auth": {"api_key": "your_key"},
  "headers": {},
  "enabled": true,
  "interval": 3600,
  "tlp": "WHITE",
  "tags": ["custom", "threat_intel"],
  "filters": {}
}
```

### Live Feed Configuration
```json
{
  "name": "custom_live_feed",
  "url": "wss://example.com/ws",
  "protocol": "websocket",
  "auth": {"token": "your_token"},
  "parser": "auto",
  "enabled": true,
  "interval": 60,
  "tlp": "WHITE",
  "tags": ["live", "realtime"]
}
```

### Supported Protocols
- `http_poll` - Standard HTTP polling
- `http_long_poll` - HTTP long polling
- `sse` - Server-Sent Events
- `websocket` - WebSocket connection
- `taxii` - TAXII 2.1
- `mqtt` - MQTT (planned)

## Enrichment Plugin Development

Create a custom enrichment plugin:

```python
from living_intel.platform import ThreatIntelPlugin, ThreatIntelItem

class CustomEnrichmentPlugin(ThreatIntelPlugin):
    def __init__(self, platform):
        super().__init__(platform)
        self.name = "CustomEnrichment"
        self.version = "1.0.0"
        self.description = "Custom enrichment plugin"
    
    async def initialize(self):
        # Setup connections, load configs
        pass
    
    async def enrich(self, item: ThreatIntelItem) -> ThreatIntelItem:
        # Add enrichment data to item.context
        item.context["custom"] = {"data": "enriched"}
        return item
    
    async def cleanup(self):
        # Close connections
        pass
```

Register in `living_intel/enrichment.py` ENRICHMENT_PLUGINS dict.

## Database Schema

Key tables:
- `threat_intel.threat_intel` - Main threat intelligence store
- `feeds.feed_sources` - Feed source configurations
- `feeds.feed_items` - Raw feed data
- `feeds.live_feed_events` - Live feed events
- `threat_intel.enrichment_results` - Enrichment plugin outputs
- `feeds.plugins` - Plugin registry
- `audit.updater_status` - Auto-updater status
- `audit.audit_log` - Audit trail
- `audit.metrics` - Time-series metrics

## Monitoring

### Health Checks
```bash
# Platform health
curl http://localhost:8080/api/v1/health

# Live feed status
curl http://localhost:8080/api/v1/live-feeds

# Feed status
curl http://localhost:8080/api/v1/feeds
```

### Metrics
- Events received/processed per feed
- Enrichment success rates
- Update status per component
- Database size and growth
- API response times

## Scaling

### Horizontal Scaling
- Run multiple platform instances behind load balancer
- Shared PostgreSQL and Redis
- Each instance processes different feed partitions

### High Volume
- Enable table partitioning (see init.sql)
- Use connection pooling (PgBouncer)
- Redis Cluster for caching
- Consider Elasticsearch for search

## Security

- All API keys stored in environment variables
- TLS for all external connections
- TLP (Traffic Light Protocol) handling
- Audit logging for all operations
- Plugin sandboxing for untrusted code

## License

MIT License - See LICENSE file for details