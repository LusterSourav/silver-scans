"""
Live Feed Manager
Real-time streaming threat intelligence feeds with WebSocket, Server-Sent Events, and polling
"""
import asyncio
import logging
import json
import hashlib
import ssl
from typing import Dict, List, Optional, Any, Callable, AsyncGenerator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
from enum import Enum
import asyncio
import aiohttp
import websockets
import certifi

logger = logging.getLogger(__name__)


class FeedProtocol(Enum):
    HTTP_POLL = "http_poll"
    HTTP_LONG_POLL = "http_long_poll"
    SSE = "sse"
    WEBSOCKET = "websocket"
    TAXII = "taxii"
    MQTT = "mqtt"


@dataclass
class LiveFeedSource:
    """Live threat intelligence feed source configuration"""
    name: str
    url: str
    protocol: FeedProtocol
    auth: Dict = field(default_factory=dict)
    headers: Dict = field(default_factory=dict)
    parser: str = "auto"
    enabled: bool = True
    interval: int = 60  # seconds for polling
    tlp: str = "WHITE"
    tags: List[str] = field(default_factory=list)
    filters: Dict = field(default_factory=dict)
    reconnect_delay: int = 5
    max_reconnect_delay: int = 300
    last_event_id: Optional[str] = None
    last_update: Optional[datetime] = None
    error_count: int = 0
    connection_state: str = "disconnected"


@dataclass
class LiveFeedEvent:
    """Real-time feed event"""
    feed_name: str
    event_id: str
    timestamp: datetime
    event_type: str
    data: Dict
    raw: Any = None


class LiveFeedManager:
    """
    Manages real-time streaming threat intelligence feeds
    Supports WebSocket, SSE, HTTP long-polling, TAXII, and MQTT
    """
    
    def __init__(self, platform):
        self.platform = platform
        self.running = False
        self.feed_sources: Dict[str, LiveFeedSource] = {}
        self.connections: Dict[str, Any] = {}
        self.feed_tasks: Dict[str, asyncio.Task] = {}
        self.event_handlers: List[Callable] = []
        self.event_queue: asyncio.Queue = asyncio.Queue()
        self.metrics = {
            "events_received": 0,
            "events_processed": 0,
            "connection_errors": 0,
            "reconnections": 0
        }
        
        # Register built-in live feeds
        self._register_live_feeds()
    
    def _register_live_feeds(self):
        """Register built-in live feed sources"""
        self.feed_sources = {
            "alienvault_otx_pulses": LiveFeedSource(
                name="alienvault_otx_pulses",
                url="https://otx.alienvault.com/api/v1/pulses/subscribed",
                protocol=FeedProtocol.HTTP_POLL,
                auth={"api_key": "${OTX_API_KEY}"},
                parser="alienvault_otx",
                interval=300,
                tags=["otx", "pulses", "realtime"]
            ),
            "urlhaus_recent": LiveFeedSource(
                name="urlhaus_recent",
                url="https://urlhaus-api.abuse.ch/v1/urls/recent/",
                protocol=FeedProtocol.HTTP_POLL,
                auth={"api_key": "${URLHAUS_API_KEY}", "auth_type": "header_auth_key"},
                parser="urlhaus_api",
                interval=300,
                tags=["urlhaus", "malware", "url", "realtime"]
            ),
            "abuse_ch_sslbl_live": LiveFeedSource(
                name="abuse_ch_sslbl_live",
                url="https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
                protocol=FeedProtocol.HTTP_POLL,
                parser="abuse_ch_sslbl",
                interval=600,
                tags=["sslbl", "c2", "malware", "realtime"]
            ),
            "blocklist_de_live": LiveFeedSource(
                name="blocklist_de_live",
                url="https://lists.blocklist.de/lists/all.txt",
                protocol=FeedProtocol.HTTP_POLL,
                parser="blocklist_de",
                interval=600,
                tags=["blocklist", "ssh", "bruteforce", "realtime"]
            ),
            "emerging_threats_live": LiveFeedSource(
                name="emerging_threats_live",
                url="https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                protocol=FeedProtocol.HTTP_POLL,
                parser="emerging_threats",
                interval=600,
                tags=["emerging_threats", "compromised", "realtime"]
            ),
            "tor_exit_nodes_live": LiveFeedSource(
                name="tor_exit_nodes_live",
                url="https://check.torproject.org/torbulkexitlist",
                protocol=FeedProtocol.HTTP_POLL,
                parser="tor_exit_nodes",
                interval=3600,
                tags=["tor", "exit_nodes", "anonymity", "realtime"]
            ),
            "cisa_kev_live": LiveFeedSource(
                name="cisa_kev_live",
                url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                protocol=FeedProtocol.HTTP_POLL,
                parser="cisa_kev",
                interval=86400,
                tags=["cisa", "kev", "exploited", "vulnerability", "realtime"]
            ),
            "nvd_recent_live": LiveFeedSource(
                name="nvd_recent_live",
                url="https://services.nvd.nist.gov/rest/json/cves/2.0",
                protocol=FeedProtocol.HTTP_POLL,
                auth={"api_key": "${NVD_API_KEY}", "auth_type": "header_api_key"},
                parser="nvd_cve_api",
                interval=3600,
                tags=["nvd", "cve", "vulnerability", "realtime"]
            ),
            "github_advisories_live": LiveFeedSource(
                name="github_advisories_live",
                url="https://api.github.com/advisories",
                protocol=FeedProtocol.HTTP_POLL,
                auth={"token": "${GITHUB_TOKEN}"},
                parser="github_advisories",
                interval=3600,
                tags=["github", "advisory", "vulnerability", "realtime"]
            ),
            "misp_live": LiveFeedSource(
                name="misp_live",
                url="${MISP_URL}/events/restSearch",
                protocol=FeedProtocol.HTTP_POLL,
                auth={"key": "${MISP_KEY}"},
                parser="misp",
                interval=300,
                tags=["misp", "threat_intel", "realtime"]
            ),
            "opencti_live": LiveFeedSource(
                name="opencti_live",
                url="${OPENCTI_URL}/graphql",
                protocol=FeedProtocol.HTTP_POLL,
                auth={"token": "${OPENCTI_TOKEN}"},
                parser="opencti",
                interval=300,
                tags=["opencti", "threat_intel", "realtime"]
            ),
            "taxii_live": LiveFeedSource(
                name="taxii_live",
                url="${TAXII_URL}/api/v1/collections/",
                protocol=FeedProtocol.TAXII,
                auth={"username": "${TAXII_USER}", "password": "${TAXII_PASS}"},
                parser="taxii",
                interval=300,
                tags=["taxii", "stix", "threat_intel", "realtime"]
            )
        }
    
    def add_event_handler(self, handler: Callable):
        """Add event handler for live feed events"""
        self.event_handlers.append(handler)
    
    async def start(self):
        """Start live feed manager"""
        self.running = True
        logger.info("Starting Live Feed Manager")
        
        # Start event processor
        asyncio.create_task(self._process_event_queue())
        
        # Start all enabled feeds
        for name, feed in self.feed_sources.items():
            if feed.enabled:
                await self._start_feed(feed)
        
        logger.info(f"Live Feed Manager started with {len(self.feed_tasks)} feeds")
    
    async def stop(self):
        """Stop live feed manager"""
        self.running = False
        
        # Stop all feed tasks
        for task in self.feed_tasks.values():
            task.cancel()
        
        await asyncio.gather(*self.feed_tasks.values(), return_exceptions=True)
        
        # Close connections
        for conn in self.connections.values():
            if hasattr(conn, 'close'):
                await conn.close()
        
        logger.info("Live Feed Manager stopped")
    
    async def _start_feed(self, feed: LiveFeedSource):
        """Start a live feed based on its protocol"""
        feed.connection_state = "connecting"
        
        if feed.protocol == FeedProtocol.HTTP_POLL:
            self.feed_tasks[feed.name] = asyncio.create_task(self._run_http_poll(feed))
        elif feed.protocol == FeedProtocol.HTTP_LONG_POLL:
            self.feed_tasks[feed.name] = asyncio.create_task(self._run_http_long_poll(feed))
        elif feed.protocol == FeedProtocol.SSE:
            self.feed_tasks[feed.name] = asyncio.create_task(self._run_sse(feed))
        elif feed.protocol == FeedProtocol.WEBSOCKET:
            self.feed_tasks[feed.name] = asyncio.create_task(self._run_websocket(feed))
        elif feed.protocol == FeedProtocol.TAXII:
            self.feed_tasks[feed.name] = asyncio.create_task(self._run_taxii(feed))
        else:
            logger.warning(f"Unknown protocol for feed {feed.name}: {feed.protocol}")
    
    async def _run_http_poll(self, feed: LiveFeedSource):
        """Run HTTP polling feed"""
        last_hash = ""
        backoff = feed.reconnect_delay
        
        while self.running and feed.enabled:
            try:
                feed.connection_state = "connected"
                
                async with aiohttp.ClientSession() as session:
                    headers = feed.headers.copy()
                    # Handle different API key formats
                    if feed.auth.get("api_key"):
                        auth_type = feed.auth.get("auth_type", "bearer")
                        if feed.name == "nvd_recent_live":
                            headers["apiKey"] = feed.auth["api_key"]
                        elif feed.name == "urlhaus_recent":
                            headers["Auth-Key"] = feed.auth["api_key"]
                        elif feed.auth.get("auth_type") == "header_auth_key":
                            headers["Auth-Key"] = feed.auth["api_key"]
                        elif feed.auth.get("auth_type") == "header_api_key":
                            headers["apiKey"] = feed.auth["api_key"]
                        else:
                            headers["Authorization"] = f"Bearer {feed.auth['api_key']}"
                    elif feed.auth.get("token"):
                        headers["Authorization"] = f"Bearer {feed.auth['token']}"
                    elif feed.auth.get("key"):
                        headers["Authorization"] = feed.auth["key"]
                    
                    async with aiohttp.ClientSession() as session:
                        async with session.get(feed.url, headers=headers) as response:
                            if response.status == 200:
                                content = await response.read()
                                content_hash = hashlib.sha256(content).hexdigest()
                                
                                if content_hash != last_hash:
                                    last_hash = content_hash
                                    feed.last_hash = content_hash
                                    feed.last_update = datetime.now()
                                    feed.error_count = 0
                                    backoff = feed.reconnect_delay
                                    
                                    # Parse and queue events
                                    events = await self._parse_feed_content(content, feed)
                                    for event in events:
                                        await self.event_queue.put(event)
                                        self.metrics["events_received"] += 1
                                else:
                                    logger.debug(f"Feed {feed.name} unchanged")
                            else:
                                raise Exception(f"HTTP {response.status}")
                
                await asyncio.sleep(feed.interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Feed {feed.name} error: {e}")
                feed.error_count += 1
                feed.connection_state = "error"
                self.metrics["connection_errors"] += 1
                
                await asyncio.sleep(min(backoff, feed.max_reconnect_delay))
                backoff = min(backoff * 2, feed.max_reconnect_delay)
                self.metrics["reconnections"] += 1
        
        feed.connection_state = "disconnected"
    
    async def _run_http_long_poll(self, feed: LiveFeedSource):
        """Run HTTP long-polling feed"""
        # Similar to HTTP poll but with longer timeout
        await self._run_http_poll(feed)
    
    async def _run_sse(self, feed: LiveFeedSource):
        """Run Server-Sent Events feed"""
        backoff = feed.reconnect_delay
        last_event_id = feed.last_event_id
        
        while self.running and feed.enabled:
            try:
                feed.connection_state = "connected"
                
                headers = {
                    "Accept": "text/event-stream",
                    "Cache-Control": "no-cache"
                }
                headers.update(feed.headers)
                
                if feed.auth.get("api_key"):
                    headers["Authorization"] = f"Bearer {feed.auth['api_key']}"
                elif feed.auth.get("token"):
                    headers["Authorization"] = f"Bearer {feed.auth['token']}"
                
                if last_event_id:
                    headers["Last-Event-ID"] = last_event_id
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(feed.url, headers=headers) as response:
                        if response.status != 200:
                            raise Exception(f"HTTP {response.status}")
                        
                        feed.error_count = 0
                        backoff = feed.reconnect_delay
                        
                        async for line in response.content:
                            line = line.decode('utf-8').strip()
                            
                            if line.startswith("id: "):
                                last_event_id = line[4:]
                                feed.last_event_id = last_event_id
                            elif line.startswith("data: "):
                                data = line[6:]
                                try:
                                    event_data = json.loads(data)
                                    event = LiveFeedEvent(
                                        feed_name=feed.name,
                                        event_id=last_event_id or hashlib.md5(data.encode()).hexdigest()[:16],
                                        timestamp=datetime.now(),
                                        event_type=event_data.get("type", "unknown"),
                                        data=event_data,
                                        raw=data
                                    )
                                    await self.event_queue.put(event)
                                    self.metrics["events_received"] += 1
                                except json.JSONDecodeError:
                                    pass
                            elif line == "":
                                continue
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"SSE feed {feed.name} error: {e}")
                feed.error_count += 1
                feed.connection_state = "error"
                self.metrics["connection_errors"] += 1
                
                await asyncio.sleep(min(backoff, feed.max_reconnect_delay))
                backoff = min(backoff * 2, feed.max_reconnect_delay)
                self.metrics["reconnections"] += 1
        
        feed.connection_state = "disconnected"
    
    async def _run_websocket(self, feed: LiveFeedSource):
        """Run WebSocket feed"""
        backoff = feed.reconnect_delay
        
        while self.running and feed.enabled:
            try:
                feed.connection_state = "connected"
                
                headers = feed.headers.copy()
                if feed.auth.get("api_key"):
                    headers["Authorization"] = f"Bearer {feed.auth['api_key']}"
                elif feed.auth.get("token"):
                    headers["Authorization"] = f"Bearer {feed.auth['token']}"
                
                ssl_context = ssl.create_default_context(cafile=certifi.where())
                
                async with websockets.connect(
                    feed.url,
                    extra_headers=headers,
                    ssl=ssl_context,
                    ping_interval=30,
                    ping_timeout=10
                ) as websocket:
                    self.connections[feed.name] = websocket
                    feed.error_count = 0
                    backoff = feed.reconnect_delay
                    
                    async for message in websocket:
                        try:
                            data = json.loads(message)
                            event = LiveFeedEvent(
                                feed_name=feed.name,
                                event_id=data.get("id", hashlib.md5(message.encode()).hexdigest()[:16]),
                                timestamp=datetime.now(),
                                event_type=data.get("type", "unknown"),
                                data=data,
                                raw=message
                            )
                            await self.event_queue.put(event)
                            self.metrics["events_received"] += 1
                        except json.JSONDecodeError:
                            pass
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"WebSocket feed {feed.name} error: {e}")
                feed.error_count += 1
                feed.connection_state = "error"
                self.metrics["connection_errors"] += 1
                
                if feed.name in self.connections:
                    del self.connections[feed.name]
                
                await asyncio.sleep(min(backoff, feed.max_reconnect_delay))
                backoff = min(backoff * 2, feed.max_reconnect_delay)
                self.metrics["reconnections"] += 1
        
        feed.connection_state = "disconnected"
        if feed.name in self.connections:
            del self.connections[feed.name]
    
    async def _run_taxii(self, feed: LiveFeedSource):
        """Run TAXII 2.1 feed"""
        backoff = feed.reconnect_delay
        
        while self.running and feed.enabled:
            try:
                feed.connection_state = "connected"
                
                auth = feed.auth
                auth_header = None
                if auth.get("username") and auth.get("password"):
                    import base64
                    credentials = f"{auth['username']}:{auth['password']}"
                    auth_header = f"Basic {base64.b64encode(credentials.encode()).decode()}"
                
                headers = {
                    "Accept": "application/taxii+json;version=2.1",
                    "Content-Type": "application/taxii+json;version=2.1"
                }
                if auth_header:
                    headers["Authorization"] = auth_header
                
                async with aiohttp.ClientSession() as session:
                    # Get collections
                    async with session.get(feed.url, headers=headers) as response:
                        if response.status != 200:
                            raise Exception(f"HTTP {response.status}")
                        collections = await response.json()
                    
                    # Poll each collection for objects
                    for collection in collections.get("collections", []):
                        collection_url = f"{feed.url}{collection['id']}/objects/"
                        params = {"limit": 100}
                        if feed.last_event_id:
                            params["added_after"] = feed.last_event_id
                        
                        async with session.get(collection_url, headers=headers, params=params) as response:
                            if response.status == 200:
                                bundle = await response.json()
                                objects = bundle.get("objects", [])
                                
                                for obj in objects:
                                    event = LiveFeedEvent(
                                        feed_name=feed.name,
                                        event_id=obj.get("id", ""),
                                        timestamp=datetime.fromisoformat(obj.get("created", "").replace("Z", "+00:00")),
                                        event_type=obj.get("type", "unknown"),
                                        data=obj,
                                        raw=obj
                                    )
                                    await self.event_queue.put(event)
                                    self.metrics["events_received"] += 1
                                
                                # Update last event ID
                                if objects:
                                    feed.last_event_id = objects[-1].get("created", "")
                    
                    feed.error_count = 0
                    backoff = feed.reconnect_delay
                
                await asyncio.sleep(feed.interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"TAXII feed {feed.name} error: {e}")
                feed.error_count += 1
                feed.connection_state = "error"
                self.metrics["connection_errors"] += 1
                
                await asyncio.sleep(min(backoff, feed.max_reconnect_delay))
                backoff = min(backoff * 2, feed.max_reconnect_delay)
                self.metrics["reconnections"] += 1
        
        feed.connection_state = "disconnected"
    
    async def _process_event_queue(self):
        """Process events from the queue"""
        while self.running:
            try:
                event = await asyncio.wait_for(self.event_queue.get(), timeout=1.0)
                
                # Normalize event to ThreatIntelItem
                threat_item = self._normalize_event(event)
                
                if threat_item:
                    # Ingest into platform
                    await self.platform.ingest_threat_item(threat_item)
                    self.metrics["events_processed"] += 1
                    
                    # Call handlers
                    for handler in self.event_handlers:
                        try:
                            if asyncio.iscoroutinefunction(handler):
                                await handler(threat_item)
                            else:
                                handler(threat_item)
                        except Exception as e:
                            logger.error(f"Event handler error: {e}")
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Event processing error: {e}")
    
    def _normalize_event(self, event: LiveFeedEvent):
        """Normalize live feed event to ThreatIntelItem"""
        from .platform import ThreatIntelItem
        
        data = event.data
        
        # Extract IOC from event data
        ioc_value = None
        ioc_type = "unknown"
        
        # Try common IOC fields with proper type mapping
        ioc_fields = {
            'ipv4': ['ip', 'ipv4', 'destination.ip', 'source.ip', 'ip_src', 'ip_dst', 'ip_address'],
            'ipv6': ['ipv6'],
            'domain': ['domain', 'hostname', 'fqdn', 'url_domain'],
            'url': ['url', 'uri', 'link'],
            'md5': ['md5'],
            'sha1': ['sha1'],
            'sha256': ['sha256'],
            'sha512': ['sha512'],
            'hash': ['hash', 'file_hash'],
            'email': ['email', 'from', 'sender'],
            'cidr': ['cidr', 'network', 'subnet'],
            'file_path': ['file_path', 'path', 'filename'],
            'mutex': ['mutex', 'mutex_name'],
            'registry': ['registry', 'registry_key', 'regkey'],
            'cve': ['cve', 'cve_id', 'vulnerability']
        }
        
        for ioc_type_key, field_names in ioc_fields.items():
            for field in field_names:
                if field in data and data[field]:
                    ioc_value = str(data[field]).strip()
                    ioc_type = ioc_type_key
                    break
            if ioc_value:
                break
        
        # If we got a generic 'hash' type, try to determine specific hash type
        if ioc_type == "hash" and ioc_value:
            ioc_type = self._guess_ioc_type(ioc_value)
        
        # If we got a generic 'ip' type, check if it's IPv6
        if ioc_type == "ip" and ioc_value:
            if ':' in ioc_value and '.' not in ioc_value:
                ioc_type = "ipv6"
            else:
                ioc_type = "ipv4"
        
        if not ioc_value:
            # Try to extract from STIX objects
            if event.event_type in ['indicator', 'malware', 'tool', 'attack-pattern', 'intrusion-set']:
                # STIX object - extract pattern
                pattern = data.get("pattern", "")
                if pattern:
                    ioc_value = pattern
                    ioc_type = "stix_pattern"
        
        if not ioc_value:
            return None
        
        # Validate IOC
        if not self._validate_ioc(ioc_type, ioc_value):
            return None
        
        return ThreatIntelItem(
            id=event.event_id or hashlib.sha256(f"{ioc_value}:{event.timestamp}".encode()).hexdigest()[:16],
            type=ioc_type,
            value=ioc_value,
            confidence=0.8,
            severity="MEDIUM",
            source=event.feed_name,
            first_seen=event.timestamp,
            last_seen=event.timestamp,
            tags=["live_feed"] + self.feed_sources.get(event.feed_name, LiveFeedSource(name="", url="", protocol=FeedProtocol.HTTP_POLL)).tags,
            context={
                "feed_event": event.data,
                "feed_name": event.feed_name,
                "event_type": event.event_type
            },
            tlp=self.feed_sources[event.feed_name].tlp
        )
    
    def _validate_ioc(self, ioc_type: str, value: str) -> bool:
        """Validate IOC format"""
        import re
        validators = {
            'ipv4': lambda v: re.match(r'^(\d{1,3}\.){3}\d{1,3}$', v) and all(0 <= int(o) <= 255 for o in v.split('.')),
            'ipv6': lambda v: ':' in v and len(v) <= 45,
            'domain': lambda v: re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', v),
            'url': lambda v: v.startswith(('http://', 'https://')),
            'md5': lambda v: re.match(r'^[a-fA-F0-9]{32}$', v),
            'sha1': lambda v: re.match(r'^[a-fA-F0-9]{40}$', v),
            'sha256': lambda v: re.match(r'^[a-fA-F0-9]{64}$', v),
            'sha512': lambda v: re.match(r'^[a-fA-F0-9]{128}$', v),
            'cidr': lambda v: re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', v),
        }
        validator = validators.get(ioc_type, lambda v: True)
        return validator(str(value))
    
    async def _parse_feed_content(self, content: bytes, feed: LiveFeedSource) -> List[LiveFeedEvent]:
        """Parse feed content into events"""
        events = []
        
        if feed.parser == "json" or feed.parser == "auto":
            try:
                data = json.loads(content.decode('utf-8'))
                if isinstance(data, list):
                    for i, item in enumerate(data):
                        events.append(LiveFeedEvent(
                            feed_name=feed.name,
                            event_id=f"{feed.name}:{i}:{datetime.now().timestamp()}",
                            timestamp=datetime.now(),
                            event_type="feed_item",
                            data=item,
                            raw=item
                        ))
                elif isinstance(data, dict):
                    events.append(LiveFeedEvent(
                        feed_name=feed.name,
                        event_id=f"{feed.name}:{datetime.now().timestamp()}",
                        timestamp=datetime.now(),
                        event_type="feed_data",
                        data=data,
                        raw=data
                    ))
            except:
                pass
        elif feed.parser == "csv":
            import csv
            import io
            text = content.decode('utf-8', errors='ignore')
            reader = csv.DictReader(io.StringIO(text))
            for i, row in enumerate(reader):
                events.append(LiveFeedEvent(
                    feed_name=feed.name,
                    event_id=f"{feed.name}:{i}:{datetime.now().timestamp()}",
                    timestamp=datetime.now(),
                    event_type="csv_row",
                    data=row,
                    raw=row
                ))
        elif feed.parser in ["txt", "text"]:
            text = content.decode('utf-8', errors='ignore')
            for i, line in enumerate(text.split('\n')):
                line = line.strip()
                if line and not line.startswith('#'):
                    events.append(LiveFeedEvent(
                        feed_name=feed.name,
                        event_id=f"{feed.name}:{i}:{datetime.now().timestamp()}",
                        timestamp=datetime.now(),
                        event_type="text_line",
                        data={"line": line},
                        raw=line
                    ))
        
        return events
    
    def get_feed_status(self) -> Dict:
        """Get status of all live feeds"""
        return {
            name: {
                "enabled": feed.enabled,
                "protocol": feed.protocol.value,
                "connection_state": feed.connection_state,
                "last_update": feed.last_update.isoformat() if feed.last_update else None,
                "error_count": feed.error_count,
                "interval": feed.interval,
                "last_event_id": feed.last_event_id
            }
            for name, feed in self.feed_sources.items()
        }
    
    def get_metrics(self) -> Dict:
        return self.metrics.copy()
    
    async def add_feed(self, feed: LiveFeedSource):
        """Add a new live feed"""
        self.feed_sources[feed.name] = feed
        if feed.enabled and self.running:
            await self._start_feed(feed)
    
    async def remove_feed(self, name: str):
        """Remove a live feed"""
        if name in self.feed_tasks:
            self.feed_tasks[name].cancel()
            await self.feed_tasks[name]
            del self.feed_tasks[name]
        
        if name in self.connections:
            await self.connections[name].close()
            del self.connections[name]
        
        if name in self.feed_sources:
            del self.feed_sources[name]
    
    async def enable_feed(self, name: str):
        """Enable a live feed"""
        if name in self.feed_sources:
            self.feed_sources[name].enabled = True
            if self.running:
                await self._start_feed(self.feed_sources[name])
    
    async def disable_feed(self, name: str):
        """Disable a live feed"""
        if name in self.feed_sources:
            self.feed_sources[name].enabled = False
            if name in self.feed_tasks:
                self.feed_tasks[name].cancel()
                del self.feed_tasks[name]
            if name in self.connections:
                await self.connections[name].close()
                del self.connections[name]