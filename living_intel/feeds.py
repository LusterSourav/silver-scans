"""
Feed Management System
Handles ingestion, parsing, and processing of threat intelligence feeds
"""
import asyncio
import logging
import hashlib
import gzip
import csv
import io
import re
import json
from typing import Dict, List, Optional, Any, Callable, AsyncGenerator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import aiohttp
import aiofiles

from living_intel.platform import ThreatIntelItem

logger = logging.getLogger(__name__)


class FeedManager:
    """Manages threat intelligence feed ingestion and processing"""
    
    def __init__(self, platform):
        self.platform = platform
        self.parsers = {}
        self.running = False
        self.feed_tasks: Dict[str, asyncio.Task] = {}
        
        # Register built-in parsers
        self._register_parsers()
    
    def _register_parsers(self):
        """Register built-in feed parsers"""
        self.parsers = {
            "json": self._parse_json,
            "json_gz": self._parse_json_gz,
            "csv": self._parse_csv,
            "txt": self._parse_txt,
            "stix": self._parse_stix,
            "misp": self._parse_misp,
            "alienvault_otx": self._parse_alienvault_otx,
            "abuse_ch_sslbl": self._parse_abuse_ch_sslbl,
            "abuse_ch_feodo": self._parse_abuse_ch_feodo,
            "urlhaus": self._parse_urlhaus,
            "urlhaus_api": self._parse_urlhaus_api,
            "blocklist_de": self._parse_blocklist_de,
            "spamhaus_drop": self._parse_spamhaus_drop,
            "spamhaus_edrop": self._parse_spamhaus_edrop,
            "emerging_threats": self._parse_emerging_threats,
            "tor_exit_nodes": self._parse_tor_exit_nodes,
            "cisa_kev": self._parse_cisa_kev,
            "nvd_cve": self._parse_nvd_cve,
            "nvd_cve_api": self._parse_nvd_cve_api,
            "github_advisories": self._parse_github_advisories,
            "urlhaus": self._parse_urlhaus,
            "abuse_ch_feodo": self._parse_abuse_ch_feodo,
            "abuse_ch_sslbl": self._parse_abuse_ch_sslbl,
        }
    
    async def run_feeds(self):
        """Run all enabled feeds"""
        for name, feed in self.platform.feed_sources.items():
            if feed.enabled and name not in self.feed_tasks:
                self.feed_tasks[name] = asyncio.create_task(self._run_feed_loop(name))
    
    async def _run_feed_loop(self, feed_name: str):
        """Run a single feed on its interval"""
        feed = self.platform.feed_sources[feed_name]
        
        while True:
            try:
                if feed.enabled:
                    await self._process_feed(feed)
                
                await asyncio.sleep(feed.interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Feed {feed_name} error: {e}")
                feed.error_count += 1
                await asyncio.sleep(60)  # Back off on error
    
    async def _process_feed(self, feed: 'FeedSource'):
        """Process a single feed"""
        logger.info(f"Processing feed: {feed.name}")
        
        try:
            async with aiohttp.ClientSession() as session:
                headers = feed.headers.copy()
                # Handle different API key formats
                if feed.auth.get("api_key"):
                    # Check for specific API key formats
                    if feed.name == "nvd_recent":
                        headers["apiKey"] = feed.auth["api_key"]
                    elif feed.name == "abuse_ch_urlhaus":
                        headers["Auth-Key"] = feed.auth["api_key"]
                    else:
                        headers["Authorization"] = f"Bearer {feed.auth['api_key']}"
                elif feed.auth.get("token"):
                    headers["Authorization"] = f"Bearer {feed.auth['token']}"
                
                async with aiohttp.ClientSession(headers=headers) as session:
                    async with session.get(feed.url) as response:
                        if response.status != 200:
                            raise Exception(f"HTTP {response.status}: {await response.text()}")
                        
                        content = await response.read()
                        
                        # Check if content changed
                        content_hash = hashlib.sha256(content).hexdigest()
                        if content_hash == feed.last_hash:
                            logger.info(f"Feed {feed.name} unchanged, skipping")
                            return
                        
                        feed.last_hash = content_hash
                        feed.last_update = datetime.now()
                        feed.error_count = 0
                        
                        # Parse content
                        parser = self.parsers.get(feed.parser, self._parse_auto)
                        items = await parser(content, feed)
                        
                        # Ingest items
                        ingested = 0
                        for item in items:
                            if await self.platform.ingest_threat_item(item):
                                self.platform.metrics["items_ingested"] += 1
                                ingested += 1
                        
                        self.platform.metrics["feeds_processed"] += 1
                        
                        # Update database
                        await self._update_feed_status(feed, success=True)
                        
                        logger.info(f"Feed {feed.name}: ingested {ingested} items")
                        
        except Exception as e:
            logger.error(f"Feed {feed.name} failed: {e}")
            await self._update_feed_status(feed, success=False, error=str(e))
            raise
    
    async def _update_feed_status(self, feed, success: bool, error: str = None):
        """Update feed status in database"""
        if not self.platform.db_pool:
            return
        
        try:
            async with self.platform.db_pool.acquire() as conn:
                await conn.execute("""
                    UPDATE feed_sources SET 
                        last_update = $1,
                        last_hash = $2,
                        error_count = $3,
                        updated_at = NOW()
                    WHERE name = $4
                """, 
                datetime.now() if success else feed.last_update,
                feed.last_hash if success else feed.last_hash,
                feed.error_count,
                feed.name
                )
        except Exception as e:
            logger.error(f"Failed to update feed status: {e}")
    
    # Parsers
    
    async def _parse_auto(self, content: bytes, feed) -> List:
        """Auto-detect and parse feed content"""
        # Try to detect format
        if content.startswith(b'{') or content.startswith(b'['):
            return await self._parse_json(content, feed)
        elif content.startswith(b'\x1f\x8b'):  # gzip
            return await self._parse_json_gz(content, feed)
        elif b',' in content[:100] and b'\n' in content[:200]:
            return await self._parse_csv(content, feed)
        else:
            return await self._parse_txt(content, feed)
    
    async def _parse_json(self, content: bytes, feed) -> List:
        data = json.loads(content.decode('utf-8'))
        items = []
        
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            if 'data' in data:
                items = data['data']
            elif 'results' in data:
                items = data['results']
            elif 'pulses' in data:
                items = data['pulses']
            else:
                items = [data]
        
        return [self._normalize_item(item, feed) for item in items if isinstance(item, dict)]
    
    async def _parse_json_gz(self, content: bytes, feed) -> List:
        decompressed = gzip.decompress(content)
        return await self._parse_json(decompressed, feed)
    
    async def _parse_csv(self, content: bytes, feed) -> List:
        text = content.decode('utf-8', errors='ignore')
        reader = csv.DictReader(io.StringIO(text))
        items = []
        for row in reader:
            item = self._normalize_item(row, feed)
            if item:
                items.append(item)
        return items
    
    async def _parse_txt(self, content: bytes, feed) -> List:
        text = content.decode('utf-8', errors='ignore')
        lines = [line.strip() for line in text.split('\n') if line.strip() and not line.startswith('#')]
        items = []
        for line in lines:
            item = self._parse_text_line(line)
            if item:
                items.append(item)
        return items
    
    def _parse_text_line(self, line: str) -> Optional[Dict]:
        """Parse a single line of text for IOCs"""
        # Extract IPs, domains, hashes, URLs
        ioc_patterns = {
            'ipv4': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'domain': r'\b[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+\b',
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b',
            'url': r'https?://[^\s<>"]+'
        }
        
        items = []
        for ioc_type, pattern in ioc_patterns.items():
            matches = re.findall(pattern, line)
            for match in matches:
                yield {
                    "id": hashlib.sha256(f"{match}:{datetime.now()}".encode()).hexdigest()[:16],
                    "type": ioc_type,
                    "value": match,
                    "confidence": 0.7,
                    "severity": "MEDIUM",
                    "source": "text_feed",
                    "first_seen": datetime.now(),
                    "last_seen": datetime.now(),
                    "tags": ["text_feed"],
                    "context": {"source_line": line},
                    "tlp": "WHITE"
                }
        return list(items) if items else None
    
    async def _parse_stix(self, content: bytes, feed) -> List:
        # STIX/TAXII parsing would go here
        return []
    
    async def _parse_misp(self, content: bytes, feed) -> List:
        # MISP format parsing
        return []
    
    def _normalize_item(self, item: Dict, feed) -> Optional[Dict]:
        """Normalize feed item to ThreatIntelItem format"""
        # Extract IOC from various feed formats
        ioc_mappings = {
            'ip': ['ip', 'ipv4', 'ipv6', 'destination.ip', 'source.ip', 'ip_src', 'ip_dst'],
            'domain': ['domain', 'hostname', 'fqdn', 'url', 'url_domain'],
            'url': ['url', 'uri', 'link'],
            'hash': ['hash', 'md5', 'sha1', 'sha256', 'sha512', 'file_hash'],
            'email': ['email', 'from', 'sender'],
            'cidr': ['cidr', 'network', 'subnet'],
            'registry': ['registry', 'registry_key', 'regkey'],
            'mutex': ['mutex', 'mutex_name'],
            'file_path': ['file_path', 'path', 'filename'],
            'registry_value': ['registry_value', 'reg_value']
        }
        
        # Try to extract IOC from various field names
        ioc_value = None
        ioc_type = "unknown"
        
        for ioc_type_key, field_names in ioc_mappings.items():
            for field in field_names:
                if field in item:
                    value = item[field]
                    if isinstance(value, str) and value:
                        ioc_value = value
                        ioc_type = ioc_type_key
                        break
            if ioc_value:
                break
        
        # Check for direct IOC fields
        if not ioc_value:
            for key in ['indicator', 'ioc', 'observable', 'value', 'artifact']:
                if key in item and item[key]:
                    ioc_value = item[key]
                    ioc_type = self._guess_ioc_type(ioc_value)
                    break
        
        if not ioc_value:
            return None
        
        # Validate and clean IOC
        ioc_value = str(ioc_value).strip()
        if not self._validate_ioc(ioc_type, ioc_value):
            return None
        
        return {
            "id": hashlib.sha256(f"{ioc_value}:{datetime.now()}".encode()).hexdigest()[:16],
            "type": ioc_type,
            "value": ioc_value,
            "confidence": 0.7,
            "severity": "MEDIUM",
            "source": "feed",
            "first_seen": datetime.now(),
            "last_seen": datetime.now(),
            "tags": ["feed"],
            "context": {"source_feed": "unknown"},
            "tlp": "WHITE"
        }
    
    def _guess_ioc_type(self, value: str) -> str:
        value = str(value).strip()
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
            return 'ipv4'
        elif re.match(r'^[a-fA-F0-9]{32}$', value):
            return 'md5'
        elif re.match(r'^[a-fA-F0-9]{40}$', value):
            return 'sha1'
        elif re.match(r'^[a-fA-F0-9]{64}$', value):
            return 'sha256'
        elif re.match(r'^[a-fA-F0-9]{128}$', value):
            return 'sha512'
        elif re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', value):
            return 'domain'
        elif re.match(r'^https?://', value):
            return 'url'
        elif re.match(r'^[a-fA-F0-9]{32}$', value):
            return 'md5'
        return 'unknown'
    
    def _validate_ioc(self, ioc_type: str, value: str) -> bool:
        validators = {
            'ipv4': lambda v: bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', v)) and all(0 <= int(o) <= 255 for o in v.split('.')),
            'ipv6': lambda v: ':' in v and len(v) <= 45,
            'domain': lambda v: bool(re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', v)),
            'url': lambda v: v.startswith(('http://', 'https://')),
            'md5': lambda v: bool(re.match(r'^[a-fA-F0-9]{32}$', v)),
            'sha1': lambda v: bool(re.match(r'^[a-fA-F0-9]{40}$', v)),
            'sha256': lambda v: bool(re.match(r'^[a-fA-F0-9]{64}$', v)),
            'sha512': lambda v: bool(re.match(r'^[a-fA-F0-9]{128}$', v)),
            'cidr': lambda v: bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', v)),
        }
        validator = validators.get(ioc_type, lambda v: True)
        return validator(str(value))
    
    # Feed-specific parsers
    
    async def _parse_alienvault_otx(self, content: bytes, feed) -> List:
        data = json.loads(content.decode('utf-8'))
        pulses = data.get('results', data.get('pulses', []))
        items = []
        
        for pulse in pulses:
            indicators = pulse.get('indicators', [])
            for indicator in indicators:
                item = self._normalize_item(indicator, feed)
                if item:
                    item['context'] = {
                        'pulse_id': pulse.get('id'),
                        'pulse_name': pulse.get('name'),
                        'pulse_tags': pulse.get('tags', []),
                        'pulse_created': pulse.get('created'),
                        'pulse_modified': pulse.get('modified')
                    }
                    yield item
    
    async def _parse_abuse_ch_sslbl(self, content: bytes, feed) -> List:
        text = content.decode('utf-8', errors='ignore')
        reader = csv.DictReader(io.StringIO(text), delimiter=',')
        for row in reader:
            yield {
                "id": hashlib.sha256(f"{row.get('ip_address', '')}:{datetime.now()}".encode()).hexdigest()[:16],
                "type": "ipv4",
                "value": row.get('ip_address', ''),
                "confidence": 0.9,
                "severity": "HIGH",
                "source": "abuse_ch_sslbl",
                "first_seen": datetime.now(),
                "last_seen": datetime.now(),
                "tags": ["sslbl", "c2", "malware"],
                "context": {"port": row.get('port'), "first_seen": row.get('first_seen'), "last_online": row.get('last_online')},
                "tlp": "WHITE"
            }
    
    async def _parse_abuse_ch_feodo(self, content: bytes, feed) -> List:
        text = content.decode('utf-8', errors='ignore')
        reader = csv.DictReader(io.StringIO(text), delimiter=',')
        for row in reader:
            yield {
                "id": hashlib.sha256(f"{row.get('ip', '')}:{datetime.now()}".encode()).hexdigest()[:16],
                "type": "ipv4",
                "value": row.get('ip', ''),
                "confidence": 0.9,
                "severity": "HIGH",
                "source": "abuse_ch_feodo",
                "first_seen": datetime.now(),
                "last_seen": datetime.now(),
                "tags": ["feodo", "c2", "banking", "trojan"],
                "context": {"port": row.get('port'), "version": row.get('version'), "malware": row.get('malware')},
                "tlp": "WHITE"
            }
    
    async def _parse_urlhaus(self, content: bytes, feed) -> List:
        text = content.decode('utf-8', errors='ignore')
        reader = csv.DictReader(io.StringIO(text), delimiter=',')
        for row in reader:
            yield {
                "id": hashlib.sha256(f"{row.get('url', '')}:{datetime.now()}".encode()).hexdigest()[:16],
                "type": "url",
                "value": row.get('url', ''),
                "confidence": 0.9,
                "severity": "HIGH",
                "source": "urlhaus",
                "first_seen": datetime.now(),
                "last_seen": datetime.now(),
                "tags": ["urlhaus", "malware", "url"],
                "context": {
                    "threat": row.get('threat'),
                    "tags": row.get('tags'),
                    "urlhaus_link": row.get('urlhaus_link'),
                    "date_added": row.get('date_added')
                },
                "tlp": "WHITE"
            }
    
    async def _parse_blocklist_de(self, content: bytes, feed) -> List:
        text = content.decode('utf-8', errors='ignore')
        for line in text.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                parts = line.split('\t')
                if len(parts) >= 2:
                    yield {
                        "id": hashlib.sha256(f"{parts[0]}:{datetime.now()}".encode()).hexdigest()[:16],
                        "type": "ipv4",
                        "value": parts[0],
                        "confidence": 0.8,
                        "severity": "HIGH",
                        "source": "blocklist_de",
                        "first_seen": datetime.now(),
                        "last_seen": datetime.now(),
                        "tags": ["blocklist", "ssh", "bruteforce"],
                        "context": {"port": parts[1] if len(parts) > 1 else "", "service": parts[2] if len(parts) > 2 else ""},
                        "tlp": "WHITE"
                    }
    
    async def _parse_spamhaus_drop(self, content: bytes, feed) -> List:
        text = content.decode('utf-8', errors='ignore')
        for line in text.split('\n'):
            line = line.strip()
            if line and not line.startswith(';'):
                parts = line.split()
                if len(parts) >= 2:
                    yield {
                        "id": hashlib.sha256(f"{parts[0]}:{datetime.now()}".encode()).hexdigest()[:16],
                        "type": "cidr",
                        "value": parts[0],
                        "confidence": 0.9,
                        "severity": "HIGH",
                        "source": "spamhaus_drop",
                        "first_seen": datetime.now(),
                        "last_seen": datetime.now(),
                        "tags": ["spamhaus", "drop", "network"],
                        "context": {"description": parts[1] if len(parts) > 1 else ""},
                        "tlp": "WHITE"
                    }
    
    async def _parse_spamhaus_edrop(self, content: bytes, feed) -> List:
        return await self._parse_spamhaus_drop(content, feed)
    
    async def _parse_emerging_threats(self, content: bytes, feed) -> List:
        text = content.decode('utf-8', errors='ignore')
        for line in text.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                yield {
                    "id": hashlib.sha256(f"{line}:{datetime.now()}".encode()).hexdigest()[:16],
                    "type": "ipv4",
                    "value": line,
                    "confidence": 0.8,
                    "severity": "HIGH",
                    "source": "emerging_threats",
                    "first_seen": datetime.now(),
                    "last_seen": datetime.now(),
                    "tags": ["emerging_threats", "compromised"],
                    "context": {},
                    "tlp": "WHITE"
                }
    
    async def _parse_tor_exit_nodes(self, content: bytes, feed) -> List:
        text = content.decode('utf-8', errors='ignore')
        for line in text.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                yield {
                    "id": hashlib.sha256(f"{line}:{datetime.now()}".encode()).hexdigest()[:16],
                    "type": "ipv4",
                    "value": line,
                    "confidence": 0.9,
                    "severity": "MEDIUM",
                    "source": "tor_exit_nodes",
                    "first_seen": datetime.now(),
                    "last_seen": datetime.now(),
                    "tags": ["tor", "exit_node", "anonymity"],
                    "context": {},
                    "tlp": "WHITE"
                }
    
    async def _parse_cisa_kev(self, content: bytes, feed) -> List:
        data = json.loads(content.decode('utf-8'))
        vulnerabilities = data.get('vulnerabilities', [])
        
        for vuln in vulnerabilities:
            yield {
                "id": vuln.get('cveID', ''),
                "type": "cve",
                "value": vuln.get('cveID', ''),
                "confidence": 1.0,
                "severity": "CRITICAL",
                "source": "cisa_kev",
                "first_seen": datetime.now(),
                "last_seen": datetime.now(),
                "tags": ["cisa", "kev", "exploited", "vulnerability"],
                "context": {
                    "vendor": vuln.get('vendorProject'),
                    "product": vuln.get('product'),
                    "vulnerability_name": vuln.get('vulnerabilityName'),
                    "date_added": vuln.get('dateAdded'),
                    "short_description": vuln.get('shortDescription'),
                    "required_action": vuln.get('requiredAction'),
                    "due_date": vuln.get('dueDate')
                },
                "tlp": "WHITE"
            }
    
    async def _parse_nvd_cve(self, content: bytes, feed) -> List:
        decompressed = gzip.decompress(content)
        data = json.loads(decompressed.decode('utf-8'))
        vulnerabilities = data.get('CVE_Items', [])
        
        for vuln in vulnerabilities:
            cve = vuln.get('cve', {})
            cve_id = cve.get('CVE_data_meta', {}).get('ID', '')
            description = cve.get('description', {}).get('description_data', [{}])[0].get('value', '')
            
            # Get CVSS scores
            cvss_v3 = {}
            cvss_v2 = {}
            impact = vuln.get('impact', {})
            if 'baseMetricV3' in impact:
                cvss_v3 = impact['baseMetricV3'].get('cvssV3', {})
            if 'baseMetricV2' in impact:
                cvss_v2 = impact['baseMetricV2'].get('cvssV2', {})
            
            yield {
                "id": vuln.get('cve', {}).get('CVE_data_meta', {}).get('ID', ''),
                "type": "cve",
                "value": vuln.get('cve', {}).get('CVE_data_meta', {}).get('ID', ''),
                "confidence": 1.0,
                "severity": cvss_v3.get('baseSeverity', cvss_v2.get('baseSeverity', 'UNKNOWN')).upper(),
                "source": "nvd",
                "first_seen": datetime.now(),
                "last_seen": datetime.now(),
                "tags": ["nvd", "cve", "vulnerability"],
                "context": {
                    "description": description,
                    "cvss_v3": cvss_v3,
                    "cvss_v2": cvss_v2,
                    "references": [r.get('url') for r in cve.get('references', {}).get('reference_data', [])],
                    "cwe": [w.get('description', [{}])[0].get('value', '') for w in cve.get('problemtype', {}).get('problemtype_data', [{}])[0].get('description', [])]
                },
                "tlp": "WHITE"
            }
    
    async def _parse_github_advisories(self, content: bytes, feed) -> List:
        data = json.loads(content.decode('utf-8'))
        
        for advisory in data:
            yield {
                "id": advisory.get('ghsa_id', ''),
                "type": "advisory",
                "value": advisory.get('ghsa_id', ''),
                "confidence": 1.0,
                "severity": advisory.get('severity', '').upper(),
                "source": "github_advisory",
                "first_seen": datetime.now(),
                "last_seen": datetime.now(),
                "tags": ["github", "advisory", "vulnerability"],
                "context": {
                    "summary": advisory.get('summary'),
                    "description": advisory.get('description'),
                    "severity": advisory.get('severity'),
                    "package": advisory.get('package', {}).get('name'),
                    "ecosystem": advisory.get('package', {}).get('ecosystem'),
                    "severity": advisory.get('severity'),
                    "cvss": advisory.get('cvss'),
                    "references": [r.get('url') for r in advisory.get('references', [])],
                    "published_at": advisory.get('published_at'),
                    "updated_at": advisory.get('updated_at')
                },
                "tlp": "WHITE"
            }


    async def _parse_urlhaus_api(self, content: bytes, feed) -> List:
        """Parse URLhaus API v1 response format"""
        data = json.loads(content.decode('utf-8'))
        urls = data.get('urls', [])
        items = []
        
        for url_data in urls:
            item = ThreatIntelItem(
                id=hashlib.sha256(f"{url_data.get('url', '')}:{datetime.now()}".encode()).hexdigest()[:16],
                type="url",
                value=url_data.get('url', ''),
                confidence=0.9,
                severity="HIGH",
                source="urlhaus_api",
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                tags=["urlhaus", "malware", "url"],
                context={
                    "urlhaus_id": url_data.get('id'),
                    "url_status": url_data.get('url_status'),
                    "host": url_data.get('host'),
                    "date_added": url_data.get('date_added'),
                    "threat": url_data.get('threat'),
                    "tags": url_data.get('tags', []),
                    "urlhaus_reference": url_data.get('urlhaus_reference')
                },
                tlp="WHITE"
            )
            items.append(item)
        
        return items
    
    async def _parse_nvd_cve_api(self, content: bytes, feed) -> List:
        """Parse NVD API 2.0 response format"""
        data = json.loads(content.decode('utf-8'))
        vulnerabilities = data.get('vulnerabilities', [])
        items = []
        
        for vuln in vulnerabilities:
            cve = vuln.get('cve', {})
            cve_id = cve.get('id', '')
            description = cve.get('descriptions', [{}])[0].get('value', '')
            
            # Get CVSS scores
            cvss_v3 = {}
            cvss_v2 = {}
            metrics = cve.get('metrics', {})
            if 'cvssMetricV31' in metrics:
                cvss_v3 = metrics['cvssMetricV31'][0].get('cvssData', {})
            elif 'cvssMetricV30' in metrics:
                cvss_v3 = metrics['cvssMetricV30'][0].get('cvssData', {})
            if 'cvssMetricV2' in metrics:
                cvss_v2 = metrics['cvssMetricV2'][0].get('cvssData', {})
            
            # Get CWE
            cwe_list = []
            weaknesses = cve.get('weaknesses', [])
            for w in weaknesses:
                for desc in w.get('description', []):
                    cwe_list.append(desc.get('value', ''))
            
            items.append(ThreatIntelItem(
                id=vuln.get('cve', {}).get('id', ''),
                type="cve",
                value=vuln.get('cve', {}).get('id', ''),
                confidence=1.0,
                severity=cvss_v3.get('baseSeverity', cvss_v2.get('baseSeverity', 'UNKNOWN')).upper(),
                source="nvd",
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                tags=["nvd", "cve", "vulnerability"],
                context={
                    "description": description,
                    "cvss_v3": cvss_v3,
                    "cvss_v2": cvss_v2,
                    "references": [r.get('url', '') for r in cve.get('references', [])],
                    "cwe": cwe_list
                },
                tlp="WHITE"
            ))
        
        return items


class AutoUpdater:
    """
    Automatic updater for threat intelligence platform
    """
    
    def __init__(self, platform):
        self.platform = platform
        self.running = False
        self.update_tasks: Dict[str, asyncio.Task] = {}
    
    async def start(self):
        """Start auto-updater"""
        self.running = True
        
        # Update feeds
        asyncio.create_task(self._update_feeds_loop())
        
        # Update CVE database
        asyncio.create_task(self._update_cve_database())
        
        # Update threat intel feeds
        asyncio.create_task(self._update_threat_intel_feeds())
        
        # Update plugins
        asyncio.create_task(self._update_plugins_loop())
        
        # Update GeoIP database
        asyncio.create_task(self._update_geoip_database())
        
        logger.info("Auto-updater started")
    
    async def _update_feeds_loop(self):
        """Update feed sources periodically"""
        while True:
            try:
                await self._update_feed_sources()
                await asyncio.sleep(3600)  # Every hour
            except Exception as e:
                logger.error(f"Feed update loop error: {e}")
                await asyncio.sleep(300)
    
    async def _update_feed_sources(self):
        """Update feed sources from configuration"""
        # Would fetch from config management system
        pass
    
    async def _update_cve_database(self):
        """Update CVE database from NVD"""
        while True:
            try:
                await self._sync_nvd_cves()
                await asyncio.sleep(86400)  # Daily
            except Exception as e:
                logger.error(f"CVE database update error: {e}")
                await asyncio.sleep(3600)
    
    async def _sync_nvd_cves(self):
        """Sync CVE data from NVD"""
        try:
            # Download recent CVEs
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz"
                ) as resp:
                    if resp.status == 200:
                        content = await resp.read()
                        # Process and store CVEs
                        pass
        except Exception as e:
            logger.error(f"NVD sync error: {e}")
    
    async def _update_threat_intel_feeds(self):
        """Update threat intelligence feeds"""
        while True:
            try:
                # Update from various threat intel sources
                await asyncio.sleep(3600)
            except Exception as e:
                logger.error(f"Threat intel feed update error: {e}")
                await asyncio.sleep(300)
    
    async def _update_plugins_loop(self):
        """Update plugins"""
        while True:
            try:
                # Check for plugin updates
                await asyncio.sleep(86400)  # Daily
            except Exception as e:
                logger.error(f"Plugin update error: {e}")
                await asyncio.sleep(3600)
    
    async def _update_geoip_database(self):
        """Update GeoIP database"""
        while True:
            try:
                # Download latest GeoLite2 database
                await asyncio.sleep(86400 * 7)  # Weekly
            except Exception as e:
                logger.error(f"GeoIP update error: {e}")
                await asyncio.sleep(86400)
    
    def stop(self):
        self.running = False