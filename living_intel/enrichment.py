"""
Built-in Enrichment Plugins
Enrichment plugins for GeoIP, VirusTotal, ThreatFox, MISP, Abuse.ch, Hybrid Analysis, GreyNoise, Shodan, PassiveTotal, AlienVault OTX
"""
import asyncio
import logging
import json
import hashlib
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import asyncio
import aiohttp

from .platform import ThreatIntelPlugin, ThreatIntelItem

logger = logging.getLogger(__name__)


class GeoIPEnrichmentPlugin(ThreatIntelPlugin):
    """Enrich IPs with GeoIP data from MaxMind GeoLite2"""
    
    def __init__(self, platform):
        super().__init__(platform)
        self.name = "GeoIPEnrichment"
        self.version = "1.0.0"
        self.description = "Enrich IP addresses with geographic and network information"
        self.author = "Living Intel Platform"
        self.geoip_db = None
        self.asn_db = None
    
    async def initialize(self):
        try:
            import geoip2.database
            self.geoip_db = geoip2.database.Reader('/usr/share/GeoIP/GeoLite2-City.mmdb')
            self.asn_db = geoip2.database.Reader('/usr/share/GeoIP/GeoLite2-ASN.mmdb')
            logger.info("GeoIP databases loaded")
        except Exception as e:
            logger.warning(f"GeoIP database not found: {e}")
    
    async def enrich(self, item: ThreatIntelItem) -> ThreatIntelItem:
        if item.type in ["ipv4", "ipv6", "ip"] and self.geoip_db:
            try:
                response = self.geoip_db.city(item.value)
                item.context["geoip"] = {
                    "country": response.country.name,
                    "country_code": response.country.iso_code,
                    "city": response.city.name,
                    "latitude": response.location.latitude,
                    "longitude": response.location.longitude,
                    "timezone": response.location.time_zone,
                    "postal_code": response.postal.code,
                    "accuracy_radius": response.location.accuracy_radius
                }
            except Exception as e:
                logger.debug(f"GeoIP city lookup failed for {item.value}: {e}")
        
        if item.type in ["ipv4", "ipv6", "ip"] and self.asn_db:
            try:
                response = self.asn_db.asn(item.value)
                if "geoip" not in item.context:
                    item.context["geoip"] = {}
                item.context["geoip"]["asn"] = {
                    "number": response.autonomous_system_number,
                    "organization": response.autonomous_system_organization
                }
            except Exception as e:
                logger.debug(f"GeoIP ASN lookup failed for {item.value}: {e}")
        
        return item
    
    async def cleanup(self):
        if self.geoip_db:
            self.geoip_db.close()
        if self.asn_db:
            self.asn_db.close()


class VirusTotalEnrichmentPlugin(ThreatIntelPlugin):
    """Enrich with VirusTotal v3 API data"""
    
    def __init__(self, platform):
        super().__init__(platform)
        self.name = "VirusTotalEnrichment"
        self.version = "1.0.0"
        self.description = "Enrich IOCs with VirusTotal v3 API data"
        self.author = "Living Intel Platform"
        self.api_key = None
        self.session = None
        self.rate_limit = 4  # requests per second
        self.last_request = 0
    
    async def initialize(self):
        self.api_key = self.platform.config.get("virustotal_api_key")
        if self.api_key:
            self.session = aiohttp.ClientSession(
                headers={"x-apikey": self.api_key},
                timeout=aiohttp.ClientTimeout(total=30)
            )
            logger.info("VirusTotal enrichment initialized")
        else:
            logger.warning("VirusTotal API key not configured")
    
    async def _rate_limit_wait(self):
        import time
        now = time.time()
        elapsed = now - self.last_request
        if elapsed < 1.0 / self.rate_limit:
            await asyncio.sleep(1.0 / self.rate_limit - elapsed)
        self.last_request = time.time()
    
    async def enrich(self, item: ThreatIntelItem) -> ThreatIntelItem:
        if not self.api_key or not self.session:
            return item
        
        endpoint_map = {
            "ipv4": "ip_addresses",
            "ipv6": "ip_addresses",
            "ip": "ip_addresses",
            "domain": "domains",
            "url": "urls",
            "hash": "files",
            "md5": "files",
            "sha1": "files",
            "sha256": "files",
            "sha512": "files"
        }
        
        endpoint = endpoint_map.get(item.type)
        if not endpoint:
            return item
        
        await self._rate_limit_wait()
        
        try:
            if endpoint == "urls":
                # URL needs special encoding
                import base64
                url_id = base64.urlsafe_b64encode(item.value.encode()).decode().strip("=")
                url = f"https://www.virustotal.com/api/v3/{endpoint}/{url_id}"
            else:
                url = f"https://www.virustotal.com/api/v3/{endpoint}/{item.value}"
            
            async with self.session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    item.context["virustotal"] = self._parse_vt_response(data, item.type)
                elif resp.status == 404:
                    item.context["virustotal"] = {"not_found": True}
                elif resp.status == 429:
                    logger.warning("VirusTotal rate limit exceeded")
        
        except Exception as e:
            logger.error(f"VirusTotal enrichment error for {item.value}: {e}")
        
        return item
    
    def _parse_vt_response(self, data: Dict, ioc_type: str) -> Dict:
        """Parse VirusTotal response into structured format"""
        attrs = data.get("data", {}).get("attributes", {})
        
        result = {
            "last_analysis_stats": attrs.get("last_analysis_stats", {}),
            "reputation": attrs.get("reputation", 0),
            "categories": attrs.get("categories", []),
            "tags": attrs.get("tags", [])
        }
        
        if ioc_type in ["ipv4", "ipv6", "ip"]:
            result.update({
                "asn": attrs.get("asn"),
                "as_owner": attrs.get("as_owner"),
                "country": attrs.get("country"),
                "network": attrs.get("network"),
                "last_analysis_results": attrs.get("last_analysis_results", {})
            })
        elif ioc_type == "domain":
            result.update({
                "registrar": attrs.get("registrar"),
                "creation_date": attrs.get("creation_date"),
                "last_dns_records": attrs.get("last_dns_records", []),
                "subdomains": attrs.get("subdomains", []),
                "last_analysis_results": attrs.get("last_analysis_results", {})
            })
        elif ioc_type == "url":
            result.update({
                "url": attrs.get("url"),
                "title": attrs.get("title"),
                "last_http_response_code": attrs.get("last_http_response_code"),
                "last_http_response_content_length": attrs.get("last_http_response_content_length"),
                "last_analysis_results": attrs.get("last_analysis_results", {})
            })
        elif ioc_type in ["hash", "md5", "sha1", "sha256", "sha512"]:
            result.update({
                "type_description": attrs.get("type_description"),
                "size": attrs.get("size"),
                "magic": attrs.get("magic"),
                "meaningful_name": attrs.get("meaningful_name"),
                "trid": attrs.get("trid", []),
                "signature_info": attrs.get("signature_info", {}),
                "last_analysis_results": attrs.get("last_analysis_results", {})
            })
        
        return result
    
    async def cleanup(self):
        if self.session:
            await self.session.close()


class ThreatFoxEnrichmentPlugin(ThreatIntelPlugin):
    """Enrich with ThreatFox malware IOC data from abuse.ch"""
    
    def __init__(self, platform):
        super().__init__(platform)
        self.name = "ThreatFoxEnrichment"
        self.version = "1.0.0"
        self.description = "Enrich IOCs with ThreatFox malware intelligence"
        self.author = "Living Intel Platform"
        self.session = None
    
    async def initialize(self):
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30))
        logger.info("ThreatFox enrichment initialized")
    
    async def enrich(self, item: ThreatIntelItem) -> ThreatIntelItem:
        if not self.session:
            return item
        
        if item.type in ["ipv4", "ipv6", "ip", "domain", "hash", "md5", "sha1", "sha256", "sha512", "url"]:
            try:
                async with self.session.post(
                    "https://threatfox-api.abuse.ch/api/v1/",
                    json={"query": "search_ioc", "search_term": item.value}
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("data"):
                            item.context["threatfox"] = data["data"]
            except Exception as e:
                logger.error(f"ThreatFox enrichment error for {item.value}: {e}")
        
        return item
    
    async def hunt(self, query: Dict) -> List[ThreatIntelItem]:
        """Search ThreatFox for malware campaigns"""
        results = []
        if not self.session:
            return results
        
        try:
            if query.get("malware"):
                async with self.session.post(
                    "https://threatfox-api.abuse.ch/api/v1/",
                    json={"query": "malinfo", "malware": query["malware"], "limit": 100}
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for entry in data.get("data", []):
                            for ioc in entry.get("iocs", []):
                                results.append(ThreatIntelItem(
                                    id=hashlib.sha256(f"{ioc['ioc_value']}:threatfox".encode()).hexdigest()[:16],
                                    type=self._map_ioc_type(ioc["ioc_type"]),
                                    value=ioc["ioc_value"],
                                    confidence=0.9,
                                    severity="HIGH",
                                    source="threatfox",
                                    first_seen=datetime.fromisoformat(ioc["first_seen"].replace("Z", "+00:00")),
                                    last_seen=datetime.fromisoformat(ioc["last_seen"].replace("Z", "+00:00")),
                                    tags=["threatfox", "malware", entry.get("malware", "")],
                                    context={
                                        "malware": entry.get("malware"),
                                        "malware_printable": entry.get("malware_printable"),
                                        "threat_type": entry.get("threat_type"),
                                        "confidence_level": entry.get("confidence_level"),
                                        "reference": entry.get("reference")
                                    },
                                    tlp="WHITE"
                                ))
        except Exception as e:
            logger.error(f"ThreatFox hunt error: {e}")
        
        return results
    
    def _map_ioc_type(self, tf_type: str) -> str:
        mapping = {
            "ip:port": "ipv4",
            "domain": "domain",
            "url": "url",
            "sha256": "sha256",
            "md5": "md5",
            "sha1": "sha1",
            "email": "email"
        }
        return mapping.get(tf_type, "unknown")
    
    async def cleanup(self):
        if self.session:
            await self.session.close()


class MISPEnrichmentPlugin(ThreatIntelPlugin):
    """Enrich from MISP instance"""
    
    def __init__(self, platform):
        super().__init__(platform)
        self.name = "MISPEnrichment"
        self.version = "1.0.0"
        self.description = "Enrich IOCs from MISP threat intelligence platform"
        self.author = "Living Intel Platform"
        self.misp_url = None
        self.misp_key = None
        self.session = None
    
    async def initialize(self):
        self.misp_url = self.platform.config.get("misp_url")
        self.misp_key = self.platform.config.get("misp_key")
        if self.misp_url and self.misp_key:
            self.session = aiohttp.ClientSession(
                headers={
                    "Authorization": self.misp_key,
                    "Accept": "application/json",
                    "Content-Type": "application/json"
                },
                timeout=aiohttp.ClientTimeout(total=30)
            )
            logger.info("MISP enrichment initialized")
        else:
            logger.warning("MISP URL or key not configured")
    
    async def enrich(self, item: ThreatIntelItem) -> ThreatIntelItem:
        if not self.misp_url or not self.misp_key or not self.session:
            return item
        
        try:
            # Search for attributes matching the IOC
            search_data = {
                "value": item.value,
                "type": self._map_type_to_misp(item.type),
                "includeContext": True,
                "includeCorrelations": True,
                "limit": 50
            }
            
            async with self.session.post(
                f"{self.misp_url}/attributes/restSearch",
                json=search_data
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("response", {}).get("Attribute"):
                        item.context["misp"] = data["response"]["Attribute"]
        
        except Exception as e:
            logger.error(f"MISP enrichment error for {item.value}: {e}")
        
        return item
    
    def _map_type_to_misp(self, ioc_type: str) -> str:
        mapping = {
            "ipv4": "ip-src",
            "ipv6": "ip-src",
            "ip": "ip-src",
            "domain": "domain",
            "url": "url",
            "hash": "sha256",
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
            "sha512": "sha512",
            "email": "email-src",
            "cidr": "ip-src"
        }
        return mapping.get(ioc_type, "text")
    
    async def hunt(self, query: Dict) -> List[ThreatIntelItem]:
        """Search MISP for events"""
        results = []
        if not self.misp_url or not self.misp_key or not self.session:
            return results
        
        try:
            search_data = {
                "tags": query.get("tags", []),
                "timestamp": query.get("since", "7d"),
                "limit": 100,
                "includeAttributes": True
            }
            
            async with self.session.post(
                f"{self.misp_url}/events/restSearch",
                json=search_data
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for event in data.get("response", []):
                        for attr in event.get("Event", {}).get("Attribute", []):
                            results.append(ThreatIntelItem(
                                id=attr.get("uuid", hashlib.sha256(f"{attr['value']}:misp".encode()).hexdigest()[:16]),
                                type=self._map_misp_type(attr.get("type")),
                                value=attr.get("value"),
                                confidence=0.8,
                                severity="MEDIUM",
                                source="misp",
                                first_seen=datetime.fromisoformat(attr.get("timestamp", "").replace("Z", "+00:00")),
                                last_seen=datetime.fromisoformat(event.get("Event", {}).get("date", "").replace("Z", "+00:00")),
                                tags=["misp"] + event.get("Event", {}).get("Tag", []),
                                context={
                                    "event_id": event.get("Event", {}).get("id"),
                                    "event_info": event.get("Event", {}).get("info"),
                                    "category": attr.get("category"),
                                    "comment": attr.get("comment")
                                },
                                tlp="WHITE"
                            ))
        except Exception as e:
            logger.error(f"MISP hunt error: {e}")
        
        return results
    
    def _map_misp_type(self, misp_type: str) -> str:
        mapping = {
            "ip-src": "ipv4",
            "ip-dst": "ipv4",
            "domain": "domain",
            "hostname": "domain",
            "url": "url",
            "sha256": "sha256",
            "md5": "md5",
            "sha1": "sha1",
            "sha512": "sha512",
            "email-src": "email",
            "email-dst": "email"
        }
        return mapping.get(misp_type, "unknown")
    
    async def cleanup(self):
        if self.session:
            await self.session.close()


class AbuseCHEnrichmentPlugin(ThreatIntelPlugin):
    """Enrich with abuse.ch threat intelligence (Feodo, SSLBL, URLhaus, ThreatFox)"""
    
    def __init__(self, platform):
        super().__init__(platform)
        self.name = "AbuseCHEnrichment"
        self.version = "1.0.0"
        self.description = "Enrich IOCs with abuse.ch threat intelligence feeds"
        self.author = "Living Intel Platform"
        self.session = None
    
    async def initialize(self):
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30))
        logger.info("Abuse.ch enrichment initialized")
    
    async def enrich(self, item: ThreatIntelItem) -> ThreatIntelItem:
        if not self.session:
            return item
        
        if item.type in ["ipv4", "ipv6", "ip"]:
            # Check Feodo Tracker
            await self._check_feodo(item)
            # Check SSLBL
            await self._check_sslbl(item)
        
        if item.type in ["domain", "url"]:
            # Check URLhaus
            await self._check_urlhaus(item)
        
        return item
    
    async def _check_feodo(self, item: ThreatIntelItem):
        try:
            async with self.session.get(
                f"https://feodotracker.abuse.ch/api/v1/ip/{item.value}/"
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("data"):
                        item.context["abuse_ch_feodo"] = data["data"]
        except Exception as e:
            logger.debug(f"Feodo check failed for {item.value}: {e}")
    
    async def _check_sslbl(self, item: ThreatIntelItem):
        try:
            async with self.session.get(
                f"https://sslbl.abuse.ch/api/v1/ip/{item.value}/"
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("data"):
                        item.context["abuse_ch_sslbl"] = data["data"]
        except Exception as e:
            logger.debug(f"SSLBL check failed for {item.value}: {e}")
    
    async def _check_urlhaus(self, item: ThreatIntelItem):
        try:
            search_value = item.value
            if item.type == "url":
                import base64
                search_value = base64.urlsafe_b64encode(item.value.encode()).decode().strip("=")
            
            async with self.session.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": search_value}
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("query_status") == "ok":
                        item.context["abuse_ch_urlhaus"] = data
        except Exception as e:
            logger.debug(f"URLhaus check failed for {item.value}: {e}")
    
    async def cleanup(self):
        if self.session:
            await self.session.close()


class HybridAnalysisEnrichmentPlugin(ThreatIntelPlugin):
    """Enrich with Hybrid Analysis (Falcon Sandbox) data"""
    
    def __init__(self, platform):
        super().__init__(platform)
        self.name = "HybridAnalysisEnrichment"
        self.version = "1.0.0"
        self.description = "Enrich file hashes with Hybrid Analysis sandbox results"
        self.author = "Living Intel Platform"
        self.api_key = None
        self.session = None
    
    async def initialize(self):
        self.api_key = self.platform.config.get("hybrid_analysis_api_key")
        if self.api_key:
            self.session = aiohttp.ClientSession(
                headers={
                    "api-key": self.api_key,
                    "User-Agent": "Falcon Sandbox",
                    "Accept": "application/json"
                },
                timeout=aiohttp.ClientTimeout(total=30)
            )
            logger.info("Hybrid Analysis enrichment initialized")
        else:
            logger.warning("Hybrid Analysis API key not configured")
    
    async def enrich(self, item: ThreatIntelItem) -> ThreatIntelItem:
        if not self.api_key or not self.session:
            return item
        
        if item.type in ["hash", "md5", "sha1", "sha256", "sha512"]:
            try:
                async with self.session.get(
                    f"https://www.hybrid-analysis.com/api/v2/search/hash/{item.value}"
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("result"):
                            item.context["hybrid_analysis"] = data["result"]
            except Exception as e:
                logger.error(f"Hybrid Analysis enrichment error for {item.value}: {e}")
        
        return item
    
    async def cleanup(self):
        if self.session:
            await self.session.close()


class GreyNoiseEnrichmentPlugin(ThreatIntelPlugin):
    """Enrich with GreyNoise Internet background noise data"""
    
    def __init__(self, platform):
        super().__init__(platform)
        self.name = "GreyNoiseEnrichment"
        self.version = "1.0.0"
        self.description = "Enrich IPs with GreyNoise internet scanner intelligence"
        self.author = "Living Intel Platform"
        self.api_key = None
        self.session = None
    
    async def initialize(self):
        self.api_key = self.platform.config.get("greynoise_api_key")
        if self.api_key:
            self.session = aiohttp.ClientSession(
                headers={
                    "key": self.api_key,
                    "Accept": "application/json"
                },
                timeout=aiohttp.ClientTimeout(total=30)
            )
            logger.info("GreyNoise enrichment initialized")
        else:
            logger.warning("GreyNoise API key not configured")
    
    async def enrich(self, item: ThreatIntelItem) -> ThreatIntelItem:
        if not self.api_key or not self.session:
            return item
        
        if item.type in ["ipv4", "ipv6", "ip"]:
            try:
                async with self.session.get(
                    f"https://api.greynoise.io/v3/community/{item.value}"
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        item.context["greynoise"] = data
                    elif resp.status == 404:
                        item.context["greynoise"] = {"seen": False}
            except Exception as e:
                logger.error(f"GreyNoise enrichment error for {item.value}: {e}")
        
        return item
    
    async def cleanup(self):
        if self.session:
            await self.session.close()


class ShodanEnrichmentPlugin(ThreatIntelPlugin):
    """Enrich with Shodan internet scanning data"""
    
    def __init__(self, platform):
        super().__init__(platform)
        self.name = "ShodanEnrichment"
        self.version = "1.0.0"
        self.description = "Enrich IPs with Shodan internet scanning intelligence"
        self.author = "Living Intel Platform"
        self.api_key = None
        self.session = None
    
    async def initialize(self):
        self.api_key = self.platform.config.get("shodan_api_key")
        if self.api_key:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            )
            logger.info("Shodan enrichment initialized")
        else:
            logger.warning("Shodan API key not configured")
    
    async def enrich(self, item: ThreatIntelItem) -> ThreatIntelItem:
        if not self.api_key or not self.session:
            return item
        
        if item.type in ["ipv4", "ipv6", "ip"]:
            try:
                async with self.session.get(
                    f"https://api.shodan.io/shodan/host/{item.value}",
                    params={"key": self.api_key}
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        item.context["shodan"] = self._parse_shodan(data)
                    elif resp.status == 404:
                        item.context["shodan"] = {"not_found": True}
            except Exception as e:
                logger.error(f"Shodan enrichment error for {item.value}: {e}")
        
        return item
    
    def _parse_shodan(self, data: Dict) -> Dict:
        return {
            "ip": data.get("ip_str"),
            "org": data.get("org"),
            "isp": data.get("isp"),
            "asn": data.get("asn"),
            "country": data.get("country_name"),
            "city": data.get("city"),
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "domains": data.get("domains", []),
            "vulns": list(data.get("vulns", {}).keys()) if data.get("vulns") else [],
            "tags": data.get("tags", []),
            "last_update": data.get("last_update")
        }
    
    async def cleanup(self):
        if self.session:
            await self.session.close()


class PassiveTotalEnrichmentPlugin(ThreatIntelPlugin):
    """Enrich with RiskIQ PassiveTotal DNS and passive DNS data"""
    
    def __init__(self, platform):
        super().__init__(platform)
        self.name = "PassiveTotalEnrichment"
        self.version = "1.0.0"
        self.description = "Enrich domains and IPs with PassiveTotal passive DNS"
        self.author = "Living Intel Platform"
        self.username = None
        self.api_key = None
        self.session = None
    
    async def initialize(self):
        self.username = self.platform.config.get("passivetotal_username")
        self.api_key = self.platform.config.get("passivetotal_api_key")
        if self.username and self.api_key:
            import base64
            auth = base64.b64encode(f"{self.username}:{self.api_key}".encode()).decode()
            self.session = aiohttp.ClientSession(
                headers={
                    "Authorization": f"Basic {auth}",
                    "Accept": "application/json"
                },
                timeout=aiohttp.ClientTimeout(total=30)
            )
            logger.info("PassiveTotal enrichment initialized")
        else:
            logger.warning("PassiveTotal credentials not configured")
    
    async def enrich(self, item: ThreatIntelItem) -> ThreatIntelItem:
        if not self.username or not self.api_key or not self.session:
            return item
        
        if item.type in ["domain", "ipv4", "ipv6", "ip"]:
            try:
                if item.type == "domain":
                    await self._enrich_domain(item)
                else:
                    await self._enrich_ip(item)
            except Exception as e:
                logger.error(f"PassiveTotal enrichment error for {item.value}: {e}")
        
        return item
    
    async def _enrich_domain(self, item: ThreatIntelItem):
        async with self.session.get(
            f"https://api.passivetotal.org/v2/dns/passive",
            params={"query": item.value}
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                item.context["passivetotal"] = data
    
    async def _enrich_ip(self, item: ThreatIntelItem):
        async with self.session.get(
            f"https://api.passivetotal.org/v2/dns/passive",
            params={"query": item.value}
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                item.context["passivetotal"] = data
    
    async def cleanup(self):
        if self.session:
            await self.session.close()


class AlienVaultOTXEnrichmentPlugin(ThreatIntelPlugin):
    """Enrich with AlienVault OTX pulse data"""
    
    def __init__(self, platform):
        super().__init__(platform)
        self.name = "AlienVaultOTXEnrichment"
        self.version = "1.0.0"
        self.description = "Enrich IOCs with AlienVault OTX pulse intelligence"
        self.author = "Living Intel Platform"
        self.api_key = None
        self.session = None
    
    async def initialize(self):
        self.api_key = self.platform.config.get("otx_api_key")
        if self.api_key:
            self.session = aiohttp.ClientSession(
                headers={
                    "X-OTX-API-KEY": self.api_key,
                    "Accept": "application/json"
                },
                timeout=aiohttp.ClientTimeout(total=30)
            )
            logger.info("AlienVault OTX enrichment initialized")
        else:
            logger.warning("AlienVault OTX API key not configured")
    
    async def enrich(self, item: ThreatIntelItem) -> ThreatIntelItem:
        if not self.api_key or not self.session:
            return item
        
        if item.type in ["ipv4", "ipv6", "ip", "domain", "url", "hash", "md5", "sha1", "sha256", "sha512"]:
            try:
                endpoint_map = {
                    "ipv4": "IPv4",
                    "ipv6": "IPv6",
                    "ip": "IPv4",
                    "domain": "domain",
                    "url": "url",
                    "hash": "file",
                    "md5": "file",
                    "sha1": "file",
                    "sha256": "file",
                    "sha512": "file"
                }
                
                endpoint = endpoint_map.get(item.type)
                if not endpoint:
                    return item
                
                async with self.session.get(
                    f"https://otx.alienvault.com/api/v1/indicators/{endpoint}/{item.value}/general"
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        item.context["alienvault_otx"] = data
            except Exception as e:
                logger.error(f"AlienVault OTX enrichment error for {item.value}: {e}")
        
        return item
    
    async def hunt(self, query: Dict) -> List[ThreatIntelItem]:
        """Search OTX for pulses"""
        results = []
        if not self.api_key or not self.session:
            return results
        
        try:
            if query.get("pulse"):
                async with self.session.get(
                    f"https://otx.alienvault.com/api/v1/pulses/{query['pulse']}"
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for indicator in data.get("indicators", []):
                            results.append(ThreatIntelItem(
                                id=indicator.get("id", hashlib.sha256(f"{indicator['indicator']}:otx".encode()).hexdigest()[:16]),
                                type=self._map_otx_type(indicator.get("type")),
                                value=indicator.get("indicator"),
                                confidence=0.8,
                                severity="MEDIUM",
                                source="alienvault_otx",
                                first_seen=datetime.fromisoformat(indicator.get("created", "").replace("Z", "+00:00")),
                                last_seen=datetime.fromisoformat(data.get("modified", "").replace("Z", "+00:00")),
                                tags=["alienvault_otx", "pulse"] + data.get("tags", []),
                                context={
                                    "pulse_id": data.get("id"),
                                    "pulse_name": data.get("name"),
                                    "pulse_description": data.get("description"),
                                    "pulse_tags": data.get("tags", []),
                                    "pulse_author": data.get("author_name"),
                                    "indicator_type": indicator.get("type"),
                                    "indicator_title": indicator.get("title"),
                                    "indicator_description": indicator.get("description")
                                },
                                tlp="WHITE"
                            ))
        except Exception as e:
            logger.error(f"OTX hunt error: {e}")
        
        return results
    
    def _map_otx_type(self, otx_type: str) -> str:
        mapping = {
            "IPv4": "ipv4",
            "IPv6": "ipv6",
            "domain": "domain",
            "hostname": "domain",
            "URL": "url",
            "FileHash-MD5": "md5",
            "FileHash-SHA1": "sha1",
            "FileHash-SHA256": "sha256",
            "FileHash-SHA512": "sha512",
            "email": "email",
            "CIDR": "cidr",
            "Mutex": "mutex",
            "FilePath": "file_path"
        }
        return mapping.get(otx_type, "unknown")
    
    async def cleanup(self):
        if self.session:
            await self.session.close()


class CIRCLEnrichmentPlugin(ThreatIntelPlugin):
    """Enrich with CIRCL (Computer Incident Response Center Luxembourg) services"""
    
    def __init__(self, platform):
        super().__init__(platform)
        self.name = "CIRCLEnrichment"
        self.version = "1.0.0"
        self.description = "Enrich with CIRCL passive DNS, SSL, and CVE services"
        self.author = "Living Intel Platform"
        self.session = None
    
    async def initialize(self):
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30))
        logger.info("CIRCL enrichment initialized")
    
    async def enrich(self, item: ThreatIntelItem) -> ThreatIntelItem:
        if not self.session:
            return item
        
        if item.type in ["domain", "ipv4", "ipv6", "ip"]:
            # Passive DNS
            await self._check_passive_dns(item)
        
        if item.type in ["hash", "md5", "sha1", "sha256", "sha512"]:
            # Malware information
            await self._check_malware(item)
        
        if item.type == "cve":
            # CVE information
            await self._check_cve(item)
        
        return item
    
    async def _check_passive_dns(self, item: ThreatIntelItem):
        try:
            async with self.session.get(
                f"https://www.circl.lu/pdns/query/{item.value}"
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("results"):
                        item.context["circl_passive_dns"] = data["results"]
        except Exception as e:
            logger.debug(f"CIRCL passive DNS check failed for {item.value}: {e}")
    
    async def _check_malware(self, item: ThreatIntelItem):
        try:
            async with self.session.get(
                f"https://www.circl.lu/api/malware/{item.value}"
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    item.context["circl_malware"] = data
        except Exception as e:
            logger.debug(f"CIRCL malware check failed for {item.value}: {e}")
    
    async def _check_cve(self, item: ThreatIntelItem):
        try:
            async with self.session.get(
                f"https://cve.circl.lu/api/cve/{item.value}"
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    item.context["circl_cve"] = data
        except Exception as e:
            logger.debug(f"CIRCL CVE check failed for {item.value}: {e}")
    
    async def cleanup(self):
        if self.session:
            await self.session.close()


class CiscoTalosEnrichmentPlugin(ThreatIntelPlugin):
    """Enrich with Cisco Talos Intelligence"""
    
    def __init__(self, platform):
        super().__init__(platform)
        self.name = "CiscoTalosEnrichment"
        self.version = "1.0.0"
        self.description = "Enrich IPs and domains with Cisco Talos reputation"
        self.author = "Living Intel Platform"
        self.session = None
    
    async def initialize(self):
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30))
        logger.info("Cisco Talos enrichment initialized")
    
    async def enrich(self, item: ThreatIntelItem) -> ThreatIntelItem:
        if not self.session:
            return item
        
        if item.type in ["ipv4", "ipv6", "ip"]:
            await self._check_ip_reputation(item)
        elif item.type == "domain":
            await self._check_domain_reputation(item)
        
        return item
    
    async def _check_ip_reputation(self, item: ThreatIntelItem):
        try:
            async with self.session.get(
                f"https://talosintelligence.com/reputation_center/lookup",
                params={"search": item.value}
            ) as resp:
                if resp.status == 200:
                    # Parse HTML response
                    text = await resp.text()
                    # Would need HTML parsing
                    item.context["talos_reputation"] = {"raw": text[:5000]}
        except Exception as e:
            logger.debug(f"Talos IP reputation check failed for {item.value}: {e}")
    
    async def _check_domain_reputation(self, item: ThreatIntelItem):
        try:
            async with self.session.get(
                f"https://talosintelligence.com/reputation_center/lookup",
                params={"search": item.value}
            ) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    item.context["talos_reputation"] = {"raw": text[:5000]}
        except Exception as e:
            logger.debug(f"Talos domain reputation check failed for {item.value}: {e}")
    
    async def cleanup(self):
        if self.session:
            await self.session.close()


# Enrichment plugin registry
ENRICHMENT_PLUGINS = {
    "geoip": GeoIPEnrichmentPlugin,
    "virustotal": VirusTotalEnrichmentPlugin,
    "threatfox": ThreatFoxEnrichmentPlugin,
    "misp": MISPEnrichmentPlugin,
    "abuse_ch": AbuseCHEnrichmentPlugin,
    "hybrid_analysis": HybridAnalysisEnrichmentPlugin,
    "greynoise": GreyNoiseEnrichmentPlugin,
    "shodan": ShodanEnrichmentPlugin,
    "passivetotal": PassiveTotalEnrichmentPlugin,
    "alienvault_otx": AlienVaultOTXEnrichmentPlugin,
    "circl": CIRCLEnrichmentPlugin,
    "cisco_talos": CiscoTalosEnrichmentPlugin
}


def get_enrichment_plugin(name: str) -> type:
    """Get enrichment plugin class by name"""
    return ENRICHMENT_PLUGINS.get(name)


def list_enrichment_plugins() -> List[str]:
    """List all available enrichment plugins"""
    return list(ENRICHMENT_PLUGINS.keys())