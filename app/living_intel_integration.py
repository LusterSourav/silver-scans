"""
Living Intelligence Integration
Connects the main scanner with the Living Threat Intelligence Platform
"""
import asyncio
import logging
import os
from typing import Dict, List, Optional, Any
from datetime import datetime
import aiohttp

logger = logging.getLogger(__name__)


class LivingIntelClient:
    """Client for interacting with Living Intel Platform API"""
    
    def __init__(self, base_url: str = None, api_key: str = None, timeout: int = 60):
        self.base_url = base_url or os.getenv("LIVING_INTEL_URL", "http://localhost:8080")
        self.api_key = api_key
        self.timeout = timeout
        self.session = None
        self._connected = False
    
    async def connect(self):
        """Initialize HTTP session"""
        if not self.session:
            headers = {}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            self.session = aiohttp.ClientSession(
                base_url=self.base_url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            )
            self._connected = True
    
    async def close(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()
            self.session = None
            self._connected = False
    
    async def _request(self, method: str, path: str, **kwargs) -> Optional[Dict]:
        """Make HTTP request"""
        if not self._connected:
            await self.connect()
        
        try:
            async with self.session.request(method, path, **kwargs) as resp:
                if resp.status == 200:
                    return await resp.json()
                else:
                    logger.error(f"Living Intel API error: {resp.status} - {await resp.text()}")
                    return None
        except Exception as e:
            logger.error(f"Living Intel request failed: {e}")
            return None
    
    # Health & Status
    async def health_check(self) -> Optional[Dict]:
        return await self._request("GET", "/api/v1/health")
    
    async def get_metrics(self) -> Optional[Dict]:
        return await self._request("GET", "/api/v1/metrics")
    
    # Threat Intelligence Queries
    async def search_ioc(self, ioc_type: str, value: str) -> Optional[Dict]:
        return await self._request("GET", f"/api/v1/threat-intel/search/{ioc_type}/{value}")
    
    async def query_threat_intel(self, query: Dict) -> Optional[Dict]:
        return await self._request("POST", "/api/v1/threat-intel/query", json=query)
    
    async def get_stats(self) -> Optional[Dict]:
        return await self._request("GET", "/api/v1/threat-intel/stats")
    
    # Enrichment
    async def enrich_ioc(self, ioc_type: str, value: str) -> Optional[Dict]:
        return await self._request("POST", "/api/v1/enrich", json={"type": ioc_type, "value": value})
    
    async def bulk_enrich(self, iocs: List[Dict]) -> Optional[Dict]:
        return await self._request("POST", "/api/v1/enrich/bulk", json={"iocs": iocs})
    
    # Feed Management
    async def list_feeds(self) -> Optional[Dict]:
        return await self._request("GET", "/api/v1/feeds")
    
    async def refresh_feed(self, name: str) -> Optional[Dict]:
        return await self._request("POST", f"/api/v1/feeds/{name}/refresh")
    
    # Live Feeds
    async def list_live_feeds(self) -> Optional[Dict]:
        return await self._request("GET", "/api/v1/live-feeds")
    
    async def get_live_feed_metrics(self) -> Optional[Dict]:
        return await self._request("GET", "/api/v1/live-feeds/metrics")
    
    # Threat Hunting
    async def threat_hunt(self, query: Dict) -> Optional[Dict]:
        return await self._request("POST", "/api/v1/hunt", json=query)
    
    # Export
    async def export_stix(self, limit: int = 1000, since: str = None) -> Optional[Dict]:
        params = {"limit": limit}
        if since:
            params["since"] = since
        return await self._request("GET", "/api/v1/export/stix", params=params)
    
    async def export_csv(self, limit: int = 1000, since: str = None) -> Optional[str]:
        params = {"limit": limit}
        if since:
            params["since"] = since
        async with self.session.get("/api/v1/export/csv", params=params) as resp:
            if resp.status == 200:
                return await resp.text()
            return None


class ScanEnricher:
    """Enrich scan results with Living Intel threat intelligence"""
    
    def __init__(self, client: LivingIntelClient = None):
        self.client = client or LivingIntelClient()
    
    async def enrich_scan_result(self, scan_result: Dict) -> Dict:
        """Enrich a complete scan result with threat intelligence"""
        enriched = scan_result.copy()
        
        # Extract IOCs from scan result
        iocs = self._extract_iocs(scan_result)
        
        if iocs:
            # Bulk enrich in batches of 20 to avoid timeout
            batch_size = 20
            all_results = []
            
            for i in range(0, len(iocs), batch_size):
                batch = iocs[i:i + batch_size]
                enrichment_results = await self.client.bulk_enrich(batch)
                if enrichment_results and enrichment_results.get("results"):
                    all_results.extend(enrichment_results["results"])
            
            if all_results:
                enriched["threat_intelligence"] = all_results
        
        return enriched
    
    async def enrich_apk_analysis(self, apk_analysis: Dict) -> Dict:
        """Enrich APK analysis with threat intelligence"""
        enriched = apk_analysis.copy()
        iocs = []
        
        # Extract network IOCs
        if "network" in apk_analysis:
            network = apk_analysis["network"]
            if "urls" in network:
                for url in network["urls"]:
                    iocs.append({"type": "url", "value": url})
            if "ips" in network:
                for ip in network["ips"]:
                    iocs.append({"type": "ipv4", "value": ip})
            if "domains" in network:
                for domain in network["domains"]:
                    iocs.append({"type": "domain", "value": domain})
        
        # Extract file hashes
        if "file_info" in apk_analysis:
            file_info = apk_analysis["file_info"]
            for hash_type in ["md5", "sha1", "sha256"]:
                if hash_type in file_info:
                    iocs.append({"type": hash_type, "value": file_info[hash_type]})
        
        # Enrich IOCs
        if iocs:
            enrichment_results = await self.client.bulk_enrich(iocs)
            if enrichment_results:
                enriched["threat_intelligence"] = enrichment_results.get("results", [])
        
        return enriched
    
    def _extract_iocs(self, scan_result: Dict) -> List[Dict]:
        """Extract IOCs from scan result"""
        iocs = []
        
        # Helper to extract from nested dict
        def extract_from_dict(d: Dict, prefix: str = ""):
            # Network IOCs - standard structure
            if "network" in d:
                network = d["network"]
                if "urls" in network:
                    for url in network["urls"]:
                        iocs.append({"type": "url", "value": url})
                if "ips" in network:
                    for ip in network["ips"]:
                        iocs.append({"type": "ipv4", "value": ip})
                if "domains" in network:
                    for domain in network["domains"]:
                        iocs.append({"type": "domain", "value": domain})
            
            # MobSF structure - urls is list of dicts with 'urls' and 'path'
            if "urls" in d and isinstance(d["urls"], list):
                for item in d["urls"]:
                    if isinstance(item, dict) and "urls" in item:
                        for url in item["urls"]:
                            iocs.append({"type": "url", "value": url})
            
            # MobSF domains - dict mapping domain to details
            if "domains" in d and isinstance(d["domains"], dict):
                for domain in d["domains"].keys():
                    iocs.append({"type": "domain", "value": domain})
            
            # MobSF emails - list of dicts with 'emails' key
            if "emails" in d and isinstance(d["emails"], list):
                for item in d["emails"]:
                    if isinstance(item, dict) and "emails" in item:
                        for email in item["emails"]:
                            iocs.append({"type": "email", "value": email})
            
            # MobSF firebase_urls
            if "firebase_urls" in d and isinstance(d["firebase_urls"], list):
                for url in d["firebase_urls"]:
                    iocs.append({"type": "url", "value": url})
            
            # File hashes
            if "file_info" in d:
                file_info = d["file_info"]
                for hash_type in ["md5", "sha1", "sha256"]:
                    if hash_type in file_info:
                        iocs.append({"type": hash_type, "value": file_info[hash_type]})
            
            # File hashes at top level (MobSF)
            for hash_type in ["md5", "sha1", "sha256"]:
                if hash_type in d:
                    iocs.append({"type": hash_type, "value": d[hash_type]})
            
            # YARA matches
            if "yara" in d:
                for match in d["yara"]:
                    if "strings" in match:
                        for string in match["strings"]:
                            # Extract potential IOCs from strings
                            pass
        
        # Check top level
        extract_from_dict(scan_result)
        
        # Check scans sub-dicts
        if "scans" in scan_result and isinstance(scan_result["scans"], dict):
            for scan_name, scan_data in scan_result["scans"].items():
                if isinstance(scan_data, dict):
                    extract_from_dict(scan_data)
        
        return iocs
    
    async def check_ioc_reputation(self, ioc_type: str, value: str) -> Dict:
        """Check reputation of a single IOC"""
        return await self.client.enrich_ioc(ioc_type, value)
    
    async def hunt_related_threats(self, query: Dict) -> List[Dict]:
        """Hunt for related threats"""
        result = await self.client.threat_hunt(query)
        if result:
            return result.get("results", [])
        return []


class FeedSyncManager:
    """Manage synchronization of threat feeds with scan engine"""
    
    def __init__(self, client: LivingIntelClient = None):
        self.client = client or LivingIntelClient()
        self.last_sync = None
    
    async def sync_yara_rules(self) -> Dict:
        """Sync YARA rules from threat intelligence"""
        # Query for YARA rules in threat intel
        query = {
            "type": "yara",
            "tags": ["yara", "rule"],
            "since": self.last_sync.isoformat() if self.last_sync else None
        }
        result = await self.client.query_threat_intel(query)
        
        if result and result.get("results"):
            self.last_sync = datetime.now()
            return {
                "synced": len(result["results"]),
                "rules": result["results"]
            }
        return {"synced": 0, "rules": []}
    
    async def sync_malware_hashes(self) -> Dict:
        """Sync known malware hashes"""
        query = {
            "type": "hash",
            "tags": ["malware", "hash"],
            "since": self.last_sync.isoformat() if self.last_sync else None
        }
        result = await self.client.query_threat_intel(query)
        
        if result and result.get("results"):
            self.last_sync = datetime.now()
            return {
                "synced": len(result["results"]),
                "hashes": result["results"]
            }
        return {"synced": 0, "hashes": []}
    
    async def sync_c2_indicators(self) -> Dict:
        """Sync C2 indicators"""
        query = {
            "tags": ["c2", "c2_server", "command_control"],
            "since": self.last_sync.isoformat() if self.last_sync else None
        }
        result = await self.client.query_threat_intel(query)
        
        if result and result.get("results"):
            self.last_sync = datetime.now()
            return {
                "synced": len(result["results"]),
                "indicators": result["results"]
            }
        return {"synced": 0, "indicators": []}
    
    async def full_sync(self) -> Dict:
        """Perform full synchronization"""
        results = {}
        results["yara"] = await self.sync_yara_rules()
        results["malware_hashes"] = await self.sync_malware_hashes()
        results["c2"] = await self.sync_c2_indicators()
        return results


import threading


# Thread-local storage for client instances
_client_local = threading.local()


def get_living_intel_client() -> LivingIntelClient:
    """Get or create Living Intel client for current thread/process"""
    if not hasattr(_client_local, 'client') or _client_local.client is None:
        _client_local.client = LivingIntelClient()
    return _client_local.client


async def enrich_scan_with_threat_intel(scan_result: Dict) -> Dict:
    """Convenience function to enrich scan with threat intelligence"""
    # Create a new client for each call to avoid issues with forked processes
    client = LivingIntelClient()
    enricher = ScanEnricher(client)
    try:
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"Starting threat intel enrichment for {len(scan_result.get('scans', {}))} scans")
        result = await enricher.enrich_scan_result(scan_result)
        logger.warning(f"Enrichment completed, keys: {list(result.keys())}")
        if 'threat_intelligence' in result:
            logger.warning(f"Threat intel added: {len(result['threat_intelligence'])} items")
        else:
            logger.warning("No threat_intelligence field in result")
        return result
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Threat intel enrichment failed: {e}", exc_info=True)
        raise
    finally:
        await client.close()


async def check_ioc_threat_intel(ioc_type: str, value: str) -> Dict:
    """Convenience function to check IOC reputation"""
    client = LivingIntelClient()
    enricher = ScanEnricher(client)
    try:
        return await enricher.check_ioc_reputation(ioc_type, value)
    finally:
        await client.close()