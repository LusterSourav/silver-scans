"""
MISP Integration - Threat intelligence sharing platform
Open source alternative to Recorded Future, CrowdStrike Intel
"""
import asyncio
import logging
import json
import aiohttp
from typing import Dict, List, Optional, Any
from datetime import datetime

from .base import OpenSourceToolBase, ToolConfig, ToolResult, tool_registry

logger = logging.getLogger(__name__)


class MISPIntegration(OpenSourceToolBase):
    """MISP integration for threat intelligence"""
    
    def __init__(self, url: str = None, api_key: str = None):
        config = ToolConfig(
            name="misp",
            executable="misp",
            args=[],
            install_check="curl -s http://localhost:8080",
            timeout=120
        )
        super().__init__(config)
        self.url = url
        self.api_key = api_key
        self.session = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        if not self.session:
            headers = {
                "Authorization": self.api_key,
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            self.session = aiohttp.ClientSession(
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout)
            )
        return self.session
    
    async def analyze(self, target: str, options: Dict = None) -> ToolResult:
        """Query MISP for threat intelligence on target"""
        start_time = asyncio.get_event_loop().time()
        options = options or {}
        
        try:
            session = await self._get_session()
            findings = []
            
            # Search for IOCs
            ioc_type = options.get('ioc_type', 'auto')
            
            # Determine IOC type if auto
            if ioc_type == 'auto':
                ioc_type = self._detect_ioc_type(target)
            
            # Search attributes
            search_data = {
                "value": target,
                "type": ioc_type,
                "includeContext": True,
                "includeCorrelations": True,
                "limit": options.get('limit', 100),
                "tags": options.get('tags', []),
                "to_ids": options.get('to_ids', True)
            }
            
            async with session.post(
                f"{self.url}/attributes/restSearch",
                json=search_data
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    attributes = data.get('response', {}).get('Attribute', [])
                    
                    for attr in attributes:
                        findings.append({
                            "type": "misp_attribute",
                            "id": attr.get('id'),
                            "type": attr.get('type'),
                            "value": attr.get('value'),
                            "category": attr.get('category'),
                            "comment": attr.get('comment'),
                            "to_ids": attr.get('to_ids'),
                            "timestamp": attr.get('timestamp'),
                            "event_id": attr.get('event_id'),
                            "event_info": attr.get('Event', {}).get('info'),
                            "tags": [t.get('name') for t in attr.get('Tag', [])],
                            "correlations": attr.get('Correlation', [])
                        })
            
            # Search events
            event_data = {
                "value": target,
                "includeAttributes": True,
                "limit": options.get('limit', 50)
            }
            
            async with session.post(
                f"{self.url}/events/restSearch",
                json=event_data
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    events = data.get('response', [])
                    
                    for event in events:
                        event_info = event.get('Event', {})
                        findings.append({
                            "type": "misp_event",
                            "id": event_info.get('id'),
                            "info": event_info.get('info'),
                            "date": event_info.get('date'),
                            "threat_level": event_info.get('threat_level_id'),
                            "analysis": event_info.get('analysis'),
                            "distribution": event_info.get('distribution'),
                            "tags": [t.get('name') for t in event_info.get('Tag', [])],
                            "attributes_count": len(event_info.get('Attribute', []))
                        })
            
            # Get galaxy clusters if applicable
            if options.get('galaxy', False):
                galaxy_findings = await self._search_galaxy(session, target)
                findings.extend(galaxy_findings)
            
            return ToolResult(
                tool_name=self.config.name,
                success=True,
                findings=findings,
                metadata={
                    "target": target,
                    "ioc_type": ioc_type,
                    "url": self.url
                },
                execution_time=asyncio.get_event_loop().time() - start_time
            )
            
        except Exception as e:
            logger.error(f"MISP query failed: {e}")
            return ToolResult(
                tool_name=self.config.name,
                success=False,
                error=str(e),
                execution_time=asyncio.get_event_loop().time() - start_time
            )
    
    def _detect_ioc_type(self, value: str) -> str:
        """Detect IOC type from value"""
        import re
        
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
            return 'ip-src'
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
        elif value.startswith(('http://', 'https://')):
            return 'url'
        elif '@' in value:
            return 'email-src'
        return 'text'
    
    async def _search_galaxy(self, session: aiohttp.ClientSession, target: str) -> List[Dict]:
        """Search MISP galaxy clusters"""
        findings = []
        
        try:
            # Search galaxy clusters
            async with session.post(
                f"{self.url}/galaxies/restSearch",
                json={"value": target, "limit": 20}
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    clusters = data.get('response', [])
                    
                    for cluster in clusters:
                        cluster_info = cluster.get('GalaxyCluster', {})
                        findings.append({
                            "type": "misp_galaxy",
                            "id": cluster_info.get('id'),
                            "name": cluster_info.get('name'),
                            "description": cluster_info.get('description'),
                            "type": cluster_info.get('type'),
                            "tags": cluster_info.get('tags', []),
                            "references": cluster_info.get('references', []),
                            "galaxy_id": cluster_info.get('galaxy_id')
                        })
        except Exception as e:
            logger.warning(f"Galaxy search failed: {e}")
        
        return []


# Register
misp_tool = MISPIntegration()
tool_registry.register(misp_tool)