"""
Yeti Integration - Threat intelligence platform
Open source alternative to MISP, OpenCTI
"""
import asyncio
import logging
import json
import aiohttp
from typing import Dict, List, Optional, Any

from .base import OpenSourceToolBase, ToolConfig, ToolResult, tool_registry

logger = logging.getLogger(__name__)


class YetiIntegration(OpenSourceToolBase):
    """Yeti integration for threat intelligence"""
    
    def __init__(self, url: str = None, api_key: str = None):
        config = ToolConfig(
            name="yeti",
            executable="yeti",
            args=[],
            install_check="curl -s http://localhost:5000",
            timeout=120
        )
        super().__init__(config)
        self.url = url
        self.api_key = api_key
        self.session = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        if not self.session:
            headers = {
                "X-Api-Key": self.api_key,
                "Content-Type": "application/json"
            }
            self.session = aiohttp.ClientSession(
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout)
            )
        return self.session
    
    async def analyze(self, target: str, options: Dict = None) -> ToolResult:
        """Query Yeti for threat intelligence"""
        start_time = asyncio.get_event_loop().time()
        options = options or {}
        
        try:
            session = await self._get_session()
            findings = []
            
            # Search observables
            async with session.get(
                f"{self.url}/api/observables/search/",
                params={"value": target, "limit": 100}
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for obs in data.get('objects', []):
                        findings.append({
                            "type": "yeti_observable",
                            "id": obs.get('id'),
                            "type": obs.get('type'),
                            "value": obs.get('value'),
                            "tags": obs.get('tags', []),
                            "created": obs.get('created'),
                            "updated": obs.get('updated'),
                            "description": obs.get('description'),
                            "contexts": obs.get('contexts', [])
                        })
            
            # Search entities
            async with session.get(
                f"{self.url}/api/entities/search/",
                params={"name": target, "limit": 50}
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entity in data.get('objects', []):
                        findings.append({
                            "type": "yeti_entity",
                            "id": entity.get('id'),
                            "name": entity.get('name'),
                            "type": entity.get('type'),
                            "description": entity.get('description'),
                            "tags": entity.get('tags', []),
                            "created": entity.get('created'),
                            "updated": entity.get('updated')
                        })
            
            # Search indicators
            async with session.get(
                f"{self.url}/api/indicators/search/",
                params={"name": target, "limit": 50}
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for indicator in data.get('objects', []):
                        findings.append({
                            "type": "yeti_indicator",
                            "id": indicator.get('id'),
                            "name": indicator.get('name'),
                            "pattern": indicator.get('pattern'),
                            "type": indicator.get('type'),
                            "description": indicator.get('description'),
                            "confidence": indicator.get('confidence'),
                            "tags": indicator.get('tags', []),
                            "created": indicator.get('created'),
                            "updated": indicator.get('updated')
                        })
            
            # Get related entities
            if options.get('expand', False):
                # Get relationships for found entities
                for finding in findings[:10]:  # Limit
                    if finding.get('id'):
                        await self._expand_relationships(session, finding, findings)
            
            return ToolResult(
                tool_name=self.config.name,
                success=True,
                findings=findings,
                metadata={
                    "target": target,
                    "url": self.url
                },
                execution_time=asyncio.get_event_loop().time() - start_time
            )
            
        except Exception as e:
            logger.error(f"Yeti query failed: {e}")
            return ToolResult(
                tool_name=self.config.name,
                success=False,
                error=str(e),
                execution_time=asyncio.get_event_loop().time() - start_time
            )
    
    async def _expand_relationships(self, session: aiohttp.ClientSession, entity: Dict, findings: List):
        """Expand relationships for entity"""
        try:
            entity_id = entity.get('id')
            if not entity_id:
                return
            
            async with session.get(
                f"{self.url}/api/entities/{entity_id}/relationships/"
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for rel in data.get('objects', []):
                        findings.append({
                            "type": "yeti_relationship",
                            "source": rel.get('source'),
                            "target": rel.get('target'),
                            "type": rel.get('relationship_type'),
                            "description": rel.get('description')
                        })
        except Exception as e:
            logger.warning(f"Relationship expansion failed: {e}")


# Register
yeti_tool = YetiIntegration()
tool_registry.register(yeti_tool)