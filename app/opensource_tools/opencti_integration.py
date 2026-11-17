"""
OpenCTI Integration - Open Cyber Threat Intelligence platform
Open source alternative to Recorded Future, CrowdStrike Intel
"""
import asyncio
import logging
import json
import aiohttp
from typing import Dict, List, Optional, Any

from .base import OpenSourceToolBase, ToolConfig, ToolResult, tool_registry

logger = logging.getLogger(__name__)


class OpenCTIIntegration(OpenSourceToolBase):
    """OpenCTI integration for threat intelligence"""
    
    def __init__(self, url: str = None, api_token: str = None):
        config = ToolConfig(
            name="opencti",
            executable="opencti",
            args=[],
            install_check="curl -s http://localhost:4000",
            timeout=120
        )
        super().__init__(config)
        self.url = url
        self.api_token = api_token
        self.session = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        if not self.session:
            headers = {
                "Authorization": f"Bearer {self.api_token}",
                "Content-Type": "application/json"
            }
            self.session = aiohttp.ClientSession(
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout)
            )
        return self.session
    
    async def analyze(self, target: str, options: Dict = None) -> ToolResult:
        """Query OpenCTI for threat intelligence"""
        start_time = asyncio.get_event_loop().time()
        options = options or {}
        
        try:
            session = await self._get_session()
            findings = []
            
            # GraphQL query for IOC search
            query = """
            query SearchIndicators($value: String!) {
                indicators(filters: {value: $value}, first: 100) {
                    edges {
                        node {
                            id
                            name
                            pattern_type
                            pattern
                            valid_from
                            valid_until
                            description
                            confidence
                            created
                            modified
                            labels {
                                edges {
                                    node {
                                        value
                                    }
                                }
                            }
                            external_references {
                                edges {
                                    node {
                                        source_name
                                        external_id
                                        url
                                    }
                                }
                            }
                            kill_chain_phases {
                                edges {
                                    node {
                                        kill_chain_name
                                        phase_name
                                    }
                                }
                            }
                            stix_objects {
                                edges {
                                    node {
                                        ... on Malware {
                                            name
                                            description
                                            is_family
                                        }
                                        ... on IntrusionSet {
                                            name
                                            description
                                            aliases
                                        }
                                        ... on ThreatActor {
                                            name
                                            description
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            variables = {"value": target}
            
            async with session.post(
                f"{self.url}/graphql",
                json={"query": query, "variables": variables}
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    indicators = data.get('data', {}).get('indicators', {}).get('edges', [])
                    
                    for edge in indicators:
                        node = edge.get('node', {})
                        findings.append({
                            "type": "opencti_indicator",
                            "id": node.get('id'),
                            "name": node.get('name'),
                            "pattern_type": node.get('pattern_type'),
                            "pattern": node.get('pattern'),
                            "valid_from": node.get('valid_from'),
                            "valid_until": node.get('valid_until'),
                            "description": node.get('description'),
                            "confidence": node.get('confidence'),
                            "labels": [l['node']['value'] for l in node.get('labels', {}).get('edges', [])],
                            "external_references": [
                                {
                                    "source": r['node']['source_name'],
                                    "external_id": r['node']['external_id'],
                                    "url": r['node']['url']
                                }
                                for r in node.get('external_references', {}).get('edges', [])
                            ],
                            "kill_chain_phases": [
                                {
                                    "kill_chain": p['node']['kill_chain_name'],
                                    "phase": p['node']['phase_name']
                                }
                                for p in node.get('kill_chain_phases', {}).get('edges', [])
                            ],
                            "stix_objects": [
                                {
                                    "type": obj['node']['__typename'],
                                    "name": obj['node'].get('name'),
                                    "description": obj['node'].get('description')
                                }
                                for obj in node.get('stix_objects', {}).get('edges', [])
                            ]
                        })
            
            # Search for malware
            malware_query = """
            query SearchMalware($name: String!) {
                malwares(filters: {name: $name}, first: 20) {
                    edges {
                        node {
                            id
                            name
                            description
                            is_family
                            labels {
                                edges {
                                    node {
                                        value
                                    }
                                }
                            }
                            external_references {
                                edges {
                                    node {
                                        source_name
                                        external_id
                                        url
                                    }
                                }
                            }
                        }
                    }
                }
            """
            
            async with session.post(
                f"{self.url}/graphql",
                json={"query": malware_query, "variables": {"name": target}}
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    malwares = data.get('data', {}).get('malwares', {}).get('edges', [])
                    
                    for edge in malwares:
                        node = edge.get('node', {})
                        findings.append({
                            "type": "opencti_malware",
                            "id": node.get('id'),
                            "name": node.get('name'),
                            "description": node.get('description'),
                            "is_family": node.get('is_family'),
                            "labels": [l['node']['value'] for l in node.get('labels', {}).get('edges', [])],
                            "external_references": [
                                {
                                    "source": r['node']['source_name'],
                                    "external_id": r['node']['external_id'],
                                    "url": r['node']['url']
                                }
                                for r in node.get('external_references', {}).get('edges', [])
                            ]
                        })
            
            # Search intrusion sets (threat actors)
            actor_query = """
            query SearchIntrusionSet($name: String!) {
                intrusionSets(filters: {name: $name}, first: 20) {
                    edges {
                        node {
                            id
                            name
                            description
                            aliases
                            labels {
                                edges {
                                    node {
                                        value
                                    }
                                }
                            }
                            external_references {
                                edges {
                                    node {
                                        source_name
                                        external_id
                                        url
                                    }
                                }
                            }
                        }
                    }
                }
            }
            """
            
            async with session.post(
                f"{self.url}/graphql",
                json={"query": actor_query, "variables": {"name": target}}
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    actors = data.get('data', {}).get('intrusionSets', {}).get('edges', [])
                    
                    for edge in actors:
                        node = edge.get('node', {})
                        findings.append({
                            "type": "opencti_threat_actor",
                            "id": node.get('id'),
                            "name": node.get('name'),
                            "description": node.get('description'),
                            "aliases": node.get('aliases', []),
                            "labels": [l['node']['value'] for l in node.get('labels', {}).get('edges', [])],
                            "external_references": [
                                {
                                    "source": r['node']['source_name'],
                                    "external_id": r['node']['external_id'],
                                    "url": r['node']['url']
                                }
                                for r in node.get('external_references', {}).get('edges', [])
                            ]
                        })
            
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
            logger.error(f"OpenCTI query failed: {e}")
            return ToolResult(
                tool_name=self.config.name,
                success=False,
                error=str(e),
                execution_time=asyncio.get_event_loop().time() - start_time
            )


# Register
opencti_tool = OpenCTIIntegration()
tool_registry.register(opencti_tool)