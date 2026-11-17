"""
Cuckoo Sandbox Integration - Dynamic malware analysis
Open source alternative to Joe Sandbox, VMRay, Hybrid Analysis
"""
import asyncio
import logging
import json
import aiohttp
import time
from typing import Dict, List, Optional, Any
from pathlib import Path

from .base import OpenSourceToolBase, ToolConfig, ToolResult, tool_registry

logger = logging.getLogger(__name__)


class CuckooIntegration(OpenSourceToolBase):
    """Cuckoo Sandbox integration for dynamic analysis"""
    
    def __init__(self, api_url: str = "http://cuckoo:8090", api_token: str = None):
        config = ToolConfig(
            name="cuckoo",
            executable="cuckoo",
            args=[],
            install_check="curl -s http://cuckoo:8090/api/cuckoo/status",
            timeout=600
        )
        super().__init__(config)
        self.api_url = api_url
        self.api_token = api_token
        self.session = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        if not self.session:
            headers = {}
            if self.api_token:
                headers["Authorization"] = f"Bearer {self.api_token}"
            self.session = aiohttp.ClientSession(
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout)
            )
        return self.session
    
    async def analyze(self, target: str, options: Dict = None) -> ToolResult:
        """Submit file to Cuckoo Sandbox for dynamic analysis"""
        start_time = asyncio.get_event_loop().time()
        options = options or {}
        
        try:
            session = await self._get_session()
            file_path = Path(target)
            
            if not file_path.exists():
                return ToolResult(
                    tool_name=self.config.name,
                    success=False,
                    error=f"File not found: {target}"
                )
            
            # Submit file
            with open(file_path, 'rb') as f:
                files = {'file': (file_path.name, f)}
                data = {
                    'package': options.get('package', 'com.android'),
                    'timeout': options.get('timeout', 120),
                    'options': options.get('options', ''),
                    'priority': options.get('priority', 1),
                    'machine': options.get('machine', ''),
                    'platform': options.get('platform', 'android'),
                    'tags': options.get('tags', ''),
                    'custom': options.get('custom', ''),
                    'memory': options.get('memory', False),
                    'enforce_timeout': options.get('enforce_timeout', True),
                    'clock': options.get('clock', ''),
                }
                
                async with session.post(
                    f"{self.api_url}/tasks/create/file",
                    data=data,
                    files={'file': (file_path.name, f)}
                ) as resp:
                    if resp.status != 200:
                        return ToolResult(
                            tool_name=self.config.name,
                            success=False,
                            error=f"Submission failed: {await resp.text()}"
                        )
                    submit_result = await resp.json()
            
            task_id = submit_result.get('task_id')
            if not task_id:
                return ToolResult(
                    tool_name=self.config.name,
                    success=False,
                    error="No task ID returned"
                )
            
            # Wait for completion
            report = await self._wait_for_completion(session, task_id, options.get('timeout', 120))
            
            if not report:
                return ToolResult(
                    tool_name=self.config.name,
                    success=False,
                    error="Analysis timed out or failed"
                )
            
            # Extract findings
            findings = self._extract_findings(report)
            
            return ToolResult(
                tool_name=self.config.name,
                success=True,
                findings=findings,
                metadata={
                    "task_id": task_id,
                    "file_hash": report.get('target', {}).get('file', {}).get('sha256'),
                    "report": report
                },
                execution_time=asyncio.get_event_loop().time() - start_time
            )
            
        except Exception as e:
            logger.error(f"Cuckoo analysis failed: {e}")
            return ToolResult(
                tool_name=self.config.name,
                success=False,
                error=str(e),
                execution_time=asyncio.get_event_loop().time() - start_time
            )
    
    async def _wait_for_completion(self, session: aiohttp.ClientSession, task_id: int, timeout: int) -> Optional[Dict]:
        """Wait for task completion and return report"""
        start = time.time()
        while time.time() - start < timeout:
            try:
                async with session.get(f"{self.api_url}/tasks/view/{task_id}") as resp:
                    if resp.status == 200:
                        task = await resp.json()
                        status = task.get('task', {}).get('status')
                        
                        if status == 'reported':
                            # Get full report
                            async with session.get(f"{self.api_url}/tasks/report/{task_id}") as report_resp:
                                if report_resp.status == 200:
                                    return await report_resp.json()
                        elif status in ['failure', 'error']:
                            return None
                
                await asyncio.sleep(10)
            except Exception as e:
                logger.error(f"Error checking task status: {e}")
                await asyncio.sleep(10)
        
        return None
    
    def _extract_findings(self, report: Dict) -> List[Dict]:
        """Extract standardized findings from Cuckoo report"""
        findings = []
        
        # Behavioral analysis
        for category in ['filesystem', 'registry', 'network', 'processes', 'signatures']:
            for item in report.get('behavior', {}).get(category, []):
                findings.append({
                    "type": f"behavior_{category}",
                    "data": item
                })
        
        # Network IOCs
        for domain in report.get('network', {}).get('domains', []):
            findings.append({
                "type": "network_domain",
                "domain": domain.get('domain'),
                "ip": domain.get('ip')
            })
        
        for http in report.get('network', {}).get('http', []):
            findings.append({
                "type": "network_http",
                "url": http.get('uri'),
                "method": http.get('method'),
                "headers": http.get('headers')
            })
        
        # Signatures (MITRE ATT&CK mapped)
        for sig in report.get('signatures', []):
            findings.append({
                "type": "signature",
                "name": sig.get('name'),
                "description": sig.get('description'),
                "severity": sig.get('severity', 2),
                "references": sig.get('references', []),
                "tags": sig.get('tags', []),
                "mitre": sig.get('mitre', [])
            })
        
        # Static analysis
        static = report.get('static', {})
        if static:
            findings.append({
                "type": "static_analysis",
                "pe_info": static.get('pe'),
                "strings": static.get('strings'),
                "imports": static.get('imports'),
                "exports": static.get('exports')
            })
        
        # Dropped files
        for dropped in report.get('dropped', []):
            findings.append({
                "type": "dropped_file",
                "sha256": dropped.get('sha256'),
                "path": dropped.get('path'),
                "size": dropped.get('size'),
                "type": dropped.get('type')
            })
        
        return findings


# Register
cuckoo_tool = CuckooIntegration()
tool_registry.register(cuckoo_tool)