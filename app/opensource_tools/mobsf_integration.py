"""
MobSF (Mobile Security Framework) Integration
Open source alternative to NowSecure, Appdome, Zimperium
"""
import asyncio
import logging
import aiohttp
import json
from typing import Dict, List, Optional, Any
from pathlib import Path

from .base import OpenSourceToolBase, ToolConfig, ToolResult, tool_registry

logger = logging.getLogger(__name__)


class MobSFIntegration(OpenSourceToolBase):
    """MobSF integration for static and dynamic mobile analysis"""
    
    def __init__(self, api_url: str = "http://mobsf:8000", api_key: str = None):
        config = ToolConfig(
            name="mobsf",
            executable="mobsf",
            args=[],
            install_check="curl -s http://mobsf:8000/api/v1/health",
            timeout=600
        )
        super().__init__(config)
        self.api_url = api_url
        self.api_key = api_key
        self.session = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        if not self.session:
            headers = {}
            if self.api_key:
                headers["Authorization"] = self.api_key
            self.session = aiohttp.ClientSession(
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout)
            )
        return self.session
    
    async def analyze(self, target: str, options: Dict = None) -> ToolResult:
        """Analyze APK/IPA with MobSF"""
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
            
            # Upload file
            with open(file_path, 'rb') as f:
                files = {'file': (file_path.name, f, 'application/octet-stream')}
                async with session.post(
                    f"{self.api_url}/api/v1/upload",
                    data=files
                ) as resp:
                    if resp.status != 200:
                        return ToolResult(
                            tool_name=self.config.name,
                            success=False,
                            error=f"Upload failed: {await resp.text()}"
                        )
                    upload_result = await resp.json()
            
            file_hash = upload_result.get('hash')
            if not file_hash:
                return ToolResult(
                    tool_name=self.config.name,
                    success=False,
                    error="No hash returned from upload"
                )
            
            # Start scan
            async with session.post(
                f"{self.api_url}/api/v1/scan",
                data={'hash': file_hash},
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            ) as resp:
                if resp.status != 200:
                    return ToolResult(
                        tool_name=self.config.name,
                        success=False,
                        error=f"Scan failed: {await resp.text()}"
                    )
            
            # Get report
            async with session.post(
                f"{self.api_url}/api/v1/report_json",
                data={'hash': file_hash},
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            ) as resp:
                if resp.status != 200:
                    return ToolResult(
                        tool_name=self.config.name,
                        success=False,
                        error=f"Report failed: {await resp.text()}"
                    )
                report = await resp.json()
            
            # Extract findings
            findings = self._extract_findings(report)
            
            return ToolResult(
                tool_name=self.config.name,
                success=True,
                findings=findings,
                metadata={
                    "file_hash": file_hash,
                    "scan_type": options.get("scan_type", "static"),
                    "report": report
                },
                execution_time=asyncio.get_event_loop().time() - start_time
            )
            
        except Exception as e:
            logger.error(f"MobSF analysis failed: {e}")
            return ToolResult(
                tool_name=self.config.name,
                success=False,
                error=str(e),
                execution_time=asyncio.get_event_loop().time() - start_time
            )
    
    def _extract_findings(self, report: Dict) -> List[Dict]:
        """Extract standardized findings from MobSF report"""
        findings = []
        
        # Security issues
        for issue in report.get("security_issues", []):
            findings.append({
                "type": "security_issue",
                "title": issue.get("title"),
                "description": issue.get("description"),
                "severity": issue.get("severity", "MEDIUM"),
                "file": issue.get("file"),
                "line": issue.get("line"),
                "cwe": issue.get("cwe")
            })
        
        # Permissions
        for perm in report.get("permissions", []):
            findings.append({
                "type": "permission",
                "name": perm.get("permission"),
                "status": perm.get("status"),
                "description": perm.get("description"),
                "risk": perm.get("risk")
            })
        
        # Network
        for url in report.get("urls", []):
            findings.append({
                "type": "network",
                "url": url.get("url"),
                "path": url.get("path"),
                "method": url.get("method")
            })
        
        # Components
        for comp_type in ["activities", "receivers", "providers", "services"]:
            for comp in report.get(comp_type, []):
                if comp.get("exported"):
                    findings.append({
                        "type": "exported_component",
                        "component_type": comp_type,
                        "name": comp.get("name"),
                        "permission": comp.get("permission")
                    })
        
        # Code analysis
        for issue in report.get("code_analysis", []):
            findings.append({
                "type": "code_issue",
                "title": issue.get("title"),
                "description": issue.get("description"),
                "severity": issue.get("severity"),
                "file": issue.get("file"),
                "line": issue.get("line")
            })
        
        # Trackers
        for tracker in report.get("trackers", []):
            findings.append({
                "type": "tracker",
                "name": tracker.get("name"),
                "category": tracker.get("category"),
                "url": tracker.get("url")
            })
        
        # Secrets
        for secret in report.get("secrets", []):
            findings.append({
                "type": "secret",
                "type": secret.get("type"),
                "value": secret.get("value"),
                "file": secret.get("file"),
                "line": secret.get("line")
            })
        
        return findings


# Register
mobsf_tool = MobSFIntegration()
tool_registry.register(mobsf_tool)