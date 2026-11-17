"""
Grype Integration - Vulnerability scanner for containers and filesystems
Open source alternative to Snyk, Black Duck, Veracode SCA
"""
import asyncio
import logging
import json
from typing import Dict, List, Optional, Any

from .base import OpenSourceToolBase, ToolConfig, ToolResult, tool_registry

logger = logging.getLogger(__name__)


class GrypeIntegration(OpenSourceToolBase):
    """Grype integration for vulnerability scanning"""
    
    def __init__(self):
        config = ToolConfig(
            name="grype",
            executable="grype",
            args=[],
            install_check="grype version",
            timeout=300
        )
        super().__init__(config)
    
    async def analyze(self, target: str, options: Dict = None) -> ToolResult:
        """Scan target with Grype for vulnerabilities"""
        start_time = asyncio.get_event_loop().time()
        options = options or {}
        
        try:
            # Build command
            cmd = ['grype', target]
            
            # Output format
            output_format = options.get('output', 'json')
            cmd.extend(['-o', output_format])
            
            # Severity threshold
            if options.get('severity'):
                cmd.extend(['--severity', options['severity']])
            
            # Platform
            if options.get('platform'):
                cmd.extend(['--platform', options['platform']])
            
            # Add database update
            if options.get('update_db', True):
                cmd.insert(1, 'db')
                cmd.insert(2, 'update')
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.config.timeout
            )
            
            if proc.returncode != 0 and proc.returncode != 1:  # 1 = vulnerabilities found
                return ToolResult(
                    tool_name=self.config.name,
                    success=False,
                    error=stderr.decode() or stdout.decode()
                )
            
            # Parse findings
            findings = []
            output = stdout.decode()
            
            if output_format == 'json':
                try:
                    data = json.loads(output)
                    matches = data.get('matches', [])
                    
                    for match in matches:
                        vuln = match.get('vulnerability', {})
                        artifact = match.get('artifact', {})
                        
                        findings.append({
                            "type": "vulnerability",
                            "id": vuln.get('id'),
                            "severity": vuln.get('severity'),
                            "cvss": vuln.get('cvss', []),
                            "description": vuln.get('description'),
                            "package": artifact.get('name'),
                            "version": artifact.get('version'),
                            "type": artifact.get('type'),
                            "locations": match.get('artifact', {}).get('locations', []),
                            "related_vulnerabilities": vuln.get('relatedVulnerabilities', []),
                            "fix": vuln.get('fix', {}).get('versions', [])
                        })
                except json.JSONDecodeError:
                    pass
            
            # Also parse table output if not JSON
            if not findings:
                findings = self._parse_table_output(stdout.decode())
            
            return ToolResult(
                tool_name=self.config.name,
                success=True,
                findings=findings,
                metadata={
                    "target": target,
                    "vulnerability_count": len(findings)
                },
                execution_time=asyncio.get_event_loop().time() - start_time
            )
            
        except asyncio.TimeoutError:
            return ToolResult(
                tool_name=self.config.name,
                success=False,
                error="Scan timed out",
                execution_time=asyncio.get_event_loop().time() - start_time
            )
        except Exception as e:
            logger.error(f"Grype scan failed: {e}")
            return ToolResult(
                tool_name=self.config.name,
                success=False,
                error=str(e),
                execution_time=asyncio.get_event_loop().time() - start_time
            )
    
    def _parse_table_output(self, output: str) -> List[Dict]:
        """Parse Grype table output"""
        findings = []
        lines = output.strip().split('\n')
        
        for line in lines:
            if '│' in line and not line.startswith('─') and 'NAME' not in line:
                parts = [p.strip() for p in line.split('│') if p.strip()]
                if len(parts) >= 5:
                    findings.append({
                        "type": "vulnerability",
                        "package": parts[0],
                        "version": parts[1],
                        "type": parts[2],
                        "vulnerability": parts[3],
                        "severity": parts[4]
                    })
        return findings


# Register
grype_tool = GrypeIntegration()
tool_registry.register(grype_tool)