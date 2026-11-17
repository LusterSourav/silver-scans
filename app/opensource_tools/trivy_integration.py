"""
Trivy Integration - Comprehensive security scanner
Open source alternative to Snyk, Aqua, Aqua Security
"""
import asyncio
import logging
import json
from typing import Dict, List, Optional, Any

from .base import OpenSourceToolBase, ToolConfig, ToolResult, tool_registry

logger = logging.getLogger(__name__)


class TrivyIntegration(OpenSourceToolBase):
    """Trivy integration for comprehensive security scanning"""
    
    def __init__(self):
        config = ToolConfig(
            name="trivy",
            executable="trivy",
            args=[],
            install_check="trivy version",
            timeout=300
        )
        super().__init__(config)
    
    async def analyze(self, target: str, options: Dict = None) -> ToolResult:
        """Scan target with Trivy"""
        start_time = asyncio.get_event_loop().time()
        options = options or {}
        
        try:
            findings = []
            
            # Determine scan type
            scan_types = options.get('scanners', ['vuln', 'secret', 'config', 'sbom'])
            
            for scanner in scan_types:
                cmd = ['trivy', scanner, target]
                
                # Output format
                cmd.extend(['-f', 'json'])
                
                # Severity
                if options.get('severity'):
                    cmd.extend(['--severity', options['severity']])
                
                # Ignore unfixed
                if options.get('ignore_unfixed'):
                    cmd.append('--ignore-unfixed')
                
                # Skip DB update
                if not options.get('update_db', True):
                    cmd.append('--skip-db-update')
                
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.config.timeout
                )
                
                if proc.returncode not in [0, 1]:
                    logger.warning(f"Trivy {scanner} returned {proc.returncode}: {stderr.decode()}")
                    continue
                
                # Parse findings
                output = stdout.decode()
                try:
                    data = json.loads(output)
                    results = data.get('Results', [])
                    
                    for result in results:
                        target_name = result.get('Target', target)
                        target_type = result.get('Type', scanner)
                        vulnerabilities = result.get('Vulnerabilities', [])
                        misconfigurations = result.get('Misconfigurations', [])
                        secrets = result.get('Secrets', [])
                        
                        for vuln in vulnerabilities:
                            findings.append({
                                "type": "vulnerability",
                                "scanner": scanner,
                                "target": target_name,
                                "target_type": target_type,
                                "id": vuln.get('VulnerabilityID'),
                                "title": vuln.get('Title'),
                                "description": vuln.get('Description'),
                                "severity": vuln.get('Severity'),
                                "cvss": vuln.get('CVSS', {}),
                                "references": vuln.get('References', []),
                                "package": vuln.get('PkgName'),
                                "installed_version": vuln.get('InstalledVersion'),
                                "fixed_version": vuln.get('FixedVersion'),
                                "cwe": vuln.get('CweIDs', [])
                            })
                        
                        for misconfig in misconfigurations:
                            findings.append({
                                "type": "misconfiguration",
                                "scanner": scanner,
                                "target": target_name,
                                "target_type": target_type,
                                "id": misconfig.get('ID'),
                                "title": misconfig.get('Title'),
                                "description": misconfig.get('Description'),
                                "severity": misconfig.get('Severity'),
                                "namespace": misconfig.get('Namespace'),
                                "query": misconfig.get('Query'),
                                "resolution": misconfig.get('Resolution')
                            })
                        
                        for secret in secrets:
                            findings.append({
                                "type": "secret",
                                "scanner": scanner,
                                "target": target_name,
                                "target_type": target_type,
                                "rule_id": secret.get('RuleID'),
                                "category": secret.get('Category'),
                                "severity": secret.get('Severity'),
                                "match": secret.get('Match'),
                                "file": secret.get('File'),
                                "line": secret.get('Line')
                            })
                            
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse Trivy {scanner} output")
            
            return ToolResult(
                tool_name=self.config.name,
                success=True,
                findings=findings,
                metadata={
                    "target": target,
                    "scanners_used": scan_types,
                    "finding_count": len(findings)
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
            logger.error(f"Trivy scan failed: {e}")
            return ToolResult(
                tool_name=self.config.name,
                success=False,
                error=str(e),
                execution_time=asyncio.get_event_loop().time() - start_time
            )


# Register
trivy_tool = TrivyIntegration()
tool_registry.register(trivy_tool)