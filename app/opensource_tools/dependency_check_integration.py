"""
OWASP Dependency-Check Integration - SCA for dependencies
Open source alternative to Black Duck, Veracode SCA, Snyk
"""
import asyncio
import logging
import json
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any
from pathlib import Path

from .base import OpenSourceToolBase, ToolConfig, ToolResult, tool_registry

logger = logging.getLogger(__name__)


class DependencyCheckIntegration(OpenSourceToolBase):
    """OWASP Dependency-Check integration for SCA"""
    
    def __init__(self):
        config = ToolConfig(
            name="dependency-check",
            executable="dependency-check",
            args=[],
            install_check="dependency-check --version",
            timeout=600
        )
        super().__init__(config)
    
    async def analyze(self, target: str, options: Dict = None) -> ToolResult:
        """Scan target with OWASP Dependency-Check"""
        start_time = asyncio.get_event_loop().time()
        options = options or {}
        
        try:
            cmd = ['dependency-check', '--scan', target]
            
            # Output format
            cmd.extend(['--format', 'JSON'])
            
            # Output file
            output_file = options.get('output', '/tmp/dependency-check-report.json')
            cmd.extend(['--out', output_file])
            
            # Project name
            project_name = options.get('project', 'silver-scan')
            cmd.extend(['--project', project_name])
            
            # Fail on CVSS
            if options.get('fail_on_cvss'):
                cmd.extend(['--failOnCVSS', str(options['fail_on_cvss'])])
            
            # Skip NVD update
            if not options.get('update_nvd', True):
                cmd.append('--noupdate')
            
            # Suppression file
            if options.get('suppression'):
                cmd.extend(['--suppression', options['suppression']])
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.config.timeout
            )
            
            # Dependency-check returns 0 on success, 1 on vulnerabilities found
            if proc.returncode not in [0, 1]:
                return ToolResult(
                    tool_name=self.config.name,
                    success=False,
                    error=stderr.decode() or stdout.decode()
                )
            
            # Parse JSON report
            findings = []
            try:
                with open(output_file, 'r') as f:
                    data = json.load(f)
                
                dependencies = data.get('dependencies', [])
                
                for dep in dependencies:
                    vulnerabilities = dep.get('vulnerabilities', [])
                    
                    for vuln in vulnerabilities:
                        findings.append({
                            "type": "vulnerability",
                            "cve": vuln.get('name'),
                            "severity": vuln.get('severity'),
                            "cvss_v2": vuln.get('cvssV2', {}),
                            "cvss_v3": vuln.get('cvssV3', {}),
                            "description": vuln.get('description'),
                            "cwe": vuln.get('cwe', []),
                            "references": vuln.get('references', []),
                            "package": dep.get('fileName'),
                            "package_path": dep.get('filePath'),
                            "package_version": dep.get('version'),
                            "evidence": dep.get('evidence', [])
                        })
                        
            except (json.JSONDecodeError, FileNotFoundError) as e:
                logger.warning(f"Failed to parse Dependency-Check report: {e}")
            
            # Also parse XML if JSON fails
            if not findings:
                xml_file = output_file.replace('.json', '.xml')
                findings = await self._parse_xml_report(xml_file)
            
            return ToolResult(
                tool_name=self.config.name,
                success=True,
                findings=findings,
                metadata={
                    "target": target,
                    "output_file": output_file,
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
            logger.error(f"Dependency-Check scan failed: {e}")
            return ToolResult(
                tool_name=self.config.name,
                success=False,
                error=str(e),
                execution_time=asyncio.get_event_loop().time() - start_time
            )
    
    async def _parse_xml_report(self, xml_file: str) -> List[Dict]:
        """Parse XML report as fallback"""
        findings = []
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Parse dependencies
            for dep in root.findall('.//dependency'):
                file_name = dep.findtext('fileName', '')
                file_path = dep.findtext('filePath', '')
                version = dep.findtext('version', '')
                
                for vuln in dep.findall('vulnerabilities/vulnerability'):
                    findings.append({
                        "type": "vulnerability",
                        "cve": vuln.findtext('name', ''),
                        "severity": vuln.findtext('severity', ''),
                        "cvss_v2": vuln.findtext('cvssV2', ''),
                        "cvss_v3": vuln.findtext('cvssV3', ''),
                        "description": vuln.findtext('description', ''),
                        "cwe": [cwe.text for cwe in vuln.findall('cwes/cwe')],
                        "references": [ref.text for ref in vuln.findall('references/reference')],
                        "package": file_name,
                        "package_path": file_path,
                        "package_version": version
                    })
        except Exception as e:
            logger.warning(f"Failed to parse XML report: {e}")
        return findings


# Register
dependency_check_tool = DependencyCheckIntegration()
tool_registry.register(dependency_check_tool)