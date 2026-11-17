"""
Drozer Integration - Android security assessment framework
Open source alternative to NowSecure, Appdome
"""
import asyncio
import logging
import json
import re
from typing import Dict, List, Optional, Any

from .base import OpenSourceToolBase, ToolConfig, ToolResult, tool_registry

logger = logging.getLogger(__name__)


class DrozerIntegration(OpenSourceToolBase):
    """Drozer integration for Android security assessment"""
    
    def __init__(self):
        config = ToolConfig(
            name="drozer",
            executable="drozer",
            args=[],
            install_check="drozer --version",
            timeout=300
        )
        super().__init__(config)
    
    async def analyze(self, target: str, options: Dict = None) -> ToolResult:
        """Run Drozer analysis on target package"""
        start_time = asyncio.get_event_loop().time()
        options = options or {}
        
        try:
            package = options.get('package')
            if not package:
                return ToolResult(
                    tool_name=self.config.name,
                    success=False,
                    error="Package name required for Drozer"
                )
            
            findings = []
            
            # Run all modules
            modules = [
                ("app.package.info", "Package Information"),
                ("app.package.attacksurface", "Attack Surface"),
                ("app.provider.info", "Content Providers"),
                ("app.provider.finduri", "Provider URIs"),
                ("app.activity.info", "Activities"),
                ("app.service.info", "Services"),
                ("app.receiver.info", "Receivers"),
                ("scanner.miscellaneous", "Miscellaneous Scanner"),
                ("scanner.provider.injection", "SQL Injection in Providers"),
                ("scanner.provider.traversal", "Path Traversal in Providers"),
            ]
            
            for module, description in modules:
                result = await self._run_module(package, module)
                if result.get('success'):
                    findings.append({
                        "module": module,
                        "description": description,
                        "data": result.get('output')
                    })
                else:
                    findings.append({
                        "module": module,
                        "description": description,
                        "error": result.get('error')
                    })
            
            # Run custom modules if specified
            custom_modules = options.get('modules', [])
            for module in custom_modules:
                result = await self._run_module(package, module)
                findings.append({
                    "module": module,
                    "custom": True,
                    "data": result.get('output') if result.get('success') else None,
                    "error": result.get('error') if not result.get('success') else None
                })
            
            return ToolResult(
                tool_name=self.config.name,
                success=True,
                findings=findings,
                metadata={
                    "package": package,
                    "modules_run": len(modules) + len(custom_modules)
                },
                execution_time=asyncio.get_event_loop().time() - start_time
            )
            
        except Exception as e:
            logger.error(f"Drozer analysis failed: {e}")
            return ToolResult(
                tool_name=self.config.name,
                success=False,
                error=str(e),
                execution_time=asyncio.get_event_loop().time() - start_time
            )
    
    async def _run_module(self, package: str, module: str) -> Dict:
        """Run a single Drozer module"""
        try:
            cmd = [
                'drozer', 'console', 'connect',
                '-c', f"run {module} {package}"
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=60
            )
            
            output = stdout.decode()
            
            if proc.returncode == 0:
                return {
                    'success': True,
                    'output': self._parse_output(output)
                }
            else:
                return {
                    'success': False,
                    'error': stderr.decode() or output
                }
                
        except asyncio.TimeoutError:
            return {'success': False, 'error': 'Module timed out'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _parse_output(self, output: str) -> List[Dict]:
        """Parse Drozer output into structured findings"""
        findings = []
        
        # Parse different output formats
        lines = output.strip().split('\n')
        current_finding = {}
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Look for key findings
            if any(keyword in line.lower() for keyword in [
                'vulnerable', 'exploit', 'injection', 'traversal',
                'exposed', 'unprotected', 'debuggable', 'backup',
                'allowbackup', 'exported', 'permission'
            ]):
                findings.append({
                    'type': 'security_finding',
                    'description': line,
                    'severity': self._assess_severity(line)
                })
            elif line.startswith('Package:'):
                current_finding['package'] = line.split(':', 1)[1].strip()
            elif line.startswith('Version:'):
                current_finding['version'] = line.split(':', 1)[1].strip()
            elif ':' in line and not line.startswith(' '):
                key, value = line.split(':', 1)
                current_finding[key.strip()] = value.strip()
        
        if current_finding:
            findings.insert(0, {'type': 'package_info', **current_finding})
        
        return findings
    
    def _assess_severity(self, line: str) -> str:
        line_lower = line.lower()
        if any(kw in line_lower for kw in ['critical', 'rce', 'rce', 'sql injection', 'command injection']):
            return 'CRITICAL'
        elif any(kw in line_lower for kw in ['high', 'injection', 'traversal', 'rce']):
            return 'HIGH'
        elif any(kw in line_lower for kw in ['medium', 'exposed', 'unprotected', 'exported']):
            return 'MEDIUM'
        return 'LOW'


# Register
drozer_tool = DrozerIntegration()
tool_registry.register(drozer_tool)