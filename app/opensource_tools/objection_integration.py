"""
Objection Integration - Runtime mobile exploration
Open source alternative to NowSecure runtime analysis
"""
import asyncio
import logging
import json
import tempfile
import os
from typing import Dict, List, Optional, Any

from .base import OpenSourceToolBase, ToolConfig, ToolResult, tool_registry

logger = logging.getLogger(__name__)


class ObjectionIntegration(OpenSourceToolBase):
    """Objection integration for runtime mobile exploration"""
    
    def __init__(self):
        config = ToolConfig(
            name="objection",
            executable="objection",
            args=[],
            install_check="objection --version",
            timeout=300
        )
        super().__init__(config)
    
    async def analyze(self, target: str, options: Dict = None) -> ToolResult:
        """Run Objection analysis on target package"""
        start_time = asyncio.get_event_loop().time()
        options = options or {}
        
        try:
            package = options.get('package')
            if not package:
                return ToolResult(
                    tool_name=self.config.name,
                    success=False,
                    error="Package name required for Objection"
                )
            
            findings = []
            
            # Run all exploration commands
            commands = [
                ("env", "Environment Information"),
                ("hooking list classes", "Hookable Classes"),
                ("hooking list class_methods", "Class Methods"),
                ("storage sharedprefs list", "SharedPreferences"),
                ("storage sqlite list", "SQLite Databases"),
                ("storage keychain list", "Keychain Items"),
                ("filesystem ls /", "Filesystem Root"),
                ("network urls", "Network URLs"),
                ("network endpoints", "Network Endpoints"),
                ("crypto cipher list", "Cipher Usage"),
                ("crypto hash list", "Hash Usage"),
                ("crypto certificate list", "Certificates"),
                ("social media list", "Social Media"),
                ("browser history list", "Browser History"),
                ("gps locations list", "GPS Locations"),
            ]
            
            for cmd, description in commands:
                result = await self._run_command(package, cmd)
                if result.get('success'):
                    findings.append({
                        "command": cmd,
                        "description": description,
                        "data": result.get('output')
                    })
                else:
                    findings.append({
                        "command": cmd,
                        "description": description,
                        "error": result.get('error')
                    })
            
            # Run custom commands
            custom_commands = options.get('commands', [])
            for cmd in custom_commands:
                result = await self._run_command(package, cmd)
                findings.append({
                    "command": cmd,
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
                    "commands_run": len(commands) + len(custom_commands)
                },
                execution_time=asyncio.get_event_loop().time() - start_time
            )
            
        except Exception as e:
            logger.error(f"Objection analysis failed: {e}")
            return ToolResult(
                tool_name=self.config.name,
                success=False,
                error=str(e),
                execution_time=asyncio.get_event_loop().time() - start_time
            )
    
    async def _run_command(self, package: str, command: str) -> Dict:
        """Run a single Objection command"""
        try:
            cmd = [
                'objection', '-g', package, 'explore', '-q', command
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
            return {'success': False, 'error': 'Command timed out'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _parse_output(self, output: str) -> List[Dict]:
        """Parse Objection output"""
        findings = []
        
        try:
            # Try to parse as JSON first
            data = json.loads(output)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                return [data]
        except json.JSONDecodeError:
            pass
        
        # Parse text output
        lines = output.strip().split('\n')
        for line in lines:
            line = line.strip()
            if line:
                findings.append({"raw": line})
        
        return findings


# Register
objection_tool = ObjectionIntegration()
tool_registry.register(objection_tool)