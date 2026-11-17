"""
detect-secrets Integration - Secrets detection baseline
Open source alternative to GitGuardian, TruffleHog
"""
import asyncio
import logging
import json
import os
from typing import Dict, List, Optional, Any

from .base import OpenSourceToolBase, ToolConfig, ToolResult, tool_registry

logger = logging.getLogger(__name__)


class DetectSecretsIntegration(OpenSourceToolBase):
    """detect-secrets integration for secrets baseline scanning"""
    
    def __init__(self):
        config = ToolConfig(
            name="detect-secrets",
            executable="detect-secrets",
            args=[],
            install_check="detect-secrets --version",
            timeout=300
        )
        super().__init__(config)
    
    async def analyze(self, target: str, options: Dict = None) -> ToolResult:
        """Scan target with detect-secrets"""
        start_time = asyncio.get_event_loop().time()
        options = options or {}
        
        try:
            # Create baseline
            baseline_file = options.get('baseline', '.secrets.baseline')
            
            cmd = ['detect-secrets', 'scan', target]
            
            # Output format
            cmd.extend(['--format', 'json'])
            
            # Baseline
            cmd.extend(['--baseline', baseline_file])
            
            # Force all files
            if options.get('all_files'):
                cmd.append('--all-files')
            
            # Plugins
            if options.get('plugins'):
                for plugin in options['plugins']:
                    cmd.extend(['--plugin', plugin])
            
            # Disable plugins
            if options.get('disable_plugins'):
                for plugin in options['disable_plugins']:
                    cmd.extend(['--disable-plugin', plugin])
            
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
                return ToolResult(
                    tool_name=self.config.name,
                    success=False,
                    error=stderr.decode() or stdout.decode()
                )
            
            # Parse findings
            findings = []
            output = stdout.decode()
            
            try:
                data = json.loads(output)
                results = data.get('results', {})
                
                for file_path, secrets in results.items():
                    for secret in secrets:
                        findings.append({
                            "type": "secret",
                            "file": file_path,
                            "line": secret.get('line_number'),
                            "type": secret.get('type'),
                            "hashed_secret": secret.get('hashed_secret'),
                            "is_verified": secret.get('is_verified', False)
                        })
                        
            except json.JSONDecodeError:
                pass
            
            # Also audit baseline
            audit_cmd = ['detect-secrets', 'audit', baseline_file]
            proc = await asyncio.create_subprocess_exec(
                *audit_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            return ToolResult(
                tool_name=self.config.name,
                success=True,
                findings=findings,
                metadata={
                    "target": target,
                    "baseline_file": baseline_file,
                    "secrets_found": len(findings)
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
            logger.error(f"detect-secrets scan failed: {e}")
            return ToolResult(
                tool_name=self.config.name,
                success=False,
                error=str(e),
                execution_time=asyncio.get_event_loop().time() - start_time
            )


# Register
detect_secrets_tool = DetectSecretsIntegration()
tool_registry.register(detect_secrets_tool)