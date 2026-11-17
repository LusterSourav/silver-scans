"""
TruffleHog Integration - Secrets detection
Open source alternative to GitGuardian, GitHub Secret Scanning
"""
import asyncio
import logging
import json
from typing import Dict, List, Optional, Any

from .base import OpenSourceToolBase, ToolConfig, ToolResult, tool_registry

logger = logging.getLogger(__name__)


class TruffleHogIntegration(OpenSourceToolBase):
    """TruffleHog integration for secrets detection"""
    
    def __init__(self):
        config = ToolConfig(
            name="trufflehog",
            executable="trufflehog",
            args=[],
            install_check="trufflehog --version",
            timeout=300
        )
        super().__init__(config)
    
    async def analyze(self, target: str, options: Dict = None) -> ToolResult:
        """Scan target with TruffleHog for secrets"""
        start_time = asyncio.get_event_loop().time()
        options = options or {}
        
        try:
            cmd = ['trufflehog', 'filesystem', target]
            
            # Output format
            cmd.extend(['--json'])
            
            # Concurrency
            if options.get('concurrency'):
                cmd.extend(['--concurrency', str(options['concurrency'])])
            
            # Max depth
            if options.get('max_depth'):
                cmd.extend(['--max-depth', str(options['max_depth'])])
            
            # Include paths
            if options.get('include_paths'):
                for path in options['include_paths']:
                    cmd.extend(['--include-paths', path])
            
            # Exclude paths
            if options.get('exclude_paths'):
                for path in options['exclude_paths']:
                    cmd.extend(['--exclude-paths', path])
            
            # No verification (faster)
            if options.get('no_verification', False):
                cmd.append('--no-verification')
            
            # Only verified
            if options.get('only_verified', False):
                cmd.append('--only-verified')
            
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
            
            for line in output.strip().split('\n'):
                if line.strip():
                    try:
                        data = json.loads(line)
                        
                        # Extract key information
                        finding = {
                            "type": "secret",
                            "detector": data.get('DetectorType'),
                            "decoder": data.get('Decoder'),
                            "verified": data.get('Verified', False),
                            "file": data.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file'),
                            "line": data.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('line'),
                            "commit": data.get('SourceMetadata', {}).get('Data', {}).get('Git', {}).get('commit'),
                            "author": data.get('SourceMetadata', {}).get('Data', {}).get('Git', {}).get('author'),
                            "email": data.get('SourceMetadata', {}).get('Data', {}).get('Git', {}).get('email'),
                            "date": data.get('SourceMetadata', {}).get('Data', {}).get('Git', {}).get('date'),
                            "raw": data.get('Raw'),
                            "redacted": data.get('Redacted')
                        }
                        
                        findings.append(finding)
                        
                    except json.JSONDecodeError:
                        continue
            
            return ToolResult(
                tool_name=self.config.name,
                success=True,
                findings=findings,
                metadata={
                    "target": target,
                    "secrets_found": len(findings),
                    "verified_count": sum(1 for f in findings if f.get('verified'))
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
            logger.error(f"TruffleHog scan failed: {e}")
            return ToolResult(
                tool_name=self.config.name,
                success=False,
                error=str(e),
                execution_time=asyncio.get_event_loop().time() - start_time
            )


# Register
trufflehog_tool = TruffleHogIntegration()
tool_registry.register(trufflehog_tool)