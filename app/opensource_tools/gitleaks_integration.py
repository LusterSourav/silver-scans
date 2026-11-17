"""
GitLeaks Integration - Secrets detection in git repositories
Open source alternative to GitGuardian, GitHub Secret Scanning
"""
import asyncio
import logging
import json
import os
from typing import Dict, List, Optional, Any

from .base import OpenSourceToolBase, ToolConfig, ToolResult, tool_registry

logger = logging.getLogger(__name__)


class GitLeaksIntegration(OpenSourceToolBase):
    """GitLeaks integration for secrets detection in git repos"""
    
    def __init__(self):
        config = ToolConfig(
            name="gitleaks",
            executable="gitleaks",
            args=[],
            install_check="gitleaks version",
            timeout=300
        )
        super().__init__(config)
    
    async def analyze(self, target: str, options: Dict = None) -> ToolResult:
        """Scan target with GitLeaks for secrets"""
        start_time = asyncio.get_event_loop().time()
        options = options or {}
        
        try:
            # Check if target is a git repo
            target_path = Path(target)
            git_dir = target_path / '.git'
            if not git_dir.exists():
                # Try to find git repo
                parent = target_path.parent
                while parent != parent.parent:
                    if (parent / '.git').exists():
                        target = str(parent)
                        break
                    parent = parent.parent
            
            cmd = ['gitleaks', 'detect', '--source', target]
            
            # Output format
            cmd.extend(['--report-format', 'json'])
            
            # Config file
            if options.get('config'):
                cmd.extend(['--config', options['config']])
            
            # Verbose
            if options.get('verbose'):
                cmd.append('-v')
            
            # No banner
            cmd.append('--no-banner')
            
            # Exit code
            cmd.append('--exit-code')
            cmd.append('0')  # Don't fail on findings
            
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
                # GitLeaks outputs JSON array
                data = json.loads(output)
                
                if isinstance(data, list):
                    for leak in data:
                        findings.append({
                            "type": "secret",
                            "rule_id": leak.get('RuleID'),
                            "description": leak.get('Description'),
                            "file": leak.get('File'),
                            "line": leak.get('StartLine'),
                            "commit": leak.get('Commit'),
                            "commit_hash": leak.get('CommitHash'),
                            "author": leak.get('Author'),
                            "email": leak.get('Email'),
                            "date": leak.get('Date'),
                            "secret": leak.get('Secret'),
                            "entropy": leak.get('Entropy'),
                            "rule": leak.get('Rule'),
                            "tags": leak.get('Tags', [])
                        })
                        
            except json.JSONDecodeError:
                # Parse text output
                for line in output.strip().split('\n'):
                    if line.strip() and 'leak' in line.lower():
                        findings.append({
                            "type": "secret",
                            "raw": line
                        })
            
            return ToolResult(
                tool_name=self.config.name,
                success=True,
                findings=findings,
                metadata={
                    "target": target,
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
            logger.error(f"GitLeaks scan failed: {e}")
            return ToolResult(
                tool_name=self.config.name,
                success=False,
                error=str(e),
                execution_time=asyncio.get_event_loop().time() - start_time
            )


# Register
gitleaks_tool = GitLeaksIntegration()
tool_registry.register(gitleaks_tool)