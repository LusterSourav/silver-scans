"""
JADX Integration - Java/Dex decompiler
Open source alternative to JEB, IDA Pro for Android
"""
import asyncio
import logging
import json
import os
import tempfile
from typing import Dict, List, Optional, Any
from pathlib import Path

from .base import OpenSourceToolBase, ToolConfig, ToolResult, tool_registry

logger = logging.getLogger(__name__)


class JADXIntegration(OpenSourceToolBase):
    """JADX integration for Android decompilation"""
    
    def __init__(self):
        config = ToolConfig(
            name="jadx",
            executable="jadx",
            args=[],
            install_check="jadx --version",
            timeout=300
        )
        super().__init__(config)
    
    async def analyze(self, target: str, options: Dict = None) -> ToolResult:
        """Decompile APK/AAR/JAR with JADX"""
        start_time = asyncio.get_event_loop().time()
        options = options or {}
        
        try:
            # Create output directory
            with tempfile.TemporaryDirectory() as output_dir:
                cmd = ['jadx', target]
                
                # Output directory
                cmd.extend(['-d', output_dir])
                
                # Options
                if options.get('no_res', True):
                    cmd.append('--no-res')
                if options.get('no_debug', True):
                    cmd.append('--no-debug-info')
                if options.get('show_bad_code', True):
                    cmd.append('--show-bad-code')
                if options.get('threads'):
                    cmd.extend(['-j', str(options['threads'])])
                
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.config.timeout
                )
                
                if proc.returncode != 0:
                    return ToolResult(
                        tool_name=self.config.name,
                        success=False,
                        error=stderr.decode() or stdout.decode()
                    )
                
                # Parse decompiled output
                findings = await self._parse_decompiled(output_dir, options)
                
                return ToolResult(
                    tool_name=self.config.name,
                    success=True,
                    findings=findings,
                    metadata={
                        "target": target,
                        "output_dir": output_dir,
                        "decompiled_files": findings
                    },
                    execution_time=asyncio.get_event_loop().time() - start_time
                )
            
        except asyncio.TimeoutError:
            return ToolResult(
                tool_name=self.config.name,
                success=False,
                error="Decompilation timed out",
                execution_time=asyncio.get_event_loop().time() - start_time
            )
        except Exception as e:
            logger.error(f"JADX decompilation failed: {e}")
            return ToolResult(
                tool_name=self.config.name,
                success=False,
                error=str(e),
                execution_time=asyncio.get_event_loop().time() - start_time
            )
    
    async def _parse_decompiled(self, output_dir: str, options: Dict) -> List[Dict]:
        """Parse decompiled output for analysis"""
        findings = []
        output_path = Path(output_dir)
        
        # Count decompiled files
        java_files = list(output_path.rglob('*.java'))
        class_files = list(output_dir.rglob('*.class'))
        
        findings.append({
            "type": "decompilation_summary",
            "java_files": len(java_files),
            "class_files": len(class_files),
            "output_dir": output_dir
        })
        
        # Analyze source files for security issues
        for java_file in java_files[:100]:  # Limit to first 100
            try:
                content = java_file.read_text(encoding='utf-8', errors='ignore')
                issues = self._analyze_java_code(content, str(java_file))
                if issues:
                    findings.extend(issues)
            except Exception:
                pass
        
        return findings
    
    def _analyze_java_code(self, content: str, file_path: str) -> List[Dict]:
        """Analyze Java code for security issues"""
        issues = []
        lines = content.split('\n')
        
        # Patterns to detect
        patterns = {
            'hardcoded_secret': [
                r'password\s*=\s*["\'][^"\']+["\']',
                r'api[_-]?key\s*=\s*["\'][^"\']+["\']',
                r'secret\s*=\s*["\'][^"\']+["\']',
                r'token\s*=\s*["\'][^"\']+["\']',
            ],
            'sql_injection': [
                r'executeQuery\s*\(\s*["\'].*\+',
                r'executeUpdate\s*\(\s*["\'].*\+',
                r'Statement.*executeQuery',
            ],
            'weak_crypto': [
                r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']',
                r'MessageDigest\.getInstance\s*\(\s*["\']SHA1["\']',
                r'Cipher\.getInstance\s*\(\s*["\']DES',
                r'Cipher\.getInstance\s*\(\s*["\']RC4',
            ],
            'insecure_random': [
                r'new Random\(\)',
                r'Math\.random\(\)',
            ],
            'logging_sensitive': [
                r'Log\.(d|i|w|e|v)\s*\([^)]*password',
                r'Log\.(d|i|w|e|v)\s*\([^)]*token',
                r'System\.out\.print.*password',
            ],
            'webview_insecure': [
                r'setJavaScriptEnabled\s*\(\s*true\s*\)',
                r'setAllowFileAccess\s*\(\s*true\s*\)',
                r'setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)',
            ]
        }
        
        for issue_type, regexes in patterns.items():
            for regex in regexes:
                for i, line in enumerate(lines, 1):
                    import re
                    if re.search(regex, line, re.IGNORECASE):
                        issues.append({
                            "type": "code_issue",
                            "category": issue_type,
                            "file": file_path,
                            "line": i,
                            "code": line.strip()[:200],
                            "severity": self._assess_severity(issue_type)
                        })
        
        return issues
    
    def _assess_severity(self, issue_type: str) -> str:
        severity_map = {
            'hardcoded_secret': 'HIGH',
            'sql_injection': 'CRITICAL',
            'weak_crypto': 'HIGH',
            'insecure_random': 'MEDIUM',
            'logging_sensitive': 'HIGH',
            'webview_insecure': 'HIGH'
        }
        return severity_map.get(issue_type, 'LOW')


# Register
jadx_tool = JADXIntegration()
tool_registry.register(jadx_tool)