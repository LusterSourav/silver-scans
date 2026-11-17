"""
Radare2 Integration - Reverse engineering framework
Open source alternative to IDA Pro, Ghidra (complementary)
"""
import asyncio
import logging
import json
import os
from typing import Dict, List, Optional, Any

from .base import OpenSourceToolBase, ToolConfig, ToolResult, tool_registry

logger = logging.getLogger(__name__)


class Radare2Integration(OpenSourceToolBase):
    """Radare2 integration for reverse engineering"""
    
    def __init__(self):
        config = ToolConfig(
            name="radare2",
            executable="r2",
            args=[],
            install_check="r2 -version",
            timeout=300
        )
        super().__init__(config)
    
    async def analyze(self, target: str, options: Dict = None) -> ToolResult:
        """Analyze target with Radare2"""
        start_time = asyncio.get_event_loop().time()
        options = options or {}
        
        try:
            findings = []
            
            # Basic info
            info_result = await self._run_r2_command(target, 'ij')
            if info_result.get('success'):
                info = info_result.get('output', {})
                findings.append({
                    "type": "binary_info",
                    "arch": info.get('bin', {}).get('arch'),
                    "bits": info.get('bin', {}).get('bits'),
                    "os": info.get('bin', {}).get('os'),
                    "type": info.get('bin', {}).get('type'),
                    "machine": info.get('bin', {}).get('machine'),
                    "class": info.get('bin', {}).get('class'),
                    "endian": info.get('bin', {}).get('endian'),
                    "stripped": info.get('bin', {}).get('stripped'),
                    "static": info.get('bin', {}).get('static'),
                    "pic": info.get('bin', {}).get('pic'),
                    "canary": info.get('bin', {}).get('canary'),
                    "nx": info.get('bin', {}).get('nx'),
                    "crypto": info.get('bin', {}).get('crypto'),
                    "va": info.get('bin', {}).get('va')
                })
            
            # Sections
            sections_result = await self._run_r2_command(target, 'iSj')
            if sections_result.get('success'):
                sections = sections_result.get('output', [])
                findings.append({
                    "type": "sections",
                    "count": len(sections),
                    "sections": sections
                })
            
            # Symbols
            symbols_result = await self._run_r2_command(target, 'isj')
            if symbols_result.get('success'):
                symbols = symbols_result.get('output', [])
                findings.append({
                    "type": "symbols",
                    "count": len(symbols),
                    "symbols": symbols[:100]  # Limit
                })
            
            # Imports
            imports_result = await self._run_r2_command(target, 'iij')
            if imports_result.get('success'):
                imports = imports_result.get('output', [])
                findings.append({
                    "type": "imports",
                    "count": len(imports),
                    "imports": imports[:100]
                })
            
            # Strings
            strings_result = await self._run_r2_command(target, 'izj')
            if strings_result.get('success'):
                strings = strings_result.get('output', [])
                findings.append({
                    "type": "strings",
                    "count": len(strings),
                    "strings": strings[:200]
                })
            
            # Functions
            functions_result = await self._run_r2_command(target, 'aflj')
            if functions_result.get('success'):
                functions = functions_result.get('output', [])
                findings.append({
                    "type": "functions",
                    "count": len(functions),
                    "functions": functions[:100]
                })
            
            # Entrypoints
            entry_result = await self._run_r2_command(target, 'iej')
            if entry_result.get('success'):
                entries = entry_result.get('output', [])
                findings.append({
                    "type": "entrypoints",
                    "entries": entries
                })
            
            # Relocations
            reloc_result = await self._run_r2_command(target, 'irj')
            if reloc_result.get('success'):
                relocs = reloc_result.get('output', [])
                findings.append({
                    "type": "relocations",
                    "count": len(relocs),
                    "relocations": relocs[:50]
                })
            
            # Relocations (PLT/GOT)
            plt_result = await self._run_r2_command(target, 'iIj')
            if plt_result.get('success'):
                plt = plt_result.get('output', [])
                findings.append({
                    "type": "plt_got",
                    "entries": plt
                })
            
            # Sections permissions
            perm_result = await self._run_r2_command(target, 'iMj')
            if perm_result.get('success'):
                perms = perm_result.get('output', [])
                findings.append({
                    "type": "permissions",
                    "sections": perms
                })
            
            # Security checks
            security_findings = await self._security_checks(target)
            findings.extend(security_findings)
            
            return ToolResult(
                tool_name=self.config.name,
                success=True,
                findings=findings,
                metadata={
                    "target": target
                },
                execution_time=asyncio.get_event_loop().time() - start_time
            )
            
        except Exception as e:
            logger.error(f"Radare2 analysis failed: {e}")
            return ToolResult(
                tool_name=self.config.name,
                success=False,
                error=str(e),
                execution_time=asyncio.get_event_loop().time() - start_time
            )
    
    async def _run_r2_command(self, target: str, command: str) -> Dict:
        """Run a single r2 command and return JSON output"""
        try:
            cmd = ['r2', '-q', '-c', command, target]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=60
            )
            
            if proc.returncode == 0:
                try:
                    return {
                        'success': True,
                        'output': json.loads(stdout.decode())
                    }
                except json.JSONDecodeError:
                    return {
                        'success': True,
                        'output': stdout.decode()
                    }
            else:
                return {
                    'success': False,
                    'error': stderr.decode()
                }
                
        except asyncio.TimeoutError:
            return {'success': False, 'error': 'Command timed out'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _security_checks(self, target: str) -> List[Dict]:
        """Run security-specific checks"""
        findings = []
        
        # Check for stack canaries
        canary_result = await self._run_r2_command(target, 'iIj')
        if canary_result.get('success'):
            pass  # Already checked in binary info
        
        # Search for crypto constants
        crypto_result = await self._run_r2_command(target, '/c MD5,SHA1,SHA256,AES,DES,RC4')
        if crypto_result.get('success'):
            output = crypto_result.get('output', '')
            if output:
                findings.append({
                    "type": "crypto_constants",
                    "found": True,
                    "details": output[:1000]
                })
        
        # Search for suspicious strings
        suspicious_strings = [
            'password', 'secret', 'key', 'token', 'api_key',
            'private_key', 'secret_key', 'access_token'
        ]
        
        string_result = await self._run_r2_command(target, 'izj')
        if string_result.get('success'):
            strings = string_result.get('output', [])
            for s in strings:
                value = s.get('string', '').lower()
                for keyword in ['password', 'secret', 'key', 'token', 'api']:
                    if keyword in value:
                        findings.append({
                            "type": "sensitive_string",
                            "string": s.get('string', '')[:100],
                            "address": s.get('vaddr'),
                            "keyword": keyword,
                            "severity": "HIGH"
                        })
                        break
        
        return findings


# Register
radare2_tool = Radare2Integration()
tool_registry.register(radare2_tool)