"""
YARA Integration - Pattern matching for malware detection
Open source alternative to commercial AV signatures
"""
import asyncio
import logging
import json
import tempfile
import os
from typing import Dict, List, Optional, Any
from pathlib import Path

from .base import OpenSourceToolBase, ToolConfig, ToolResult, tool_registry

logger = logging.getLogger(__name__)


class YARAIntegration(OpenSourceToolBase):
    """YARA integration for pattern matching and malware detection"""
    
    def __init__(self, rules_dir: str = "/app/rules"):
        config = ToolConfig(
            name="yara",
            executable="yara",
            args=[],
            install_check="yara --version",
            timeout=300
        )
        super().__init__(config)
        self.rules_dir = Path(rules_dir)
        self.rules_dir.mkdir(exist_ok=True)
        self._create_builtin_rules()
    
    def _create_builtin_rules(self):
        """Create built-in YARA rules for common threats"""
        rules = {
            "mobile_malware.yar": """
rule Android_Malware_Generic {
    meta:
        description = "Generic Android malware indicators"
        author = "Silver Scan"
        severity = "high"
    strings:
        $su_binary = "su" ascii wide
        $superuser = "Superuser" ascii wide
        $busybox = "busybox" ascii wide
        $root_check = "root" ascii wide nocase
        $shell = "/system/bin/sh" ascii wide
        $chmod = "chmod" ascii wide
        $chown = "chown" ascii wide
        $mount = "mount" ascii wide
        $reboot = "reboot" ascii wide
    condition:
        3 of them
}

rule Android_Banking_Trojan {
    meta:
        description = "Android banking trojan indicators"
        author = "Silver Scan"
        severity = "critical"
    strings:
        $overlay = "overlay" ascii wide nocase
        $accessibility = "accessibility" ascii wide nocase
        $device_admin = "device_admin" ascii wide nocase
        $sms_intercept = "sms" ascii wide nocase
        $ussd = "ussd" ascii wide nocase
        $keylogger = "keylogger" ascii wide nocase
    condition:
        2 of them
    }

rule Android_Spyware {
    meta:
        description = "Android spyware indicators"
        author = "Silver Scan"
        severity = "critical"
    strings:
        $location = "location" ascii wide nocase
        $gps = "gps" ascii wide nocase
        $contacts = "contacts" ascii wide nocase
        $call_log = "call_log" ascii wide nocase
        $record_audio = "record_audio" ascii wide nocase
        $camera = "camera" ascii wide nocase
        $upload = "upload" ascii wide nocase
    condition:
        3 of them
    }

rule Android_Ransomware {
    meta:
        description = "Android ransomware indicators"
        author = "Silver Scan"
        severity = "critical"
    strings:
        $encrypt = "encrypt" ascii wide nocase
        $decrypt = "decrypt" ascii wide nocase
        $ransom = "ransom" ascii wide nocase
        $bitcoin = "bitcoin" ascii wide nocase
        $payment = "payment" ascii wide nocase
        $lock = "lock" ascii wide nocase
    condition:
        2 of them
    }
""",
            "suspicious_network.yar": """
rule Suspicious_Network_Activity {
    meta:
        description = "Suspicious network communication patterns"
        author = "Silver Scan"
        severity = "high"
    strings:
        $http_raw = "http://" ascii wide nocase
        $https_raw = "https://" ascii wide nocase
        $ip_raw = /\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/
        $dns_tunnel = "dns" ascii wide nocase
        $tor = "tor" ascii wide nocase
        $proxy = "proxy" ascii wide nocase
        $vpn = "vpn" ascii wide nocase
        $c2 = "c2" ascii wide nocase
        $beacon = "beacon" ascii wide nocase
    condition:
        2 of them
    }

rule Suspicious_DNS {
    meta:
        description = "Suspicious DNS activity"
        author = "Silver Scan"
        severity = "medium"
    strings:
        $dga = /[a-z0-9]{20,}\\.(com|net|org|info|biz)/
        $fast_flux = "fast-flux" ascii wide nocase
        $domain_gen = "domain.generation" ascii wide nocase
    condition:
        any of them
    }
""",
            "crypto_weaknesses.yar": """
rule Weak_Cryptography {
    meta:
        description = "Weak cryptographic algorithms and implementations"
        author = "Silver Scan"
        severity = "high"
    strings:
        $md5 = "MD5" ascii wide nocase
        $sha1 = "SHA1" ascii wide nocase
        $des = "DES" ascii wide nocase
        $rc4 = "RC4" ascii wide nocase
        $rc2 = "RC2" ascii wide nocase
        $ecb = "ECB" ascii wide nocase
        $md5_init = "MD5_Init" ascii wide
        $sha1_init = "SHA1_Init" ascii wide
        $des_ede = "DES_ede" ascii wide
        $rc4_set_key = "RC4_set_key" ascii wide
    condition:
        any of them
    }

rule Hardcoded_Keys {
    meta:
        description = "Hardcoded cryptographic keys"
        author = "Silver Scan"
        severity = "critical"
    strings:
        $api_key = /(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\\s*[:=]\\s*["'][a-zA-Z0-9+/=]{20,}["']/
        $private_key = /-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----/
        $aws_key = /AKIA[0-9A-Z]{16}/
        $jwt = /eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+/
    condition:
        any of them
    }
""",
            "android_specific.yar": """
rule Android_Exported_Components {
    meta:
        description = "Exported Android components without permission"
        author = "Silver Scan"
        severity = "medium"
    strings:
        $exported = "android:exported=\"true\"" ascii wide
        $no_permission = "android:permission" ascii wide
    condition:
        $exported and not $no_permission
    }

rule Android_Debuggable {
    meta:
        description = "Debuggable application"
        author = "Silver Scan"
        severity = "high"
    strings:
        $debuggable = "android:debuggable=\"true\"" ascii wide
    condition:
        $debuggable
    }

rule Android_Backup_Allowed {
    meta:
        description = "Application allows backup"
        author = "Silver Scan"
        severity = "medium"
    strings:
        $backup = "android:allowBackup=\"true\"" ascii wide
    condition:
        $backup
    }

rule Android_Clear_Text_Traffic {
    meta:
        description = "Clear text traffic allowed"
        author = "Silver Scan"
        severity = "high"
    strings:
        $cleartext = "android:usesCleartextTraffic=\"true\"" ascii wide
    condition:
        $cleartext
    }

rule Android_Network_Security_Config {
    meta:
        description = "Missing network security config"
        author = "Silver Scan"
        severity = "medium"
    strings:
        $network_config = "android:networkSecurityConfig" ascii wide
    condition:
        not $network_config
    }
""",
        }
        
        for name, content in rules.items():
            rule_path = self.rules_dir / name
            if not rule_path.exists():
                rule_path.write_text(content)
    
    async def analyze(self, target: str, options: Dict = None) -> ToolResult:
        """Scan target with YARA rules"""
        start_time = asyncio.get_event_loop().time()
        options = options or {}
        
        try:
            # Collect rule files
            rule_files = options.get('rules', list(self.rules_dir.glob('*.yar')))
            if isinstance(rule_files, str):
                rule_files = [rule_files]
            
            cmd = ['yara']
            
            # Add rule files
            for rule_file in rule_files:
                cmd.extend(['-r', str(rule_file)])
            
            # Output format
            cmd.extend(['-w'])  # Show metadata
            cmd.extend(['-f'])  # Fast matching
            
            # Output format
            if options.get('json', True):
                cmd.extend(['-j'])
            
            # Target
            cmd.append(target)
            
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
            
            if options.get('json', True):
                for line in output.strip().split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            findings.append({
                                "type": "yara_match",
                                "rule": data.get('rule'),
                                "namespace": data.get('namespace'),
                                "tags": data.get('tags', []),
                                "meta": data.get('meta', {}),
                                "strings": data.get('strings', []),
                                "file": target
                            })
                        except json.JSONDecodeError:
                            pass
            
            # Also parse text output
            if not findings:
                for line in output.strip().split('\n'):
                    if line.strip() and not line.startswith('{'):
                        parts = line.split(' ', 2)
                        if len(parts) >= 2:
                            findings.append({
                                "type": "yara_match",
                                "rule": parts[0],
                                "file": parts[1] if len(parts) > 1 else target,
                                "raw": line
                            })
            
            return ToolResult(
                tool_name=self.config.name,
                success=True,
                findings=findings,
                metadata={
                    "target": target,
                    "rules_used": [str(f) for f in rule_files],
                    "matches": len(findings)
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
            logger.error(f"YARA scan failed: {e}")
            return ToolResult(
                tool_name=self.config.name,
                success=False,
                error=str(e),
                execution_time=asyncio.get_event_loop().time() - start_time
            )


# Register
yara_tool = YARAIntegration()
tool_registry.register(yara_tool)