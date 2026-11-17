"""
Apktool Integration - Android APK reverse engineering
Open source alternative to commercial APK analyzers
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


class ApktoolIntegration(OpenSourceToolBase):
    """Apktool integration for APK reverse engineering"""
    
    def __init__(self):
        config = ToolConfig(
            name="apktool",
            executable="apktool",
            args=[],
            install_check="apktool -version",
            timeout=300
        )
        super().__init__(config)
    
    async def analyze(self, target: str, options: Dict = None) -> ToolResult:
        """Analyze APK with Apktool"""
        start_time = asyncio.get_event_loop().time()
        options = options or {}
        
        try:
            with tempfile.TemporaryDirectory() as output_dir:
                cmd = ['apktool', 'd', target]
                
                # Output directory
                cmd.extend(['-o', output_dir])
                
                # Force
                cmd.append('-f')
                
                # Keep broken resources
                if options.get('keep_broken', True):
                    cmd.append('-r')
                
                # No src
                if options.get('no_src', False):
                    cmd.append('-s')
                
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
                
                # Parse output
                findings = await self._analyze_output(output_dir, options)
                
                return ToolResult(
                    tool_name=self.config.name,
                    success=True,
                    findings=findings,
                    metadata={
                        "target": target,
                        "output_dir": output_dir
                    },
                    execution_time=asyncio.get_event_loop().time() - start_time
                )
            
        except asyncio.TimeoutError:
            return ToolResult(
                tool_name=self.config.name,
                success=False,
                error="Decoding timed out",
                execution_time=asyncio.get_event_loop().time() - start_time
            )
        except Exception as e:
            logger.error(f"Apktool analysis failed: {e}")
            return ToolResult(
                tool_name=self.config.name,
                success=False,
                error=str(e),
                execution_time=asyncio.get_event_loop().time() - start_time
            )
    
    async def _analyze_output(self, output_dir: str, options: Dict) -> List[Dict]:
        """Analyze decoded APK output"""
        findings = []
        output_path = Path(output_dir)
        
        # AndroidManifest.xml
        manifest_path = output_path / 'AndroidManifest.xml'
        if manifest_path.exists():
            manifest_findings = await self._analyze_manifest(manifest_path)
            findings.extend(manifest_findings)
        
        # Resources
        res_path = output_path / 'res'
        if res_path.exists():
            resource_findings = await self._analyze_resources(res_path)
            findings.extend(resource_findings)
        
        # Smali code
        smali_dirs = list(output_path.glob('smali*'))
        for smali_dir in smali_dirs:
            smali_findings = await self._analyze_smali(smali_dir)
            findings.extend(smali_findings)
        
        # Assets
        assets_path = output_path / 'assets'
        if assets_path.exists():
            asset_findings = await self._analyze_assets(assets_path)
            findings.extend(asset_findings)
        
        return findings
    
    async def _analyze_manifest(self, manifest_path: Path) -> List[Dict]:
        """Analyze AndroidManifest.xml"""
        findings = []
        
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            # Check permissions
            for perm in root.findall('.//uses-permission'):
                name = perm.get('{http://schemas.android.com/apk/res/android}name')
                if name:
                    findings.append({
                        "type": "permission",
                        "name": name,
                        "risk": self._assess_permission_risk(name)
                    })
            
            # Check application attributes
            app = root.find('application')
            if app is not None:
                # Debuggable
                debuggable = app.get('{http://schemas.android.com/apk/res/android}debuggable')
                if debuggable == 'true':
                    findings.append({
                        "type": "manifest_issue",
                        "issue": "debuggable",
                        "description": "Application is debuggable in production",
                        "severity": "HIGH"
                    })
                
                # Allow backup
                allow_backup = app.get('{http://schemas.android.com/apk/res/android}allowBackup')
                if allow_backup == 'true':
                    findings.append({
                        "type": "manifest_issue",
                        "issue": "allowBackup",
                        "description": "Application allows backup",
                        "severity": "MEDIUM"
                    })
                
                # Network security config
                network_config = app.get('{http://schemas.android.com/apk/res/android}networkSecurityConfig')
                if not network_config:
                    findings.append({
                        "type": "manifest_issue",
                        "issue": "missing_network_security_config",
                        "description": "No network security configuration defined",
                        "severity": "MEDIUM"
                    })
                
                # Exported components
                for comp_type in ['activity', 'service', 'receiver', 'provider']:
                    for comp in root.findall(f'.//{comp_type}'):
                        exported = comp.get('{http://schemas.android.com/apk/res/android}exported')
                        if exported == 'true':
                            name = comp.get('{http://schemas.android.com/apk/res/android}name')
                            findings.append({
                                "type": "exported_component",
                                "component_type": comp_type,
                                "name": name,
                                "severity": "MEDIUM"
                            })
                        
        except Exception as e:
            logger.warning(f"Manifest analysis failed: {e}")
        
        return findings
    
    async def _analyze_resources(self, res_path: Path) -> List[Dict]:
        """Analyze resources"""
        findings = []
        
        # Check for hardcoded strings in strings.xml
        strings_path = res_path / 'values' / 'strings.xml'
        if strings_path.exists():
            try:
                import xml.etree.ElementTree as ET
                tree = ET.parse(strings_path)
                root = tree.getroot()
                
                for string in root.findall('string'):
                    name = string.get('name')
                    value = string.text
                    if value:
                        # Check for sensitive data
                        if any(keyword in name.lower() for keyword in 
                               ['password', 'secret', 'key', 'token', 'api', 'auth']):
                            findings.append({
                                "type": "hardcoded_string",
                                "name": name,
                                "value": string.text[:100],
                                "severity": "HIGH"
                            })
            except Exception:
                pass
        
        return findings
    
    async def _analyze_smali(self, smali_dir: Path) -> List[Dict]:
        """Analyze smali code"""
        findings = []
        
        # Quick scan for suspicious patterns
        smali_files = list(smali_dir.rglob('*.smali'))
        
        suspicious_patterns = {
            'crypto_weak': [
                r'Ljavax/crypto/Cipher;->getInstance.*DES',
                r'Ljavax/crypto/Cipher;->getInstance.*RC4',
                r'Ljava/security/MessageDigest;->getInstance.*MD5',
                r'Ljava/security/MessageDigest;->getInstance.*SHA1',
            ],
            'insecure_random': [
                r'Ljava/util/Random;-><init>',
                r'Ljava/lang/Math;->random',
            ],
            'webview_insecure': [
                r'Landroid/webkit/WebSettings;->setJavaScriptEnabled.*1',
                r'Landroid/webkit/WebSettings;->setAllowFileAccess.*1',
                r'Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs.*1',
            ],
            'logging': [
                r'Landroid/util/Log;->[vdiwe]',
                r'Ljava/lang/System;->out',
            ],
            'ssl_bypass': [
                r'Ljavax/net/ssl/TrustManager;->checkServerTrusted',
                r'Ljavax/net/ssl/SSLContext;->init',
            ]
        }
        
        for smali_file in smali_files[:50]:  # Limit to 50 files
            try:
                content = smali_file.read_text(encoding='utf-8', errors='ignore')
                lines = content.split('\n')
                
                for category, patterns in suspicious_patterns.items():
                    for pattern in patterns:
                        import re
                        for i, line in enumerate(lines, 1):
                            if re.search(pattern, line):
                                findings.append({
                                    "type": "smali_issue",
                                    "category": category,
                                    "file": str(smali_file.relative_to(smali_dir.parent)),
                                    "line": i,
                                    "code": line.strip()[:200],
                                    "severity": "HIGH" if category in ['crypto_weak', 'ssl_bypass'] else "MEDIUM"
                                })
            except Exception:
                pass
        
        return findings
    
    async def _analyze_assets(self, assets_path: Path) -> List[Dict]:
        """Analyze assets directory"""
        findings = []
        
        # Look for sensitive files
        for asset_file in assets_path.rglob('*'):
            if asset_file.is_file():
                # Check for certificates, keys, etc.
                if asset_file.suffix in ['.pem', '.key', '.crt', '.cer', '.der', '.p12', '.pfx']:
                    findings.append({
                        "type": "asset_certificate",
                        "file": str(asset_file),
                        "severity": "HIGH"
                    })
                
                # Check for config files with secrets
                if asset_file.name in ['config.json', 'config.xml', 'secrets.json', 'api_keys.json']:
                    findings.append({
                        "type": "asset_config",
                        "file": str(asset_file),
                        "severity": "MEDIUM"
                    })
        
        return findings
    
    def _assess_permission_risk(self, permission: str) -> str:
        """Assess permission risk level"""
        high_risk = [
            'READ_SMS', 'SEND_SMS', 'RECEIVE_SMS', 'READ_CONTACTS',
            'WRITE_CONTACTS', 'READ_CALL_LOG', 'WRITE_CALL_LOG',
            'CAMERA', 'RECORD_AUDIO', 'ACCESS_FINE_LOCATION',
            'ACCESS_COARSE_LOCATION', 'READ_EXTERNAL_STORAGE',
            'WRITE_EXTERNAL_STORAGE', 'SYSTEM_ALERT_WINDOW',
            'BIND_ACCESSIBILITY_SERVICE', 'BIND_DEVICE_ADMIN'
        ]
        
        if permission in high_risk:
            return 'HIGH'
        elif permission.startswith('android.permission.'):
            return 'MEDIUM'
        return 'LOW'


# Register
apktool_tool = ApktoolIntegration()
tool_registry.register(apktool_tool)