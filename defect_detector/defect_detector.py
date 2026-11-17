"""
Defect Detector
System defect detection, vulnerability scanning, and configuration audit
"""
import asyncio
import logging
import subprocess
import json
import re
from typing import Dict, List, Optional, Dict, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path
import asyncio

logger = logging.getLogger(__name__)


@dataclass
class Defect:
    defect_id: str
    timestamp: datetime
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str  # SECURITY, PERFORMANCE, RELIABILITY, COMPLIANCE, CONFIGURATION
    title: str
    description: str
    affected_component: str
    remediation: str
    references: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    status: str = "OPEN"  # OPEN, IN_PROGRESS, FIXED, WONT_FIX, FALSE_POSITIVE
    evidence: Dict = field(default_factory=dict)


class DefectDetector:
    """
    Main defect detection engine
    Scans for system defects, vulnerabilities, and misconfigurations
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.scan_results: List[Dict] = []
        self.defects: List[Dict] = []
        self.scan_history: List[Dict] = []
        
    async def run_full_scan(self, target: str = "localhost") -> Dict:
        """Run comprehensive defect detection scan"""
        scan_id = f"SCAN-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        start_time = datetime.now()
        
        results = {
            "scan_id": scan_id,
            "target": target,
            "start_time": start_time.isoformat(),
            "end_time": None,
            "defects_found": 0,
            "defects": [],
            "summary": {}
        }
        
        # Run all detection modules
        defects = []
        
        # System configuration defects
        config_defects = await self._scan_configurations()
        defects.extend(config_defects)
        
        # Security vulnerabilities
        vuln_defects = await self._scan_vulnerabilities()
        defects.extend(vuln_defects)
        
        # Performance defects
        perf_defects = await self._scan_performance()
        defects.extend(perf_defects)
        
        # Reliability defects
        reliability_defects = await self._scan_reliability()
        defects.extend(reliability_defects)
        
        # Compliance defects
        compliance_defects = await self._scan_compliance()
        defects.extend(compliance_defects)
        
        # Docker/Container defects
        container_defects = await self._scan_containers()
        defects.extend(container_defects)
        
        # Cloud configuration defects
        cloud_defects = await self._scan_cloud_config()
        defects.extend(cloud_defects)
        
        # Network configuration defects
        network_defects = await self._scan_network_config()
        defects.extend(network_defects)
        
        # Process all defects
        for defect in defects:
            defect_obj = self._create_defect_object(defect)
            self.defects.append(defect_obj)
            results["defects"].append(defect_obj.to_dict() if hasattr(defect_obj, 'to_dict') else defect_obj)
        
        results["defects_found"] = len(defects)
        results["end_time"] = datetime.now().isoformat()
        results["duration_seconds"] = (datetime.now() - start_time).total_seconds()
        
        # Generate summary
        results["summary"] = self._generate_summary(defects)
        
        self.scan_history.append(results)
        return results
    
    def _create_defect_object(self, defect_data: Dict) -> Defect:
        return Defect(
            defect_id=defect_data.get("id", f"DEF-{datetime.now().strftime('%Y%m%d%H%M%S')}"),
            timestamp=datetime.now(),
            severity=defect_data.get("severity", "MEDIUM"),
            category=defect_data.get("category", "CONFIGURATION"),
            title=defect_data.get("title", "Unknown Defect"),
            description=defect_data.get("description", ""),
            affected_component=defect_data.get("component", "Unknown"),
            remediation=defect_data.get("remediation", "Investigate and remediate"),
            references=defect_data.get("references", []),
            cve_ids=defect_data.get("cve_ids", []),
            cvss_score=defect_data.get("cvss_score"),
            evidence=defect_data.get("evidence", {})
        )
    
    async def _scan_configurations(self) -> List[Dict]:
        """Scan for configuration defects"""
        defects = []
        
        # Check SSH configuration
        ssh_defects = await self._check_ssh_config()
        defects.extend(ssh_defects)
        
        # Check sudo configuration
        sudo_defects = await self._check_sudo_config()
        defects.extend(sudo_defects)
        
        # Check file permissions
        perm_defects = await self._check_file_permissions()
        defects.extend(perm_defects)
        
        # Check service configurations
        service_defects = await self._check_service_configs()
        defects.extend(service_defects)
        
        # Check kernel parameters
        kernel_defects = await self._check_kernel_params()
        defects.extend(kernel_defects)
        
        return defects
    
    async def _check_ssh_config(self) -> List[Dict]:
        """Check SSH configuration for security issues"""
        defects = []
        sshd_config = "/etc/ssh/sshd_config"
        
        try:
            with open(sshd_config, 'r') as f:
                content = f.read()
            
            checks = [
                ("PermitRootLogin", "no", "PermitRootLogin should be disabled", "HIGH"),
                ("PasswordAuthentication", "no", "Password authentication should be disabled", "HIGH"),
                ("PubkeyAuthentication", "yes", "Public key authentication should be enabled", "MEDIUM"),
                ("PermitEmptyPasswords", "no", "Empty passwords should be disabled", "HIGH"),
                ("Protocol", "2", "SSH Protocol 1 is deprecated", "HIGH"),
                ("X11Forwarding", "no", "X11 forwarding should be disabled unless needed", "MEDIUM"),
                ("MaxAuthTries", "3", "Max authentication tries should be limited", "MEDIUM"),
                ("ClientAliveInterval", "300", "Client alive interval should be set", "LOW"),
                ("ClientAliveCountMax", "2", "Client alive count max should be set", "LOW"),
                ("LoginGraceTime", "60", "Login grace time should be limited", "LOW"),
                ("MaxSessions", "10", "Max sessions should be limited", "LOW"),
                ("AllowAgentForwarding", "no", "Agent forwarding should be disabled", "MEDIUM"),
                ("AllowTcpForwarding", "no", "TCP forwarding should be disabled", "MEDIUM"),
                ("PermitTunnel", "no", "Tunneling should be disabled", "MEDIUM"),
                ("DebianBanner", "no", "Debian banner should be disabled", "LOW"),
                ("PrintMotd", "no", "MOTD should be disabled", "LOW"),
                ("PrintLastLog", "yes", "Last log should be shown", "LOW"),
                ("TCPKeepAlive", "yes", "TCP keepalive should be enabled", "LOW"),
                ("Compression", "delayed", "Compression should be delayed", "LOW"),
                ("UsePAM", "yes", "PAM should be enabled", "MEDIUM"),
                ("AllowGroups", None, "AllowGroups should restrict SSH access", "MEDIUM"),
                ("AllowUsers", None, "AllowUsers should restrict SSH access", "MEDIUM"),
                ("DenyGroups", None, "DenyGroups should restrict SSH access", "MEDIUM"),
                ("DenyUsers", None, "DenyUsers should restrict SSH access", "MEDIUM")
            ]
            
            for param, expected, description, severity in checks:
                if f"{param} {expected}" not in content and f"{param.lower()} {expected}" not in content.lower():
                    defects.append({
                        "id": f"SSH-{param.upper()}",
                        "title": f"SSH Configuration: {param}",
                        "description": description,
                        "severity": severity,
                        "category": "CONFIGURATION",
                        "component": "SSH",
                        "remediation": f"Set {param} {expected} in {sshd_config}",
                        "severity_score": self._severity_score(severity)
                    })
        except FileNotFoundError:
            defects.append({
                "id": "SSH-CONFIG-MISSING",
                "title": "SSH Configuration File Missing",
                "description": f"SSH configuration file not found at {sshd_config}",
                "severity": "HIGH",
                "category": "CONFIGURATION",
                "component": "SSH",
                "remediation": f"Create {sshd_config} with secure defaults",
                "severity_score": 80
            })
        except Exception as e:
            logger.error(f"SSH config check error: {e}")
        
        return defects
    
    async def _check_sudo_config(self) -> List[Dict]:
        """Check sudo configuration"""
        defects = []
        sudoers_file = "/etc/sudoers"
        
        try:
            with open(sudoers_file, 'r') as f:
                content = f.read()
            
            # Check for NOPASSWD
            if "NOPASSWD" in content:
                defects.append({
                    "id": "SUDO-NOPASSWD",
                    "title": "Sudo NOPASSWD Enabled",
                    "description": "Sudo NOPASSWD allows passwordless sudo, security risk",
                    "severity": "HIGH",
                    "category": "CONFIGURATION",
                    "component": "Sudo",
                    "remediation": "Remove NOPASSWD from sudoers file",
                    "severity_score": 80
                })
            
            # Check for !authenticate
            if "!authenticate" in content:
                defects.append({
                    "id": "SUDO-NO-AUTH",
                    "title": "Sudo Authentication Disabled",
                    "description": "Sudo authentication disabled with !authenticate",
                    "severity": "CRITICAL",
                    "category": "CONFIGURATION",
                    "component": "Sudo",
                    "remediation": "Remove !authenticate from sudoers file",
                    "severity_score": 95
                })
            
            # Check for timestamp_timeout
            if "timestamp_timeout" not in content:
                defects.append({
                    "id": "SUDO-TIMEOUT",
                    "title": "Sudo Timestamp Timeout Not Set",
                    "description": "Sudo timestamp_timeout not configured, defaults to 15 minutes",
                    "severity": "MEDIUM",
                    "category": "CONFIGURATION",
                    "component": "Sudo",
                    "remediation": "Set timestamp_timeout=5 in sudoers",
                    "severity_score": 40
                })
            
            # Check for lecture
            if "lecture" not in content:
                defects.append({
                    "id": "SUDO-LECTURE",
                    "title": "Sudo Lecture Disabled",
                    "description": "Sudo lecture not enabled, users not warned on first use",
                    "severity": "LOW",
                    "category": "CONFIGURATION",
                    "component": "Sudo",
                    "remediation": "Add Defaults lecture=always to sudoers",
                    "severity_score": 10
                })
        
        except FileNotFoundError:
            defects.append({
                "id": "SUDO-MISSING",
                "title": "Sudoers File Missing",
                "description": "Sudoers file not found",
                "severity": "HIGH",
                "category": "CONFIGURATION",
                "component": "Sudo",
                "remediation": "Create /etc/sudoers with secure defaults",
                "severity_score": 80
            })
        
        return defects
    
    async def _check_file_permissions(self) -> List[Dict]:
        """Check critical file permissions"""
        defects = []
        
        critical_files = {
            "/etc/passwd": {"expected": "644", "owner": "root:root", "severity": "HIGH"},
            "/etc/shadow": {"expected": "640", "owner": "root:shadow", "severity": "CRITICAL"},
            "/etc/group": {"expected": "644", "owner": "root:root", "severity": "HIGH"},
            "/etc/gshadow": {"expected": "640", "owner": "root:shadow", "severity": "CRITICAL"},
            "/etc/sudoers": {"expected": "440", "owner": "root:root", "severity": "CRITICAL"},
            "/etc/ssh/sshd_config": {"expected": "644", "owner": "root:root", "severity": "HIGH"},
            "/etc/sudoers": {"expected": "440", "owner": "root:root", "severity": "CRITICAL"},
            "/etc/passwd": {"expected": "644", "owner": "root:root", "severity": "HIGH"},
            "/etc/group": {"expected": "644", "owner": "root:root", "severity": "HIGH"},
            "/etc/ssh/ssh_host_rsa_key": {"expected": "600", "owner": "root:root", "severity": "CRITICAL"},
            "/etc/ssh/ssh_host_ecdsa_key": {"expected": "600", "owner": "root:root", "severity": "CRITICAL"},
            "/etc/ssh/ssh_host_ed25519_key": {"expected": "600", "owner": "root:root", "severity": "CRITICAL"},
            "/etc/ssl/private/": {"expected": "700", "owner": "root:root", "severity": "CRITICAL", "recursive": True},
            "/etc/ssh/": {"expected": "755", "owner": "root:root", "severity": "HIGH", "recursive": True},
        }
        
        import os
        import stat
        import pwd
        import grp
        
        for path, expected in critical_files.items():
            try:
                if not os.path.exists(path):
                    # Check if directory exists for recursive checks
                    if expected.get("recursive") and os.path.isdir(path):
                        continue
                    # File missing - may be OK for some files
                    continue
                
                stat_info = os.stat(path)
                mode = stat.S_IMODE(stat_info.st_mode)
                expected_mode = int(expected["expected"], 8)
                owner_uid = pwd.getpwnam(expected["owner"].split(":")[0]).pw_uid
                owner_gid = grp.getgrnam(expected["owner"].split(":")[1]).gr_gid
                
                issues = []
                
                if mode != expected_mode:
                    defects.append({
                        "id": f"PERM-{path.replace('/', '-').strip('-')}",
                        "title": f"Incorrect Permissions: {path}",
                        "description": f"File {path} has permissions {oct(mode)}, expected {oct(expected_mode)}",
                        "severity": expected["severity"],
                        "category": "CONFIGURATION",
                        "component": "File Permissions",
                        "remediation": f"chmod {oct(expected_mode)} {path}",
                        "severity_score": self._severity_score(expected["severity"])
                    })
                
                if stat_info.st_uid != owner_uid:
                    defects.append({
                        "id": f"OWNER-{path.replace('/', '-').strip('-')}",
                        "title": f"Incorrect Owner: {path}",
                        "description": f"File {path} owned by UID {stat_info.st_uid}, expected {owner_uid}",
                        "severity": expected["severity"],
                        "category": "CONFIGURATION",
                        "component": "File Permissions",
                        "remediation": f"chown {expected['owner']} {path}",
                        "severity_score": self._severity_score(expected["severity"])
                    })
                
                if stat_info.st_gid != owner_gid:
                    defects.append({
                        "id": f"GROUP-{path.replace('/', '-').strip('-')}",
                        "title": f"Incorrect Group: {path}",
                        "description": f"File {path} group GID {stat_info.st_gid}, expected {owner_gid}",
                        "severity": expected["severity"],
                        "category": "CONFIGURATION",
                        "component": "File Permissions",
                        "remediation": f"chown {expected['owner']} {path}",
                        "severity_score": self._severity_score(expected["severity"])
                    })
                    
            except FileNotFoundError:
                # Some files may not exist, that's OK for optional files
                if not path.endswith("/"):  # Not a directory
                    pass
            except Exception as e:
                logger.error(f"Permission check error for {path}: {e}")
        
        return defects
    
    def _severity_score(self, severity: str) -> int:
        scores = {"CRITICAL": 95, "HIGH": 80, "MEDIUM": 50, "LOW": 20, "INFO": 5}
        return scores.get(severity, 50)
    
    async def _check_service_configs(self) -> List[Dict]:
        """Check service configurations"""
        defects = []
        
        # Check systemd services
        services_to_check = {
            "ssh": {"enabled": True, "required": True},
            "firewalld": {"enabled": True, "required": True},
            "ufw": {"enabled": True, "required": True},
            "iptables": {"enabled": True, "required": False},
            "fail2ban": {"enabled": True, "required": True},
            "auditd": {"enabled": True, "required": True},
            "rsyslog": {"enabled": True, "required": True},
            "systemd-journald": {"enabled": True, "required": True},
            "systemd-timesyncd": {"enabled": True, "required": True},
            "chronyd": {"enabled": True, "required": True},
            "ntpd": {"enabled": False, "required": False},  # Deprecated
        }
        
        for service, config in services_to_check.items():
            try:
                result = subprocess.run(
                    ["systemctl", "is-enabled", service],
                    capture_output=True, text=True, timeout=5
                )
                enabled = result.stdout.strip() == "enabled"
                
                if config["required"] and not enabled:
                    defects.append({
                        "id": f"SVC-{service.upper()}-DISABLED",
                        "title": f"Required Service Disabled: {service}",
                        "description": f"Required service {service} is not enabled",
                        "severity": "HIGH",
                        "category": "CONFIGURATION",
                        "component": f"Service: {service}",
                        "remediation": f"systemctl enable --now {service}",
                        "severity_score": 80
                    })
                
                if not config["required"] and enabled:
                    # Optional service running - informational
                    pass
                    
            except subprocess.TimeoutExpired:
                logger.error(f"Timeout checking service {service}")
            except Exception as e:
                logger.error(f"Service check error for {service}: {e}")
        
        return defects
    
    async def _check_kernel_params(self) -> List[Dict]:
        """Check kernel security parameters"""
        defects = []
        
        kernel_params = {
            "net.ipv4.ip_forward": {"expected": "0", "severity": "HIGH", "desc": "IP forwarding should be disabled"},
            "net.ipv4.conf.all.send_redirects": {"expected": "0", "severity": "HIGH", "desc": "ICMP redirects should be disabled"},
            "net.ipv4.conf.default.send_redirects": {"expected": "0", "severity": "HIGH", "desc": "Default ICMP redirects should be disabled"},
            "net.ipv4.conf.all.accept_redirects": {"expected": "0", "severity": "HIGH", "desc": "ICMP redirects should not be accepted"},
            "net.ipv4.conf.default.accept_redirects": {"expected": "0", "severity": "HIGH", "desc": "Default ICMP redirects should not be accepted"},
            "net.ipv4.conf.all.secure_redirects": {"expected": "0", "severity": "MEDIUM", "desc": "Secure ICMP redirects should be disabled"},
            "net.ipv4.conf.default.secure_redirects": {"expected": "0", "severity": "MEDIUM", "desc": "Default secure ICMP redirects should be disabled"},
            "net.ipv4.conf.all.accept_source_route": {"expected": "0", "severity": "HIGH", "desc": "Source routing should be disabled"},
            "net.ipv4.conf.default.accept_source_route": {"expected": "0", "severity": "HIGH", "desc": "Default source routing should be disabled"},
            "net.ipv4.conf.all.log_martians": {"expected": "1", "severity": "MEDIUM", "desc": "Log martian packets"},
            "net.ipv4.conf.default.log_martians": {"expected": "1", "severity": "MEDIUM", "desc": "Log martian packets by default"},
            "net.ipv4.icmp_echo_ignore_broadcasts": {"expected": "1", "severity": "HIGH", "desc": "Ignore ICMP broadcast requests"},
            "net.ipv4.icmp_ignore_bogus_error_responses": {"expected": "1", "severity": "MEDIUM", "desc": "Ignore bogus ICMP error responses"},
            "net.ipv4.tcp_syncookies": {"expected": "1", "severity": "HIGH", "desc": "TCP SYN cookies should be enabled"},
            "net.ipv4.tcp_max_syn_backlog": {"expected": "2048", "severity": "MEDIUM", "desc": "Increase SYN backlog"},
            "net.ipv4.tcp_synack_retries": {"expected": "2", "severity": "MEDIUM", "desc": "SYN-ACK retries"},
            "net.ipv4.tcp_syn_retries": {"expected": "2", "severity": "MEDIUM", "desc": "SYN retries"},
            "kernel.randomize_va_space": {"expected": "2", "severity": "HIGH", "desc": "ASLR should be fully enabled"},
            "kernel.yama.ptrace_scope": {"expected": "1", "severity": "MEDIUM", "desc": "Ptrace scope restriction"},
            "kernel.kptr_restrict": {"expected": "1", "severity": "MEDIUM", "desc": "Kernel pointer restriction"},
            "kernel.dmesg_restrict": {"expected": "1", "severity": "MEDIUM", "desc": "dmesg restriction"},
            "kernel.perf_event_paranoid": {"expected": "2", "severity": "MEDIUM", "desc": "Perf event paranoid"},
            "fs.suid_dumpable": {"expected": "0", "severity": "HIGH", "desc": "Disable SUID core dumps"},
            "fs.protected_hardlinks": {"expected": "1", "severity": "MEDIUM", "desc": "Protected hardlinks"},
            "fs.protected_symlinks": {"expected": "1", "severity": "MEDIUM", "desc": "Protected symlinks"},
        }
        
        for param, config in kernel_params.items():
            try:
                result = subprocess.run(
                    ["sysctl", "-n", param],
                    capture_output=True, text=True, timeout=5
                )
                current = result.stdout.strip()
                expected = config["expected"]
                
                if current != expected:
                    defects.append({
                        "id": f"KERNEL-{param.replace('.', '-').upper()}",
                        "title": f"Kernel Parameter: {param}",
                        "description": f"{config['desc']}. Current: {current}, Expected: {expected}",
                        "severity": config["severity"],
                        "category": "CONFIGURATION",
                        "component": "Kernel Parameters",
                        "remediation": f"sysctl -w {param}={expected}",
                        "severity_score": self._severity_score(config["severity"])
                    })
            except Exception as e:
                logger.error(f"Kernel param check error for {param}: {e}")
        
        return defects
    
    async def _scan_vulnerabilities(self) -> List[Dict]:
        """Scan for known vulnerabilities"""
        defects = []
        
        # Check for outdated packages
        try:
            result = subprocess.run(
                ["apt", "list", "--upgradable"],
                capture_output=True, text=True, timeout=30
            )
            
            if result.stdout:
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                for line in lines:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            pkg = parts[0].split('/')[0]
                            version = parts[1]
                            # Check if security update
                            is_security = "security" in line.lower()
                            severity = "HIGH" if is_security else "MEDIUM"
                            defects.append({
                                "id": f"PKG-{parts[0].replace('/', '-')}",
                                "title": f"Outdated Package: {parts[0]}",
                                "description": f"Package {parts[0]} has update available: {version}",
                                "severity": severity,
                                "category": "VULNERABILITY",
                                "component": f"Package: {parts[0]}",
                                "remediation": f"apt-get update && apt-get install --only-upgrade {parts[0]}",
                                "severity_score": 80 if is_security else 50
                            })
        except Exception as e:
            logger.error(f"Package scan error: {e}")
        
        # Check for known vulnerable packages
        vulnerable_packages = {
            "openssl": {"min_version": "3.0.0", "cve": "CVE-2022-XXXX"},
            "openssh-server": {"min_version": "8.9", "cve": "CVE-2022-XXXX"},
            "sudo": {"min_version": "1.9.0", "cve": "CVE-2021-3156"},
            "systemd": {"min_version": "249", "cve": "CVE-2022-XXXX"},
            "glibc": {"min_version": "2.35", "cve": "CVE-2022-XXXX"},
            "linux-image": {"min_version": "5.15", "cve": "CVE-2022-XXXX"},
            "curl": {"min_version": "7.81.0", "cve": "CVE-2022-XXXX"},
            "wget": {"min_version": "1.21", "cve": "CVE-2022-XXXX"},
            "tar": {"min_version": "1.34", "cve": "CVE-2022-XXXX"},
            "gzip": {"min_version": "1.12", "cve": "CVE-2022-XXXX"},
            "bash": {"min_version": "5.1", "cve": "CVE-2022-XXXX"},
            "systemd": {"min_version": "249", "cve": "CVE-2022-XXXX"},
        }
        
        for pkg, info in vulnerable_packages.items():
            try:
                result = subprocess.run(
                    ["dpkg", "-l", pkg],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0 and "ii" in result.stdout:
                    # Parse version
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if line.startswith("ii"):
                            parts = line.split()
                            if len(parts) >= 3:
                                installed = parts[2]
                                # Simple version comparison
                                if self._version_compare(installed, info["min_version"]) < 0:
                                    defects.append({
                                        "id": f"VULN-{pkg.upper()}",
                                        "title": f"Vulnerable Package: {pkg}",
                                        "description": f"Package {pkg} version {installed} is vulnerable (min {info['min_version']}). CVE: {info['cve']}",
                                        "severity": "HIGH",
                                        "category": "VULNERABILITY",
                                        "component": f"Package: {pkg}",
                                        "remediation": f"apt-get update && apt-get install --only-upgrade {pkg}",
                                        "cve_ids": [info["cve"]],
                                        "severity_score": 85
                                    })
            except Exception as e:
                logger.error(f"Vulnerability check error for {pkg}: {e}")
        
        return defects
    
    def _version_compare(self, v1: str, v2: str) -> int:
        """Compare version strings. Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2"""
        def normalize(v):
            parts = []
            for part in v.split('.'):
                try:
                    parts.append(int(part))
                except ValueError:
                    # Handle non-numeric parts
                    parts.append(ord(part[0]) if part else 0)
            return parts
        
        v1_parts = normalize(v1)
        v2_parts = normalize(v2)
        
        for a, b in zip(v1_parts, v2_parts):
            if a < b:
                return -1
            elif a > b:
                return 1
        
        if len(v1_parts) < len(v2_parts):
            return -1
        elif len(v1_parts) > len(v2_parts):
            return 1
        return 0
    
    async def _scan_performance(self) -> List[Dict]:
        """Scan for performance defects"""
        defects = []
        
        # Check CPU
        try:
            with open('/proc/stat', 'r') as f:
                cpu_line = f.readline()
                if cpu_line.startswith('cpu '):
                    parts = cpu_line.split()
                    if len(parts) >= 8:
                        user = int(parts[1])
                        nice = int(parts[2])
                        system = int(parts[3])
                        idle = int(parts[4])
                        iowait = int(parts[5]) if len(parts) > 5 else 0
                        irq = int(parts[6]) if len(parts) > 6 else 0
                        softirq = int(parts[7]) if len(parts) > 7 else 0
                        
                        total = user + nice + system + idle + iowait + irq + softirq
                        if total > 0:
                            idle_pct = (idle / total) * 100
                            iowait_pct = (iowait / total) * 100
                            
                            if idle_pct < 10:
                                defects.append({
                                    "id": "PERF-CPU-HIGH",
                                    "title": "High CPU Usage",
                                    "description": f"CPU idle only {idle_pct:.1f}%, system under heavy load",
                                    "severity": "HIGH",
                                    "category": "PERFORMANCE",
                                    "component": "CPU",
                                    "remediation": "Investigate high CPU processes, consider scaling",
                                    "severity_score": 70
                                })
                            
                            if iowait_pct > 20:
                                defects.append({
                                    "id": "PERF-IOWAIT-HIGH",
                                    "title": "High I/O Wait",
                                    "description": f"I/O wait at {iowait_pct:.1f}%, storage bottleneck",
                                    "severity": "HIGH",
                                    "category": "PERFORMANCE",
                                    "component": "Storage I/O",
                                    "remediation": "Investigate disk I/O, consider SSD/NVMe upgrade",
                                    "severity_score": 70
                                })
        except Exception as e:
            logger.error(f"CPU check error: {e}")
        
        # Check memory
        try:
            with open('/proc/meminfo', 'r') as f:
                meminfo = {}
                for line in f:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        meminfo[key.strip()] = value.strip()
                
                total = int(meminfo.get('MemTotal', '0').split()[0])
                available = int(meminfo.get('MemAvailable', '0').split()[0])
                free = int(meminfo.get('MemFree', '0').split()[0])
                
                if total > 0:
                    available_pct = (available / total) * 100
                    free_pct = (free / total) * 100
                    
                    if available_pct < 10:
                        defects.append({
                            "id": "PERF-MEM-LOW",
                            "title": "Low Available Memory",
                            "description": f"Only {available_pct:.1f}% memory available",
                            "severity": "CRITICAL",
                            "category": "PERFORMANCE",
                            "component": "Memory",
                            "remediation": "Add RAM, investigate memory leaks, optimize applications",
                            "severity_score": 90
                        })
                    elif available_pct < 20:
                        defects.append({
                            "id": "PERF-MEM-LOW-WARN",
                            "title": "Low Memory Warning",
                            "description": f"Only {available_pct:.1f}% memory available",
                            "severity": "HIGH",
                            "category": "PERFORMANCE",
                            "component": "Memory",
                            "remediation": "Monitor memory usage, plan capacity increase",
                            "severity_score": 70
                        })
        except Exception as e:
            logger.error(f"Memory check error: {e}")
        
        # Check disk space
        try:
            import shutil
            for mount in ['/', '/var', '/tmp', '/home', '/opt', '/data']:
                try:
                    usage = shutil.disk_usage(mount)
                    free_pct = (usage.free / usage.total) * 100
                    
                    if free_pct < 5:
                        defects.append({
                            "id": f"DISK-{mount.replace('/', '-').strip('-')}-CRITICAL",
                            "title": f"Critical Disk Space: {mount}",
                            "description": f"Only {free_pct:.1f}% free on {mount}",
                            "severity": "CRITICAL",
                            "category": "PERFORMANCE",
                            "component": f"Disk: {mount}",
                            "remediation": "Free disk space immediately, investigate large files",
                            "severity_score": 95
                        })
                    elif free_pct < 15:
                        defects.append({
                            "id": f"DISK-{mount.replace('/', '-').strip('-')}-LOW",
                            "title": f"Low Disk Space: {mount}",
                            "description": f"Only {free_pct:.1f}% free on {mount}",
                            "severity": "HIGH",
                            "category": "PERFORMANCE",
                            "component": f"Disk: {mount}",
                            "remediation": "Clean up disk space, add storage",
                            "severity_score": 75
                        })
                except:
                    pass
        except Exception as e:
            logger.error(f"Disk check error: {e}")
        
        # Check load average
        try:
            with open('/proc/loadavg', 'r') as f:
                load = f.read().strip().split()
                if len(load) >= 3:
                    load_1 = float(load[0])
                    load_5 = float(load[1])
                    load_15 = float(load[2])
                    
                    import os
                    cpu_count = os.cpu_count() or 1
                    
                    if load_1 > cpu_count * 2:
                        defects.append({
                            "id": "PERF-LOAD-HIGH",
                            "title": "High System Load",
                            "description": f"Load average {load_1:.2f} exceeds 2x CPU cores ({cpu_count})",
                            "severity": "HIGH",
                            "category": "PERFORMANCE",
                            "component": "System Load",
                            "remediation": "Investigate high load processes, consider scaling",
                            "severity_score": 70
                        })
        except Exception as e:
            logger.error(f"Load check error: {e}")
        
        return defects
    
    async def _scan_reliability(self) -> List[Dict]:
        """Scan for reliability defects"""
        defects = []
        
        # Check systemd failed units
        try:
            result = subprocess.run(
                ["systemctl", "--failed", "--no-legend", "--no-pager"],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout.strip():
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            unit = parts[0]
                            state = parts[1]
                            defects.append({
                                "id": f"SYSTEMD-FAILED-{parts[0].replace('.', '-')}",
                                "title": f"Failed Systemd Unit: {unit}",
                                "description": f"Service {unit} is in {state} state",
                                "severity": "HIGH",
                                "category": "RELIABILITY",
                                "component": f"Service: {unit}",
                                "remediation": f"systemctl status {unit} && journalctl -u {unit} -n 50",
                                "severity_score": 75
                            })
        except Exception as e:
            logger.error(f"Systemd check error: {e}")
        
        # Check for core dumps
        try:
            result = subprocess.run(
                ["coredumpctl", "list", "--no-pager"],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout.strip():
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                for line in lines:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 5:
                            defects.append({
                                "id": f"COREDUMP-{parts[0]}-{parts[1]}",
                                "title": f"Core Dump: {parts[4] if len(parts) > 4 else 'unknown'}",
                                "description": f"Core dump from {parts[4] if len(parts) > 4 else 'unknown'} at {parts[0]} {parts[1]}",
                                "severity": "HIGH",
                                "category": "RELIABILITY",
                                "component": "System",
                                "remediation": f"coredumpctl info {parts[0]} {parts[1]} && gdb /usr/bin/{parts[4]} /var/lib/systemd/coredump/core.{parts[0]}.{parts[1]}",
                                "severity_score": 75
                            })
        except Exception as e:
            logger.error(f"Core dump check error: {e}")
        
        # Check journal for errors
        try:
            result = subprocess.run(
                ["journalctl", "-p", "err..emerg", "--since", "1 hour ago", "--no-pager"],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout.strip():
                lines = result.stdout.strip().split('\n')
                error_count = len([l for l in lines if l.strip()])
                if error_count > 10:
                    defects.append({
                        "id": "JOURNAL-ERRORS-HIGH",
                        "title": "High Error Rate in Journal",
                        "description": f"{error_count} errors in last hour",
                        "severity": "HIGH",
                        "category": "RELIABILITY",
                        "component": "Systemd Journal",
                        "remediation": "journalctl -p err..emerg --since '1 hour ago'",
                        "severity_score": 70
                    })
        except Exception as e:
            logger.error(f"Journal check error: {e}")
        
        return defects
    
    async def _scan_compliance(self) -> List[Dict]:
        """Scan for compliance violations"""
        defects = []
        
        # Check for required audit rules
        audit_rules = [
            ("-w /etc/passwd -p wa -k passwd_changes", "Monitor /etc/passwd changes"),
            ("-w /etc/group -p wa -k group_changes", "Monitor /etc/group changes"),
            ("-w /etc/shadow -p wa -k shadow_changes", "Monitor /etc/shadow changes"),
            ("-w /etc/sudoers -p wa -k sudoers_changes", "Monitor /etc/sudoers changes"),
            ("-w /etc/ssh/sshd_config -p wa -k sshd_config", "Monitor SSH config"),
            ("-a always,exit -F arch=b64 -S execve -k execve", "Audit execve calls"),
            ("-a always,exit -F arch=b32 -S execve -k execve", "Audit execve (32-bit)"),
            ("-w /var/log/ -p wa -k log_changes", "Monitor log file changes"),
        ]
        
        try:
            result = subprocess.run(
                ["auditctl", "-l"],
                capture_output=True, text=True, timeout=5
            )
            current_rules = result.stdout
            
            for rule, desc in audit_rules:
                if rule not in current_rules:
                    defects.append({
                        "id": f"AUDIT-{len(defects)}",
                        "title": f"Missing Audit Rule: {desc}",
                        "description": f"Audit rule missing: {rule}",
                        "severity": "MEDIUM",
                        "category": "COMPLIANCE",
                        "component": "Audit System",
                        "remediation": f"auditctl -a {rule}",
                        "severity_score": 40
                    })
        except Exception as e:
            logger.error(f"Audit check error: {e}")
        
        # Check for password policies
        try:
            with open('/etc/login.defs', 'r') as f:
                login_defs = f.read()
            
            checks = {
                "PASS_MAX_DAYS": ("90", "MEDIUM", "Password max age should be 90 days"),
                "PASS_MIN_DAYS": ("7", "LOW", "Password min age should be 7 days"),
                "PASS_MIN_LEN": ("12", "HIGH", "Password min length should be 12"),
                "PASS_WARN_AGE": ("14", "LOW", "Password warning age should be 14 days"),
                "ENCRYPT_METHOD": ("SHA512", "HIGH", "Password encryption should be SHA512"),
                "FAIL_DELAY": ("4", "MEDIUM", "Fail delay should be 4 seconds"),
                "FAILLOCK_RECORD": ("1", "LOW", "Fail lock record should be enabled"),
                "FAILLOG_ENAB": ("yes", "LOW", "Failed login logging should be enabled"),
                "LOG_OK_LOGINS": ("yes", "LOW", "Successful login logging should be enabled"),
                "LOG_UNKFAIL_ENAB": ("yes", "LOW", "Unknown login logging should be enabled"),
                "SYSLOG_SU_ENAB": ("yes", "LOW", "SU logging should be enabled"),
                "SULOG_FILE": ("/var/log/sulog", "LOW", "SU log file should be configured"),
            }
            
            for param, (expected, severity, desc) in checks.items():
                if f"{param} {expected}" not in login_defs and f"{param} {expected}" not in login_defs.replace(' ', ''):
                    defects.append({
                        "id": f"LOGINDEFS-{param}",
                        "title": f"Login.defs: {param}",
                        "description": desc,
                        "severity": severity,
                        "category": "COMPLIANCE",
                        "component": "Login Configuration",
                        "remediation": f"Set {param} {expected} in /etc/login.defs",
                        "severity_score": self._severity_score(severity)
                    })
        except Exception as e:
            logger.error(f"Login.defs check error: {e}")
        
        return defects
    
    async def _scan_containers(self) -> List[Dict]:
        """Scan Docker/containers for security issues"""
        defects = []
        
        try:
            # Check if Docker is running
            result = subprocess.run(
                ["docker", "ps", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Status}}"],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line.strip():
                        parts = line.split('\t')
                        if len(parts) >= 3:
                            container_id, image, name, status = parts[0], parts[1], parts[2], parts[3] if len(parts) > 3 else ""
                            
                            # Check for privileged containers
                            inspect = subprocess.run(
                                ["docker", "inspect", "--format", "{{.HostConfig.Privileged}}", container_id],
                                capture_output=True, text=True, timeout=5
                            )
                            if "true" in inspect.stdout.lower():
                                defects.append({
                                    "id": f"CONTAINER-PRIVILEGED-{container_id[:12]}",
                                    "title": f"Privileged Container: {name}",
                                    "description": f"Container {name} runs in privileged mode",
                                    "severity": "HIGH",
                                    "category": "CONTAINER",
                                    "component": f"Container: {name}",
                                    "remediation": f"docker run --privileged=false {image}",
                                    "severity_score": 80
                                })
                            
                            # Check for root user
                            inspect_user = subprocess.run(
                                ["docker", "inspect", "--format", "{{.Config.User}}", container_id],
                                capture_output=True, text=True, timeout=5
                            )
                            if "root" in inspect_user.stdout.lower() or inspect_user.stdout.strip() == "":
                                defects.append({
                                    "id": f"CONTAINER-ROOT-{container_id[:12]}",
                                    "title": f"Container Running as Root: {name}",
                                    "description": f"Container {name} runs as root user",
                                    "severity": "HIGH",
                                    "category": "CONTAINER",
                                    "component": f"Container: {name}",
                                    "remediation": f"Add USER directive in Dockerfile",
                                    "severity_score": 80
                                })
                            
                            # Check for host network
                            inspect_net = subprocess.run(
                                ["docker", "inspect", "--format", "{{.HostConfig.NetworkMode}}", container_id],
                                capture_output=True, text=True, timeout=5
                            )
                            if "host" in inspect_net.stdout.lower():
                                defects.append({
                                    "id": f"CONTAINER-HOSTNET-{container_id[:12]}",
                                    "title": f"Container Uses Host Network: {name}",
                                    "description": f"Container {name} uses host network mode",
                                    "severity": "MEDIUM",
                                    "category": "CONTAINER",
                                    "component": f"Container: {name}",
                                    "remediation": "Remove --network host from docker run",
                                    "severity_score": 40
                                })
                            
                            # Check for host PID
                            inspect_pid = subprocess.run(
                                ["docker", "inspect", "--format", "{{.HostConfig.PidMode}}", container_id],
                                capture_output=True, text=True, timeout=5
                            )
                            if "host" in inspect_pid.stdout.lower():
                                defects.append({
                                    "id": f"CONTAINER-HOSTPID-{container_id[:12]}",
                                    "title": f"Container Uses Host PID: {name}",
                                    "description": f"Container {name} uses host PID namespace",
                                    "severity": "MEDIUM",
                                    "category": "CONTAINER",
                                    "component": f"Container: {name}",
                                    "remediation": "Remove --pid=host from docker run",
                                    "severity_score": 40
                                })
                            
                            # Check for capabilities
                            inspect_cap = subprocess.run(
                                ["docker", "inspect", "--format", "{{.HostConfig.CapAdd}}", container_id],
                                capture_output=True, text=True, timeout=5
                            )
                            if "SYS_ADMIN" in inspect_cap.stdout or "ALL" in inspect_cap.stdout:
                                defects.append({
                                    "id": f"CONTAINER-CAPS-{container_id[:12]}",
                                    "title": f"Dangerous Capabilities: {name}",
                                    "description": f"Container {name} has dangerous capabilities",
                                    "severity": "HIGH",
                                    "category": "CONTAINER",
                                    "component": f"Container: {name}",
                                    "remediation": "Remove --cap-add=SYS_ADMIN or --privileged",
                                    "severity_score": 85
                                })
        except Exception as e:
            logger.error(f"Container scan error: {e}")
        
        # Check for vulnerable images
        try:
            result = subprocess.run(
                ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}\t{{.ID}}"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line.strip() and ':' in line:
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            tag, image_id = parts[0], parts[1]
                            # Check for known vulnerable base images
                            vulnerable_bases = [
                                "ubuntu:14.04", "ubuntu:16.04", "ubuntu:18.04",
                                "centos:6", "centos:7",
                                "debian:8", "debian:9",
                                "alpine:3.6", "alpine:3.7", "alpine:3.8",
                                "node:8", "node:10", "node:12",
                                "python:3.6", "python:3.7"
                            ]
                            for vuln in vulnerable_bases:
                                if vuln in tag:
                                    defects.append({
                                        "id": f"IMAGE-VULN-{image_id[:12]}",
                                        "title": f"Vulnerable Base Image: {tag}",
                                        "description": f"Image {tag} uses vulnerable base {tag.split(':')[0]}",
                                        "severity": "HIGH",
                                        "category": "CONTAINER",
                                        "component": f"Image: {tag}",
                                        "remediation": f"Update to newer base image, rebuild {tag}",
                                        "severity_score": 75
                                    })
        except Exception as e:
            logger.error(f"Image scan error: {e}")
        
        return defects
    
    async def _scan_cloud_config(self) -> List[Dict]:
        """Scan cloud configuration for defects"""
        defects = []
        
        # AWS checks (if running in AWS)
        try:
            # Check for IMDSv2
            import urllib.request
            try:
                req = urllib.request.Request(
                    'http://169.254.169.254/latest/meta-data/',
                    headers={'Metadata-token': 'required'},
                    headers={'Metadata-token-ttl-seconds': '21600'}
                )
                response = urllib.request.urlopen(req, timeout=2)
                # IMDSv2 enforced
            except:
                defects.append({
                    "id": "AWS-IMDSV1",
                    "title": "AWS IMDSv1 Enabled",
                    "description": "Instance Metadata Service v1 enabled, vulnerable to SSRF",
                    "severity": "HIGH",
                    "category": "CLOUD",
                    "component": "AWS EC2",
                    "remediation": "Enforce IMDSv2 on all instances",
                    "severity_score": 80
                })
        except:
            pass
        
        # Check for public S3 buckets (would need AWS CLI)
        # Check for open security groups
        # Check for unencrypted EBS volumes
        # Check for public RDS instances
        
        # Azure checks
        try:
            # Check for managed identities
            # Check for Key Vault usage
            # Check for NSG rules
            pass
        except:
            pass
        
        # GCP checks
        try:
            # Check for default service account
            # Check for public IP on VMs
            # Check for Cloud Armor
            # Check for Binary Authorization
            pass
        except:
            pass
        
        return defects
    
    async def _scan_network_config(self) -> List[Dict]:
        """Scan network configuration for defects"""
        defects = []
        
        # Check firewall
        try:
            # UFW
            result = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=5)
            if "inactive" in result.stdout.lower():
                defects.append({
                    "id": "FW-UFW-DISABLED",
                    "title": "UFW Firewall Disabled",
                    "description": "UFW firewall is not active",
                    "severity": "HIGH",
                    "category": "NETWORK",
                    "component": "Firewall",
                    "remediation": "ufw enable",
                    "severity_score": 80
                })
            
            # iptables
            result = subprocess.run(["iptables", "-L", "-n"], capture_output=True, text=True, timeout=5)
            if not result.stdout.strip() or "ACCEPT" not in result.stdout:
                defects.append({
                    "id": "FW-IPTABLES-EMPTY",
                    "title": "Iptables Rules Empty",
                    "description": "No iptables rules configured",
                    "severity": "HIGH",
                    "category": "NETWORK",
                    "component": "Firewall",
                    "remediation": "Configure iptables rules",
                    "severity_score": 70
                })
        except Exception as e:
            logger.error(f"Firewall check error: {e}")
        
        # Check for open ports
        try:
            result = subprocess.run(["ss", "-tuln"], capture_output=True, text=True, timeout=5)
            if result.stdout:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if 'LISTEN' in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            proto = parts[0]
                            local = parts[4]
                            if '0.0.0.0:' in local or ':::' in local:
                                port = local.split(':')[-1]
                                # Check for dangerous ports
                                dangerous_ports = {'21', '23', '135', '139', '445', '1433', '3389', '5432', '6379', '27017'}
                                if port in dangerous_ports:
                                    defects.append({
                                        "id": f"PORT-{port}-EXPOSED",
                                        "title": f"Dangerous Port Exposed: {port}",
                                        "description": f"Port {port} listening on all interfaces",
                                        "severity": "HIGH",
                                        "category": "NETWORK",
                                        "component": f"Port {port}",
                                        "remediation": f"Firewall restrict port {port} to specific IPs",
                                        "severity_score": 80
                                    })
        except Exception as e:
            logger.error(f"Port scan error: {e}")
        
        # Check DNS configuration
        try:
            with open('/etc/resolv.conf', 'r') as f:
                resolv = f.read()
            if '127.0.0.53' not in resolv and '127.0.0.1' not in resolv:
                defects.append({
                    "id": "DNS-LOCAL",
                    "title": "No Local DNS Resolver",
                    "description": "No local DNS resolver configured (systemd-resolved)",
                    "severity": "MEDIUM",
                    "category": "NETWORK",
                    "component": "DNS",
                    "remediation": "Enable systemd-resolved",
                    "severity_score": 30
                })
        except:
            pass
        
        return defects
    
    def _generate_summary(self, defects: List[Dict]) -> Dict:
        """Generate scan summary"""
        by_severity = defaultdict(int)
        by_category = defaultdict(int)
        
        for defect in defects:
            by_severity[defect.get("severity", "UNKNOWN")] += 1
            by_category[defect.get("category", "UNKNOWN")] += 1
        
        return {
            "total_defects": len(defects),
            "by_severity": dict(by_severity),
            "by_category": dict(by_category),
            "critical_count": by_severity.get("CRITICAL", 0),
            "high_count": by_severity.get("HIGH", 0),
            "medium_count": by_severity.get("MEDIUM", 0),
            "low_count": by_severity.get("LOW", 0)
        }