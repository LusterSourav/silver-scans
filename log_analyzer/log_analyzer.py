"""
Log Analyzer Core
Central log processing and analysis engine
"""
import asyncio
import re
import logging
from typing import Dict, List, Optional, Callable, Any, AsyncGenerator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path
import asyncio
import aiofiles
import json
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class LogEntry:
    timestamp: datetime
    source: str
    level: str
    message: str
    raw: str
    parsed: Dict = field(default_factory=dict)
    host: str = ""
    service: str = ""
    pid: Optional[int] = None


@dataclass
class LogAlert:
    alert_id: str
    timestamp: datetime
    severity: str
    category: str
    source: str
    message: str
    matched_pattern: str
    log_entry: LogEntry
    indicators: List[str] = field(default_factory=list)


class LogAnalyzer:
    """
    Central log processing and analysis engine
    Supports multiple log formats and real-time streaming
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.running = False
        self.patterns = []
        self.watch_paths = []
        self.alert_callbacks: List[Callable] = []
        self.stats = defaultdict(int)
        self.log_buffer = defaultdict(list)
        
    def add_pattern(self, pattern: 'LogPattern'):
        """Add detection pattern"""
        self.patterns.append(pattern)
    
    def add_alert_callback(self, callback: Callable):
        self.alert_callbacks.append(callback)
    
    def add_watch_path(self, path: str, parser: str = "auto"):
        """Add log file to watch"""
        self.watch_paths.append({"path": path, "parser": parser})
    
    async def start(self):
        """Start log monitoring"""
        self.running = True
        tasks = []
        for watch in self.watch_paths:
            tasks.append(self._tail_file(watch["path"], watch["parser"]))
        tasks.append(self._analysis_loop())
        tasks.append(self._cleanup_loop())
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def stop(self):
        self.running = False
    
    async def _tail_file(self, path: str, parser: str):
        """Tail log file in real-time"""
        path_obj = Path(path)
        if not path_obj.exists():
            logger.warning(f"Log file not found: {path}")
            return
        
        async with aiofiles.open(path, 'r') as f:
            # Seek to end
            await f.seek(0, 2)
            
            while True:
                line = await f.readline()
                if not line:
                    await asyncio.sleep(0.1)
                    continue
                
                entry = await self._parse_line(line, path)
                if entry:
                    await self._process_entry(entry)
    
    async def _parse_line(self, line: str, source: str) -> Optional[LogEntry]:
        """Parse log line using appropriate parser"""
        parsers = {
            "syslog": self._parse_syslog,
            "json": self._parse_json,
            "apache": self._parse_apache,
            "nginx": self._parse_nginx,
            "auto": self._auto_parse
        }
        
        parser_func = parsers.get("auto", self._auto_parse)
        return await parser_func(line, source)
    
    async def _auto_parse(self, line: str, source: str) -> Optional[LogEntry]:
        """Auto-detect log format"""
        # Try JSON first
        if line.strip().startswith('{'):
            return await self._parse_json(line, source)
        
        # Try syslog
        if re.match(r'^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', line):
            return await self._parse_syslog(line, source)
        
        # Try Apache/Nginx
        if re.match(r'^\S+\s+\S+\s+\S+\s+\[', line):
            return await self._parse_apache(line, source)
        
        # Generic
        return LogEntry(
            timestamp=datetime.now(),
            source="unknown",
            level="INFO",
            message=line.strip(),
            raw=line,
            host=socket.gethostname()
        )
    
    async def _parse_syslog(self, line: str, source: str) -> Optional[LogEntry]:
        # RFC3164/RFC5424
        pattern = r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)'
        match = re.match(pattern, line)
        if not match:
            return None
        
        timestamp_str, host, service, pid, message = match.groups()
        timestamp = self._parse_timestamp(timestamp_str)
        
        return LogEntry(
            timestamp=timestamp,
            source="syslog",
            level=self._extract_level(message),
            message=message.strip(),
            raw=line,
            host=host,
            service=service,
            pid=int(pid) if pid else None
        )
    
    async def _parse_json(self, line: str, source: str) -> Optional[LogEntry]:
        try:
            data = json.loads(line)
            return LogEntry(
                timestamp=self._parse_timestamp(data.get('timestamp', data.get('@timestamp', ''))),
                source=data.get('source', 'json'),
                level=data.get('level', data.get('severity', 'INFO')),
                message=data.get('message', data.get('msg', '')),
                raw=line,
                parsed=data,
                host=data.get('host', data.get('hostname', '')),
                service=data.get('service', data.get('logger', ''))
            )
        except json.JSONDecodeError:
            return None
    
    async def _parse_apache(self, line: str, source: str) -> Optional[LogEntry]:
        # Common Log Format / Combined Log Format
        pattern = r'(\S+) (\S+) (\S+) \[(.*?)\] "(.*?)" (\d+) (\d+|-)'
        match = re.match(pattern, line)
        if not match:
            return None
        
        ip, ident, auth, timestamp_str, request, status, size = match.groups()
        timestamp = self._parse_timestamp(timestamp_str)
        
        return LogEntry(
            timestamp=timestamp,
            source="apache",
            level="INFO" if int(status) < 400 else "WARN",
            message=request,
            raw=line,
            parsed={
                "client_ip": ip,
                "request": request,
                "status": int(status),
                "size": int(size) if size != '-' else 0
            },
            host=source
        )
    
    async def _parse_nginx(self, line: str, source: str) -> Optional[LogEntry]:
        # Nginx combined format
        return await self._parse_apache(line, source)
    
    def _parse_timestamp(self, ts: str) -> datetime:
        formats = [
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y-%m-%dT%H:%M:%S.%f%z',
            '%Y-%m-%d %H:%M:%S',
            '%b %d %H:%M:%S',
            '%d/%b/%Y:%H:%M:%S %z'
        ]
        for fmt in formats:
            try:
                return datetime.strptime(ts.replace('T', ' ').replace('Z', ''), fmt)
            except ValueError:
                continue
        return datetime.now()
    
    def _extract_level(self, message: str) -> str:
        levels = ['ERROR', 'WARN', 'WARNING', 'CRITICAL', 'FATAL', 'DEBUG', 'INFO']
        msg_upper = message.upper()
        for level in levels:
            if level in msg_upper:
                return level
        return 'INFO'
    
    async def _process_entry(self, entry: LogEntry):
        self.stats["entries_processed"] += 1
        
        # Check patterns
        for pattern in self.patterns:
            if pattern.match(entry):
                alert = self._create_alert(pattern, entry)
                await self._trigger_alert(alert)
    
    def _create_alert(self, pattern: 'LogPattern', entry: LogEntry) -> 'LogAlert':
        return LogAlert(
            alert_id=f"LOG-{datetime.now().strftime('%Y%m%d%H%M%S')}-{hashlib.md5(str(entry).encode()).hexdigest()[:8]}",
            timestamp=datetime.now(),
            severity=pattern.severity,
            category=pattern.category,
            source=entry.source,
            message=entry.message[:500],
            matched_pattern=pattern.name,
            log_entry=entry,
            indicators=pattern.indicators
        )
    
    async def _trigger_alert(self, alert: 'LogAlert'):
        self.stats["alerts_generated"] += 1
        for callback in self.alert_callbacks:
            try:
                await callback(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")
    
    async def _analysis_loop(self):
        """Periodic log analysis"""
        while True:
            await asyncio.sleep(300)  # Every 5 minutes
            await self._analyze_patterns()
    
    async def _analyze_patterns(self):
        """Analyze buffered logs for patterns"""
        # Brute force detection
        await self._detect_brute_force()
        
        # Error rate anomalies
        await self._detect_error_spikes()
        
        # Privilege escalation
        await self._detect_privilege_escalation()
        
        # Suspicious processes
        await self._detect_suspicious_processes()
    
    async def _detect_brute_force(self):
        """Detect brute force attempts"""
        failures = defaultdict(list)
        for entry in self.log_buffer.get('auth', []):
            if 'failed' in entry.message.lower() or 'invalid' in entry.message.lower():
                # Extract IP
                ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', entry.message)
                if ip_match:
                    ip = ip_match.group(1)
                    failures[ip].append(entry.timestamp)
        
        for ip, timestamps in failures.items():
            if len(timestamps) > 5:  # Threshold
                alert = LogAlert(
                    alert_id=f"BF-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    timestamp=datetime.now(),
                    severity="HIGH",
                    category="BRUTE_FORCE",
                    source="ssh",
                    message=f"Brute force detected from {ip} - {len(timestamps)} attempts",
                    matched_pattern="BRUTE_FORCE_DETECTION",
                    log_entry=None,
                    indicators=["BRUTE_FORCE", "SSH", ip]
                )
                await self._trigger_alert(alert)
    
    async def _detect_error_spikes(self):
        """Detect error rate anomalies"""
        for source, entries in self.log_buffer.items():
            if len(entries) > 100:
                errors = sum(1 for e in entries if e.level in ['ERROR', 'CRITICAL', 'FATAL'])
                error_rate = errors / len(entries)
                if error_rate > 0.1:  # 10% error rate
                    alert = LogAlert(
                        alert_id=f"ERROR_SPIKE-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                        timestamp=datetime.now(),
                        severity="HIGH",
                        category="ANOMALY",
                        source=source,
                        message=f"High error rate detected: {error_rate:.1%}",
                        matched_pattern="ERROR_SPIKE",
                        log_entry=None,
                        indicators=["ERROR_SPIKE", source]
                    )
                    await self._trigger_alert(alert)
    
    async def _detect_privilege_escalation(self):
        """Detect privilege escalation attempts"""
        for entry in self.log_buffer.get('auth', []):
            if 'sudo' in entry.message.lower() and 'failed' not in entry.message.lower():
                if 'root' in entry.message.lower() or 'su ' in entry.message.lower():
                    alert = LogAlert(
                        alert_id=f"PRIVESC-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                        timestamp=datetime.now(),
                        severity="HIGH",
                        category="PRIVILEGE_ESCALATION",
                        source="sudo",
                        message=f"Potential privilege escalation: {entry.message[:200]}",
                        matched_pattern="PRIVILEGE_ESCALATION",
                        log_entry=None,
                        indicators=["PRIVILEGE_ESCALATION", "SUDO"]
                    )
                    await self._trigger_alert(alert)
    
    async def _detect_suspicious_processes(self):
        """Detect suspicious process execution"""
        for entry in self.log_buffer.get('audit', []):
            if any(cmd in entry.message.lower() for cmd in ['wget', 'curl', 'nc ', 'nc.', 'bash -i', 'sh -i', 'python -c', 'perl -e']):
                alert = LogAlert(
                    alert_id=f"SUSPICIOUS_CMD-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    timestamp=datetime.now(),
                    severity="HIGH",
                    category="SUSPICIOUS_COMMAND",
                    source="audit",
                    message=f"Suspicious command: {entry.message[:200]}",
                    matched_pattern="SUSPICIOUS_COMMAND",
                    log_entry=None,
                    indicators=["SUSPICIOUS_COMMAND", "REVERSE_SHELL"]
                )
                await self._trigger_alert(alert)
    
    async def _cleanup_loop(self):
        """Clean old buffer entries"""
        while True:
            await asyncio.sleep(3600)  # Hourly
            cutoff = datetime.now() - timedelta(hours=24)
            for source in list(self.log_buffer.keys()):
                self.log_buffer[source] = [
                    e for e in self.log_buffer[source]
                    if e.timestamp > cutoff
                ]


@dataclass
class LogPattern:
    name: str
    category: str
    severity: str
    indicators: List[str] = field(default_factory=list)
    match_fn: Optional[Callable] = None
    regex: Optional[str] = None
    
    def match(self, entry: LogEntry) -> bool:
        if self.match_fn:
            return self.match_fn(self)
        if self.regex:
            return bool(re.search(self.regex, entry.message))
        return False


import socket