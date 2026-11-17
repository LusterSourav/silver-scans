"""
Network Intrusion Detection System Engine
Real-time packet capture and analysis for attack detection
"""
import asyncio
import socket
import struct
import logging
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import asyncio.subprocess as asp
import json

logger = logging.getLogger(__name__)


@dataclass
class NetworkPacket:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    payload: bytes
    flags: Dict[str, bool] = field(default_factory=dict)
    length: int = 0


@dataclass
class ThreatAlert:
    alert_id: str
    timestamp: datetime
    severity: str
    category: str
    source_ip: str
    target_ip: str
    description: str
    indicators: List[str] = field(default_factory=list)
    raw_packet: Optional[NetworkPacket] = None


class IDSEngine:
    """
    Network Intrusion Detection System
    Monitors network traffic for suspicious patterns and known attack signatures
    """
    
    def __init__(self, interface: str = "any", config: Optional[Dict] = None):
        self.interface = interface
        self.config = config or {}
        self.running = False
        self.rules = []
        self.alert_callbacks: List[Callable[[ThreatAlert], None]] = []
        self.stats = defaultdict(int)
        self.connection_tracker = defaultdict(list)
        
    def add_rule(self, rule: 'Rule'):
        """Add detection rule"""
        self.rules.append(rule)
        logger.info(f"Added IDS rule: {rule.name}")
    
    def add_alert_callback(self, callback: Callable[[ThreatAlert], None]):
        """Register callback for alerts"""
        self.alert_callbacks.append(callback)
    
    async def start(self):
        """Start packet capture and analysis"""
        self.running = True
        logger.info(f"Starting IDS on interface {self.interface}")
        
        # Start packet capture tasks
        tasks = [
            self._capture_loop(),
            self._analysis_loop(),
            self._cleanup_loop(),
            self._stats_loop()
        ]
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def stop(self):
        """Stop IDS"""
        self.running = False
        logger.info("Stopping IDS")
    
    async def _capture_loop(self):
        """Capture packets using tcpdump or raw sockets"""
        cmd = [
            "tcpdump", "-i", self.interface, "-n", "-s", "65535",
            "-w", "-", "not port 22 and not port 53"
        ]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        while self.running:
            try:
                header = await process.stdout.read(24)
                if not header:
                    break
                
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", header)
                packet_data = await process.stdout.read(incl_len)
                
                packet = self._parse_packet(packet_data, datetime.fromtimestamp(ts_sec + ts_usec/1e6))
                if packet:
                    await self._process_packet(packet)
                    
            except Exception as e:
                logger.error(f"Capture error: {e}")
                await asyncio.sleep(1)
    
    def _parse_packet(self, data: bytes, timestamp: datetime) -> Optional[NetworkPacket]:
        """Parse raw packet data"""
        if len(data) < 14:
            return None
            
        eth_header = data[:14]
        eth_type = struct.unpack("!H", eth_header[12:14])[0]
        
        if eth_type != 0x0800:  # Not IPv4
            return None
            
        ip_header = data[14:34]
        ip_fields = struct.unpack("!BBHHHBBH4s4s", ip_header[:20])
        
        version_ihl = ip_fields[0]
        ihl = version_ihl & 0x0F
        protocol = ip_fields[6]
        src_ip = socket.inet_ntoa(ip_fields[8])
        dst_ip = socket.inet_ntoa(ip_fields[9])
        
        ip_header_len = ihl * 4
        transport_header = data[14 + ip_header_len:]
        
        src_port = 0
        dst_port = 0
        flags = {}
        
        if protocol == 6:  # TCP
            if len(transport_header) >= 20:
                tcp_fields = struct.unpack("!HHLLBBHHH", transport_header[:20])
                src_port, dst_port = tcp_fields[0], tcp_fields[1]
                flags_byte = tcp_fields[5]
                flags = {
                    "fin": bool(flags_byte & 0x01),
                    "syn": bool(flags_byte & 0x02),
                    "rst": bool(flags_byte & 0x04),
                    "psh": bool(flags_byte & 0x08),
                    "ack": bool(flags_byte & 0x10),
                    "urg": bool(flags_byte & 0x20)
                }
            protocol_name = "TCP"
        elif protocol == 17:  # UDP
            if len(transport_header) >= 8:
                udp_fields = struct.unpack("!HHHH", transport_header[:8])
                src_port, dst_port = udp_fields[0], udp_fields[1]
            protocol_name = "UDP"
        else:
            protocol_name = str(protocol)
        
        payload = transport_header[20:] if protocol == 6 else transport_header[8:]
        
        return NetworkPacket(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol_name,
            payload=payload,
            flags=flags,
            length=len(data)
        )
    
    async def _process_packet(self, packet: NetworkPacket):
        """Process packet against rules"""
        self.stats["packets_total"] += 1
        
        # Track connections
        conn_key = (packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port)
        self.connection_tracker[conn_key].append(packet.timestamp)
        
        # Check against rules
        for rule in self.rules:
            if rule.match(packet):
                alert = self._create_alert(rule, packet)
                await self._trigger_alert(alert)
    
    def _create_alert(self, rule: 'Rule', packet: NetworkPacket) -> ThreatAlert:
        return ThreatAlert(
            alert_id=f"IDS-{datetime.now().strftime('%Y%m%d%H%M%S')}-{id(packet)}",
            timestamp=datetime.now(),
            severity=rule.severity,
            category=rule.category,
            source_ip=packet.src_ip,
            target_ip=packet.dst_ip,
            description=rule.description,
            indicators=[rule.name],
            raw_packet=packet
        )
    
    async def _trigger_alert(self, alert: ThreatAlert):
        self.stats["alerts_total"] += 1
        self.stats[f"severity_{alert.severity}"] += 1
        
        for callback in self.alert_callbacks:
            try:
                await callback(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")
    
    async def _analysis_loop(self):
        """Periodic traffic analysis"""
        while self.running:
            await asyncio.sleep(60)  # Analyze every minute
            await self._analyze_traffic_patterns()
    
    async def _analyze_traffic_patterns(self):
        """Detect anomalies in traffic patterns"""
        now = datetime.now()
        
        # Check for port scanning
        for src_ip, connections in self._group_by_source().items():
            if len(connections) > 100:  # Threshold
                alert = ThreatAlert(
                    alert_id=f"PORTSCAN-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    timestamp=now,
                    severity="HIGH",
                    category="RECONNAISSANCE",
                    source_ip=src_ip,
                    target_ip="MULTIPLE",
                    description=f"Possible port scan from {src_ip} - {len(connections)} unique ports",
                    indicators=["PORT_SCAN", "HIGH_CONNECTION_COUNT"]
                )
                await self._trigger_alert(alert)
        
        # Check for DDoS patterns
        for dst_ip, connections in self._group_by_dest().items():
            if len(connections) > 1000:  # Threshold
                alert = ThreatAlert(
                    alert_id=f"DDOS-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    timestamp=now,
                    severity="CRITICAL",
                    category="DDoS",
                    source_ip="MULTIPLE",
                    target_ip=dst_ip,
                    description=f"Possible DDoS targeting {dst_ip} - {len(connections)} connections",
                    indicators=["HIGH_TRAFFIC_VOLUME", "MULTIPLE_SOURCES"]
                )
                await self._trigger_alert(alert)
    
    def _group_by_source(self) -> Dict[str, List]:
        groups = defaultdict(list)
        for conn_key, timestamps in self.connection_tracker.items():
            src_ip = conn_key[0]
            groups[src_ip].append(conn_key)
        return groups
    
    def _group_by_dest(self) -> Dict[str, List]:
        groups = defaultdict(list)
        for conn_key, timestamps in self.connection_tracker.items():
            dst_ip = conn_key[1]
            groups[dst_ip].append(conn_key)
        return groups
    
    async def _cleanup_loop(self):
        """Clean old connection tracking data"""
        while self.running:
            await asyncio.sleep(300)  # Every 5 minutes
            cutoff = datetime.now().timestamp() - 3600  # 1 hour
            for conn_key in list(self.connection_tracker.keys()):
                self.connection_tracker[conn_key] = [
                    ts for ts in self.connection_tracker[conn_key]
                    if ts.timestamp() > cutoff
                ]
                if not self.connection_tracker[conn_key]:
                    del self.connection_tracker[conn_key]
    
    async def _stats_loop(self):
        """Log statistics"""
        while self.running:
            await asyncio.sleep(300)
            logger.info(f"IDS Stats: {dict(self.stats)}")
    
    def get_stats(self) -> Dict:
        return dict(self.stats)


# Default detection rules
DEFAULT_RULES = [
    Rule(
        name="SYN_FLOOD",
        category="DDoS",
        severity="HIGH",
        description="TCP SYN flood detected",
        match_fn=lambda p: p.flags.get("syn", False) and not p.flags.get("ack", False)
    ),
    Rule(
        name="PORT_SCAN",
        category="RECONNAISSANCE",
        severity="MEDIUM",
        description="Sequential port scanning detected",
        match_fn=lambda p: p.flags.get("syn", False) and p.flags.get("rst", False)
    ),
    Rule(
        name="NULL_SCAN",
        category="RECONNAISSANCE",
        severity="MEDIUM",
        description="NULL scan (no flags set)",
        match_fn=lambda p: not any(p.flags.values())
    ),
    Rule(
        name="XMAS_SCAN",
        category="RECONNAISSANCE",
        severity="MEDIUM",
        description="XMAS scan (FIN, PSH, URG)",
        match_fn=lambda p: p.flags.get("fin", False) and p.flags.get("psh", False) and p.flags.get("urg", False)
    ),
    Rule(
        name="SSH_BRUTE_FORCE",
        category="BRUTE_FORCE",
        severity="HIGH",
        description="SSH brute force attempt",
        match_fn=lambda p: p.dst_port == 22 and p.flags.get("syn", False)
    ),
    Rule(
        name="RDP_BRUTE_FORCE",
        category="BRUTE_FORCE",
        severity="HIGH",
        description="RDP brute force attempt",
        match_fn=lambda p: p.dst_port == 3389 and p.flags.get("syn", False)
    ),
    Rule(
        name="SQL_INJECTION_PAYLOAD",
        category="WEB_ATTACK",
        severity="HIGH",
        description="SQL injection payload in HTTP traffic",
        match_fn=lambda p: b"union select" in p.payload.lower() or b"' or 1=1" in p.payload.lower()
    ),
    Rule(
        name="XSS_PAYLOAD",
        category="WEB_ATTACK",
        severity="HIGH",
        description="XSS payload in HTTP traffic",
        match_fn=lambda p: b"<script" in p.payload.lower() or b"javascript:" in p.payload.lower()
    ),
    Rule(
        name="SHELLSHOCK",
        category="EXPLOIT",
        severity="CRITICAL",
        description="Shellshock exploit attempt",
        match_fn=lambda p: b"() {" in p.payload
    ),
    Rule(
        name="LOG4J_EXPLOIT",
        category="EXPLOIT",
        severity="CRITICAL",
        description="Log4j JNDI exploit attempt",
        match_fn=lambda p: b"jndi:" in p.payload.lower() or b"${jndi:" in p.payload.lower()
    )
]