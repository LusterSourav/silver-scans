"""
Alert Management System
Handles alert processing, deduplication, enrichment, and notification
"""
import asyncio
import hashlib
import json
import logging
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
from enum import Enum
import asyncio

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


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
    raw_packet: Optional[Any] = None
    status: str = "NEW"
    assigned_to: Optional[str] = None
    enriched_data: Dict = field(default_factory=dict)
    correlation_id: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity,
            "category": self.category,
            "source_ip": self.source_ip,
            "target_ip": self.target_ip,
            "description": self.description,
            "indicators": self.indicators,
            "status": self.status,
            "assigned_to": self.assigned_to,
            "enriched_data": self.enriched_data,
            "correlation_id": self.correlation_id
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ThreatAlert':
        alert = cls(
            alert_id=data['alert_id'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            severity=data['severity'],
            category=data['category'],
            source_ip=data['source_ip'],
            target_ip=data['target_ip'],
            description=data['description'],
            indicators=data.get('indicators', []),
            status=data.get('status', 'NEW'),
            assigned_to=data.get('assigned_to'),
            enriched_data=data.get('enriched_data', {}),
            correlation_id=data.get('correlation_id')
        )
        return alert


class AlertEnricher:
    """Enrich alerts with threat intelligence"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.threat_intel_cache = {}
        self.geoip_cache = {}
        self.virustotal_cache = {}
    
    async def enrich(self, alert: ThreatAlert) -> ThreatAlert:
        """Enrich alert with threat intelligence"""
        # GeoIP enrichment
        await self._enrich_geoip(alert)
        
        # Threat intelligence lookup
        await self._enrich_threat_intel(alert)
        
        # WHOIS enrichment
        await self._enrich_whois(alert)
        
        # ASN lookup
        await self._enrich_asn(alert)
        
        return alert
    
    async def _enrich_geoip(self, alert: ThreatAlert):
        """Add geographic information"""
        # In production, use MaxMind GeoIP or similar
        for ip in [alert.source_ip, alert.target_ip]:
            if ip and ip not in self.geoip_cache:
                self.geoip_cache[ip] = await self._lookup_geoip(ip)
            if ip in self.geoip_cache:
                alert.enriched_data[f"geoip_{ip.replace('.', '_')}"] = self.geoip_cache[ip]
    
    async def _lookup_geoip(self, ip: str) -> Dict:
        # Placeholder - integrate with MaxMind or similar
        return {"country": "XX", "city": "Unknown", "asn": "AS0"}
    
    async def _enrich_threat_intel(self, alert: ThreatAlert):
        """Check against threat intelligence feeds"""
        iocs = [alert.source_ip, alert.target_ip]
        for ioc in iocs:
            if ioc and ioc not in self.virustotal_cache:
                self.virustotal_cache[ioc] = await self._check_virustotal(ioc)
            if ioc in self.virustotal_cache:
                alert.enriched_data[f"vt_{ioc.replace('.', '_')}"] = self.virustotal_cache[ioc]
    
    async def _check_virustotal(self, ioc: str) -> Dict:
        # Placeholder for VirusTotal API
        return {"malicious": False, "suspicious": False, "undetected": True}
    
    async def _enrich_whois(self, alert: ThreatAlert):
        """Add WHOIS information"""
        # Placeholder for WHOIS lookup
        pass
    
    async def _enrich_asn(self, alert: ThreatAlert):
        """Add ASN information"""
        # Placeholder for ASN lookup
        pass


class AlertDeduplicator:
    """Deduplicate alerts to reduce noise"""
    
    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        self.recent_alerts: Dict[str, datetime] = {}
        self.alert_counts: Dict[str, int] = defaultdict(int)
    
    def is_duplicate(self, alert: 'ThreatAlert') -> bool:
        """Check if alert is duplicate"""
        # Create fingerprint
        fingerprint = self._fingerprint(alert)
        now = datetime.now()
        
        if fingerprint in self.recent_alerts:
            time_diff = (now - self.recent_alerts[fingerprint]).total_seconds()
            if time_diff < self.window_seconds:
                self.alert_counts[fingerprint] += 1
                return True
        
        self.recent_alerts[fingerprint] = now
        self.alert_counts[fingerprint] = 1
        return False
    
    def _fingerprint(self, alert: 'ThreatAlert') -> str:
        """Create fingerprint for deduplication"""
        key_parts = [
            alert.category,
            alert.severity,
            alert.source_ip,
            alert.target_ip,
            alert.category
        ]
        return hashlib.sha256("|".join(filter(None, key_parts)).encode()).hexdigest()
    
    def get_count(self, alert: 'ThreatAlert') -> int:
        fingerprint = self._fingerprint(alert)
        return self.alert_counts.get(self._fingerprint(alert), 0)
    
    def cleanup(self, max_age_seconds: int = 3600):
        """Remove old entries"""
        now = datetime.now()
        cutoff = now - timedelta(seconds=max_age_seconds)
        keys_to_remove = [
            k for k, v in self.recent_alerts.items()
            if v < cutoff
        ]
        for k in keys_to_remove:
            del self.recent_alerts[k]
            if k in self.alert_counts:
                del self.alert_counts[k]


class AlertCorrelator:
    """Correlate related alerts into incidents"""
    
    def __init__(self, time_window_seconds: int = 3600):
        self.time_window = timedelta(seconds=time_window_seconds)
        self.alerts_by_correlation: Dict[str, List] = defaultdict(list)
        self.correlation_rules = [
            self._correlate_by_source_ip,
            self._correlate_by_target_ip,
            self._correlate_by_category,
            self._correlate_by_indicators
        ]
    
    def correlate(self, alert: 'ThreatAlert') -> Optional[str]:
        """Find correlation ID for alert"""
        correlation_ids = set()
        
        for rule in self.correlation_rules:
            corr_id = rule(alert)
            if corr_id:
                correlation_ids.add(corr_id)
        
        if correlation_ids:
            # Use first correlation ID or create new
            corr_id = list(correlation_ids)[0]
            self.alerts_by_correlation[corr_id].append(alert)
            return corr_id
        
        # Create new correlation ID
        new_corr_id = f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}-{hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]}"
        self.alerts_by_correlation[new_corr_id].append(alert)
        return new_corr_id
    
    def _correlate_by_source_ip(self, alert: 'ThreatAlert') -> Optional[str]:
        """Find existing incident with same source IP"""
        for corr_id, alerts in self.alerts_by_correlation.items():
            for a in alerts:
                if a.source_ip == alert.source_ip:
                    return corr_id
        return None
    
    def _correlate_by_target_ip(self, alert: 'ThreatAlert') -> Optional[str]:
        for corr_id, alerts in self.alerts_by_correlation.items():
            for a in alerts:
                if a.target_ip == alert.target_ip:
                    return corr_id
        return None
    
    def _correlate_by_category(self, alert: 'ThreatAlert') -> Optional[str]:
        for corr_id, alerts in self.alerts_by_correlation.items():
            if len(alerts) > 3:  # Multiple alerts same category
                categories = [a.category for a in alerts]
                if categories.count(alert.category) > 2:
                    return corr_id
        return None
    
    def _correlate_by_indicators(self, alert: 'ThreatAlert') -> Optional[str]:
        for corr_id, alerts in self.alerts_by_correlation.items():
            for a in alerts:
                common = set(a.indicators) & set(alert.indicators)
                if len(common) > 1:
                    return corr_id
        return None
    
    def get_incident(self, correlation_id: str) -> List:
        return self.alerts_by_correlation.get(correlation_id, [])


class AlertManager:
    """Main alert management system"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.enricher = AlertEnricher(config.get('enrichment', {}))
        self.deduplicator = AlertDeduplicator(config.get('dedup_window', 300))
        self.correlator = AlertCorrelator(config.get('correlation_window', 3600))
        self.alert_store: Dict[str, ThreatAlert] = {}
        self.notification_handlers: List[Callable] = []
        self.severity_order = {
            "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 2, "CRITICAL": 3
        }
    
    def add_notification_handler(self, handler: Callable):
        """Add notification handler (email, Slack, PagerDuty, etc.)"""
        self.notification_handlers.append(handler)
    
    async def process_alert(self, alert: ThreatAlert) -> ThreatAlert:
        """Process incoming alert through full pipeline"""
        # Deduplicate
        if self.deduplicator.is_duplicate(alert):
            alert.description += f" (duplicate count: {self.deduplicator.get_count(alert)})"
            return alert
        
        # Enrich
        alert = await self.enricher.enrich(alert)
        
        # Correlate
        corr_id = self.correlator.correlate(alert)
        if corr_id:
            alert.correlation_id = alert.correlation_id or corr_id
        
        # Store
        self.alert_store[alert.alert_id] = alert
        
        # Notify
        await self._notify(alert)
        
        return alert
    
    async def _notify(self, alert: 'ThreatAlert'):
        """Send notifications"""
        for handler in self.notification_handlers:
            try:
                await handler(alert)
            except Exception as e:
                logger.error(f"Notification error: {e}")
    
    def get_alert(self, alert_id: str) -> Optional[ThreatAlert]:
        return self.alert_store.get(alert_id)
    
    def get_incident(self, correlation_id: str) -> List:
        return [a for a in self.correlator.alerts_by_correlation.get(correlation_id, [])]
    
    def get_alerts_by_severity(self, severity: str) -> List[ThreatAlert]:
        return [a for a in self.alert_store.values() if a.severity == severity]
    
    def get_alerts_by_status(self, status: str) -> List[ThreatAlert]:
        return [a for a in self.alert_store.values() if a.status == status]
    
    def acknowledge_alert(self, alert_id: str, user: str) -> bool:
        alert = self.alert_store.get(alert_id)
        if alert:
            alert.status = "ACKNOWLEDGED"
            alert.assigned_to = user
            return True
        return False
    
    def resolve_alert(self, alert_id: str, user: str, resolution: str) -> bool:
        alert = self.alert_store.get(alert_id)
        if alert:
            alert.status = "RESOLVED"
            alert.assigned_to = user
            alert.enriched_data["resolution"] = resolution
            return True
        return False
    
    def get_stats(self) -> Dict:
        total = len(self.alert_store)
        by_severity = defaultdict(int)
        by_status = defaultdict(int)
        by_category = defaultdict(int)
        
        for alert in self.alert_store.values():
            by_severity[alert.severity] += 1
            by_status[alert.status] += 1
            by_category[alert.category] += 1
        
        return {
            "total": total,
            "by_severity": dict(by_severity),
            "by_status": dict(by_status),
            "by_category": dict(by_category)
        }