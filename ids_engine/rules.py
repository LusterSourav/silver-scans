"""
IDS Detection Rules
Signature-based and behavioral detection rules
"""
from typing import Callable, Optional
from dataclasses import dataclass, field
from typing import Dict, Any, List
from datetime import datetime


@dataclass
class Rule:
    """Detection rule for IDS"""
    name: str
    category: str
    severity: str
    description: str
    match_fn: Callable[['NetworkPacket'], bool]
    metadata: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.now)
    
    def match(self, packet: 'NetworkPacket') -> bool:
        """Check if packet matches this rule"""
        if not self.enabled:
            return False
        try:
            return self.match_fn(packet)
        except Exception:
            return False


def load_rules(config_path: Optional[str] = None) -> List[Rule]:
    """Load rules from configuration"""
    from .ids_engine import DEFAULT_RULES
    rules = list(DEFAULT_RULES)
    
    if config_path:
        # Load custom rules from file
        import yaml
        with open(config_path) as f:
            config = yaml.safe_load(f)
            for rule_config in config.get('rules', []):
                rules.append(Rule(
                    name=rule_config['name'],
                    category=rule_config['category'],
                    severity=rule_config['severity'],
                    description=rule_config['description'],
                    match_fn=_compile_match_fn(rule_config['match']),
                    metadata=rule_config.get('metadata', {})
                ))
    
    return rules


def _compile_match_fn(match_config: Dict[str, Any]) -> Callable:
    """Compile match function from config"""
    match_type = match_config.get('type', 'simple')
    
    if match_type == 'simple':
        field = match_config.get('field')
        value = match_config.get('value')
        operator = match_config.get('operator', 'eq')
        
        def match_fn(packet):
            packet_value = getattr(packet, field, None)
            if packet_value is None:
                return False
            if operator == 'eq':
                return packet_value == value
            elif operator == 'contains':
                return value in str(packet_value)
            elif operator == 'regex':
                import re
                return bool(re.search(value, str(packet_value)))
            return False
        return match_fn
    
    elif match_type == 'lambda':
        # Dangerous but allows complex rules
        code = match_config.get('code', '')
        if code:
            return eval(f"lambda p: {code}")
        return lambda p: False
    
    elif match_type == 'composite':
        sub_rules = match_config.get('rules', [])
        logic = match_config.get('logic', 'and')
        
        sub_fns = [_compile_match_fn(r) for r in sub_rules]
        if logic == 'and':
            return lambda p: all(fn(p) for fn in sub_fns)
        elif logic == 'or':
            return lambda p: any(fn(p) for fn in sub_fns)
        return lambda p: False
    
    return lambda p: False


# Pre-built rule sets
WEB_ATTACK_RULES = [
    {
        'name': 'SQL_INJECTION',
        'category': 'WEB_ATTACK',
        'severity': 'HIGH',
        'description': 'SQL injection attempt',
        'match': {
            'type': 'composite',
            'logic': 'or',
            'rules': [
                {'type': 'simple', 'field': 'payload', 'value': 'union select', 'operator': 'contains'},
                {'type': 'simple', 'field': 'payload', 'value': "' or 1=1", 'operator': 'contains'},
                {'type': 'simple', 'field': 'payload', 'value': 'drop table', 'operator': 'contains'},
                {'type': 'simple', 'field': 'payload', 'value': 'insert into', 'operator': 'contains'},
                {'type': 'simple', 'field': 'payload', 'value': 'delete from', 'operator': 'contains'}
            ]
        }
    },
    {
        'name': 'XSS_ATTEMPT',
        'category': 'WEB_ATTACK',
        'severity': 'HIGH',
        'description': 'Cross-site scripting attempt',
        'match': {
            'type': 'composite',
            'logic': 'or',
            'rules': [
                {'type': 'simple', 'field': 'payload', 'value': '<script', 'operator': 'contains'},
                {'type': 'simple', 'field': 'payload', 'value': 'javascript:', 'operator': 'contains'},
                {'type': 'simple', 'field': 'payload', 'value': 'onerror=', 'operator': 'contains'},
                {'type': 'simple', 'field': 'payload', 'value': 'onload=', 'operator': 'contains'},
                {'type': 'simple', 'field': 'payload', 'value': 'alert(', 'operator': 'contains'}
            ]
        }
    },
    {
        'name': 'PATH_TRAVERSAL',
        'category': 'WEB_ATTACK',
        'severity': 'HIGH',
        'description': 'Path traversal attempt',
        'match': {
            'type': 'composite',
            'logic': 'or',
            'rules': [
                {'type': 'simple', 'field': 'payload', 'value': '../', 'operator': 'contains'},
                {'type': 'simple', 'field': 'payload', 'value': '..\\', 'operator': 'contains'},
                {'type': 'simple', 'field': 'payload', 'value': '%2e%2e%2f', 'operator': 'contains'},
                {'type': 'simple', 'field': 'payload', 'value': '..%2f', 'operator': 'contains'}
            ]
        }
    }
]

MALWARE_C2_RULES = [
    {
        'name': 'SUSPICIOUS_DNS',
        'category': 'MALWARE_C2',
        'severity': 'HIGH',
        'description': 'Suspicious DNS queries to known C2 domains',
        'match': {
            'type': 'lambda',
            'code': 'p.dst_port == 53 and any(c2 in str(p.payload).lower() for c2 in ["c2.", "cmd.", "control.", "beacon"])'
        }
    },
    {
        'name': 'SUSPICIOUS_USER_AGENT',
        'category': 'MALWARE_C2',
        'severity': 'MEDIUM',
        'description': 'Suspicious user agent string',
        'match': {
            'type': 'lambda',
            'code': 'b"bot" in p.payload.lower() or b"crawler" in p.payload.lower() or b"scan" in p.payload.lower()'
        }
    }
]

EXPLOIT_RULES = [
    {
        'name': 'ETERNALBLUE',
        'category': 'EXPLOIT',
        'severity': 'CRITICAL',
        'description': 'EternalBlue SMB exploit attempt',
        'match': {
            'type': 'lambda',
            'code': 'p.dst_port == 445 and b"\\x00\\x00\\x00\\x00" in p.payload[:4]'
        }
    },
    {
        'name': 'LOG4J_EXPLOIT',
        'category': 'EXPLOIT',
        'severity': 'CRITICAL',
        'description': 'Log4Shell JNDI injection',
        'match': {
            'type': 'composite',
            'logic': 'or',
            'rules': [
                {'type': 'simple', 'field': 'payload', 'value': '${jndi:', 'operator': 'contains'},
                {'type': 'simple', 'field': 'payload', 'value': 'jndi:', 'operator': 'contains'},
                {'type': 'simple', 'field': 'payload', 'value': '${::-', 'operator': 'contains'}
            ]
        }
    },
    {
        'name': 'SPRING4SHELL',
        'category': 'EXPLOIT',
        'severity': 'CRITICAL',
        'description': 'Spring4Shell RCE attempt',
        'match': {
            'type': 'lambda',
            'code': 'b"class.module.classloader" in p.payload or b"class.module.classLoader" in p.payload'
        }
    }
]

BRUTE_FORCE_RULES = [
    {
        'name': 'SSH_BRUTE_FORCE',
        'category': 'BRUTE_FORCE',
        'severity': 'HIGH',
        'description': 'SSH brute force attempt',
        'match': {
            'type': 'composite',
            'logic': 'and',
            'rules': [
                {'type': 'simple', 'field': 'dst_port', 'value': 22, 'operator': 'eq'},
                {'type': 'simple', 'field': 'flags', 'value': 'syn', 'operator': 'contains'}
            ]
        }
    },
    {
        'name': 'RDP_BRUTE_FORCE',
        'category': 'BRUTE_FORCE',
        'severity': 'HIGH',
        'description': 'RDP brute force attempt',
        'match': {
            'type': 'composite',
            'logic': 'and',
            'rules': [
                {'type': 'simple', 'field': 'dst_port', 'value': 3389, 'operator': 'eq'},
                {'type': 'simple', 'field': 'flags', 'value': 'syn', 'operator': 'contains'}
            ]
        }
    },
    {
        'name': 'FTP_BRUTE_FORCE',
        'category': 'BRUTE_FORCE',
        'severity': 'HIGH',
        'description': 'FTP brute force attempt',
        'match': {
            'type': 'composite',
            'logic': 'and',
            'rules': [
                {'type': 'simple', 'field': 'dst_port', 'value': 21, 'operator': 'eq'},
                {'type': 'simple', 'field': 'flags', 'value': 'syn', 'operator': 'contains'}
            ]
        }
    }
]

RECONNAISSANCE_RULES = [
    {
        'name': 'PORT_SCAN',
        'category': 'RECONNAISSANCE',
        'severity': 'MEDIUM',
        'description': 'Port scanning activity',
        'match': {
            'type': 'lambda',
            'code': 'p.flags.get("syn", False) and p.flags.get("rst", False)'
        }
    },
    {
        'name': 'NULL_SCAN',
        'category': 'RECONNAISSANCE',
        'severity': 'MEDIUM',
        'description': 'NULL scan (no flags)',
        'match': {
            'type': 'lambda',
            'code': 'not any(p.flags.values())'
        }
    },
    {
        'name': 'FIN_SCAN',
        'category': 'RECONNAISSANCE',
        'severity': 'MEDIUM',
        'description': 'FIN scan',
        'match': {'type': 'simple', 'field': 'flags', 'value': 'fin', 'operator': 'contains'}
    },
    {
        'name': 'XMAS_SCAN',
        'category': 'RECONNAISSANCE',
        'severity': 'MEDIUM',
        'description': 'XMAS scan (FIN, PSH, URG)',
        'match': {
            'type': 'composite',
            'logic': 'and',
            'rules': [
                {'type': 'simple', 'field': 'flags', 'value': 'fin', 'operator': 'contains'},
                {'type': 'simple', 'field': 'flags', 'value': 'psh', 'operator': 'contains'},
                {'type': 'simple', 'field': 'flags', 'value': 'urg', 'operator': 'contains'}
            ]
        }
    }
]

# Combined rule sets
ALL_RULES = (
    DEFAULT_RULES +
    [Rule(
        name=r['name'],
        category=r['category'],
        severity=r['severity'],
        description=r['description'],
        match_fn=_compile_match_fn(r['match'])
    ) for r in WEB_ATTACK_RULES + MALWARE_C2_RULES + EXPLOIT_RULES + BRUTE_FORCE_RULES + RECONNAISSANCE_RULES]
)