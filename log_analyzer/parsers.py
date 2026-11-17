"""
Log Parsers
Parsers for various log formats
"""
import re
import json
from datetime import datetime
from typing import Optional, Dict, Any
from dataclasses import dataclass
from log_analyzer.log_analyzer import LogEntry


@dataclass
class ParsedLog:
    timestamp: datetime
    level: str
    message: str
    raw: str
    fields: Dict = None
    source: str = "unknown"


def parse_syslog(line: str, source: str = "syslog") -> Optional[Dict]:
    """Parse syslog format (RFC3164/RFC5424)"""
    # RFC5424 format: <priority>timestamp hostname app[pid]: message
    rfc5424 = r'^<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)'
    # RFC3164 format: timestamp hostname tag[pid]: message
    rfc3164 = r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)'
    
    # Try RFC5424
    match = re.match(r'^<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)', line)
    if match:
        priority, version, timestamp, hostname, app_name, proc_id, msg_id, message = match.groups()[:8]
        return {
            "timestamp": timestamp,
            "host": hostname,
            "service": app_name,
            "pid": proc_id,
            "message": message,
            "level": "INFO",
            "raw": line
        }
    
    # Try RFC3164
    match = re.match(rfc3164, line)
    if match:
        timestamp_str, host, service, pid, message = match.groups()
        return {
            "timestamp": timestamp_str,
            "host": host,
            "service": service,
            "pid": pid,
            "message": message,
            "level": "INFO",
            "raw": line
        }
    
    return None


def parse_json_log(line: str, source: str = "json") -> Optional[Dict]:
    """Parse JSON log line"""
    try:
        data = json.loads(line)
        return {
            "timestamp": data.get("timestamp", data.get("@timestamp", "")),
            "level": data.get("level", data.get("severity", "INFO")),
            "message": data.get("message", data.get("msg", "")),
            "fields": data,
            "source": data.get("source", source)
        }
    except json.JSONDecodeError:
        return None


def parse_apache_log(line: str, source: str = "apache") -> Optional[Dict]:
    """Parse Apache Common/Combined Log Format"""
    # Common Log Format: ip ident auth [timestamp] "request" status size
    # Combined: + referrer user-agent
    clf_pattern = r'(\S+) (\S+) (\S+) \[(.*?)\] "(.*?)" (\d+) (\d+|-)'
    combined_pattern = r'(\S+) (\S+) (\S+) \[(.*?)\] "(.*?)" (\d+) (\d+|-) "(.*?)" "(.*?)"'
    
    match = re.match(combined_pattern, line)
    if match:
        ip, ident, auth, timestamp, request, status, size, referrer, ua = match.groups()
        return {
            "timestamp": timestamp,
            "client_ip": ip,
            "request": request,
            "status": int(status),
            "size": int(size) if size != '-' else 0,
            "referrer": referrer,
            "user_agent": ua,
            "source": "apache"
        }
    
    match = re.match(clf_pattern, line)
    if match:
        ip, ident, auth, timestamp, request, status, size = match.groups()
        return {
            "timestamp": timestamp,
            "client_ip": ip,
            "request": request,
            "status": int(status),
            "size": int(size) if size != '-' else 0,
            "source": "apache"
        }
    
    return None


def parse_nginx_log(line: str, source: str = "nginx") -> Optional[Dict]:
    """Parse Nginx access log (similar to Apache combined)"""
    return parse_apache_log(line, source)


def parse_docker_log(line: str, source: str = "docker") -> Optional[Dict]:
    """Parse Docker container logs"""
    # Docker JSON log format: {"log":"message","stream":"stdout","time":"2023-01-01T00:00:00.000Z"}
    try:
        import json
        data = json.loads(line)
        return {
            "timestamp": data.get("time", ""),
            "message": data.get("log", ""),
            "stream": data.get("stream", ""),
            "source": "docker"
        }
    except:
        return None


def parse_kubernetes_log(line: str, source: str = "kubernetes") -> Optional[Dict]:
    """Parse Kubernetes container logs"""
    # Kubernetes logs: timestamp stream namespace pod container message
    pattern = r'(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)'
    match = re.match(pattern, line)
    if match:
        timestamp, stream, namespace, pod, message = match.groups()
        return {
            "timestamp": timestamp,
            "stream": stream,
            "namespace": namespace,
            "pod": pod,
            "message": message,
            "source": "kubernetes"
        }
    return None


def parse_windows_event(line: str, source: str = "windows") -> Optional[Dict]:
    """Parse Windows Event Log (XML format)"""
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(line)
        event_data = {}
        for child in root:
            if child.tag.endswith('TimeCreated'):
                event_data['timestamp'] = child.attrib.get('SystemTime')
            elif child.tag.endswith('EventID'):
                event_data['event_id'] = child.text
            elif child.tag.endswith('Level'):
                event_data['level'] = child.text
            elif child.tag.endswith('Source'):
                event_data['source'] = child.attrib.get('Name')
            elif child.tag.endswith('Computer'):
                event_data['computer'] = child.text
            elif child.tag.endswith('Message'):
                event_data['message'] = child.text
            elif child.tag.endswith('Data'):
                name = child.attrib.get('Name', 'data')
                event_data[name] = child.text
        
        return {
            "timestamp": event_data.get('timestamp', ''),
            "level": event_data.get('level', 'INFO'),
            "event_id": event_data.get('event_id', ''),
            "source": event_data.get('source', 'windows'),
            "message": event_data.get('message', ''),
            "computer": event_data.get('computer', ''),
            "extra": event_data
        }
    except:
        return None


def parse_cisco_asa(line: str, source: str = "cisco_asa") -> Optional[Dict]:
    """Parse Cisco ASA firewall logs"""
    # Cisco ASA log format
    patterns = [
        # %ASA-6-302013: Built outbound TCP connection 123 for outside:1.2.3.4/1234 to inside:10.0.0.1/80
        r'%ASA-(\d+)-(\d+):\s+(.+)',
        # %ASA-4-106023: Deny tcp src outside:1.2.3.4/1234 dst inside:10.0.0.1/80 by access-group "inbound"
        r'%ASA-(\d+)-(\d+):\s+(.+)'
    ]
    
    for pattern in patterns:
        match = re.match(pattern, line)
        if match:
            severity, event_id, message = match.groups()
            return {
                "severity": severity,
                "event_id": event_id,
                "message": message,
                "source": "cisco_asa",
                "raw": line
            }
    return None


def parse_paloalto_log(line: str, source: str = "paloalto") -> Optional[Dict]:
    """Parse Palo Alto Networks firewall logs"""
    # Palo Alto CEF format
    cef_pattern = r'CEF:(\d+)\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|(.*)'
    match = re.match(cef_pattern, line)
    if match:
        version, device_vendor, device_product, device_version, signature_id, name, severity, extensions = match.groups()
        # Parse extensions
        extensions = {}
        for ext in extensions.split():
            if '=' in ext:
                key, value = ext.split('=', 1)
                extensions[key] = value
        
        return {
            "device_vendor": device_vendor,
            "device_product": device_product,
            "device_version": device_version,
            "signature_id": signature_id,
            "name": name,
            "severity": severity,
            "extensions": extensions,
            "source": "paloalto"
        }
    return None


def parse_fortigate_log(line: str, source: str = "fortigate") -> Optional[Dict]:
    """Parse FortiGate firewall logs"""
    # FortiGate log format
    if 'date=' in line and 'time=' in line:
        fields = {}
        for part in line.split():
            if '=' in part:
                key, value = part.split('=', 1)
                if key and value:
                    fields[key] = value
        
        return {
            "timestamp": f"{fields.get('date', '')} {fields.get('time', '')}",
            "level": fields.get('level', 'info'),
            "type": fields.get('type', ''),
            "subtype": fields.get('subtype', ''),
            "src_ip": fields.get('srcip', ''),
            "dst_ip": fields.get('dstip', ''),
            "src_port": fields.get('srcport', ''),
            "dst_port": fields.get('dstport', ''),
            "protocol": fields.get('proto', ''),
            "action": fields.get('action', ''),
            "policy_id": fields.get('policyid', ''),
            "message": line
        }
    return None


def parse_suricata_eve(line: str, source: str = "suricata") -> Optional[Dict]:
    """Parse Suricata EVE JSON logs"""
    try:
        import json
        data = json.loads(line)
        if data.get('event_type') == 'alert':
            alert = data.get('alert', {})
            return {
                "timestamp": data.get('timestamp', ''),
                "event_type": data.get('event_type'),
                "src_ip": data.get('src_ip'),
                "dest_ip": data.get('dest_ip'),
                "src_port": data.get('src_port'),
                "dest_port": data.get('dest_port'),
                "proto": data.get('proto'),
                "alert_signature_id": alert.get('signature_id'),
                "alert_signature": alert.get('signature'),
                "alert_category": alert.get('category'),
                "alert_severity": alert.get('severity'),
                "app_proto": data.get('app_proto'),
                "source": "suricata"
            }
        return {"event_type": data.get('event_type'), "raw": line}
    except:
        return None


def parse_zeek_log(line: str, source: str = "zeek") -> Optional[Dict]:
    """Parse Zeek (Bro) logs"""
    # Zeek TSV format with header
    if line.startswith('#'):
        return None
    
    parts = line.strip().split('\t')
    if len(parts) < 5:
        return None
    
    # Try to parse common Zeek log types
    return {
        "fields": parts,
        "source": "zeek"
    }


def parse_cloudtrail_log(line: str, source: str = "cloudtrail") -> Optional[Dict]:
    """Parse AWS CloudTrail logs"""
    try:
        import json
        data = json.loads(line)
        records = data.get('Records', [])
        results = []
        for record in records:
            results.append({
                "timestamp": record.get('eventTime'),
                "event_name": record.get('eventName'),
                "event_source": record.get('eventSource'),
                "user_identity": record.get('userIdentity', {}).get('arn', ''),
                "source_ip": record.get('sourceIPAddress'),
                "user_agent": record.get('userAgent'),
                "event_name": record.get('eventName'),
                "resource_type": record.get('resources', [{}])[0].get('type', ''),
                "resource_arn": record.get('resources', [{}])[0].get('ARN', ''),
                "region": record.get('awsRegion'),
                "source": "cloudtrail"
            })
        return results if results else None
    except:
        return None


def parse_gcp_audit_log(line: str, source: str = "gcp_audit") -> Optional[Dict]:
    """Parse GCP Cloud Audit Logs"""
    try:
        import json
        data = json.loads(line)
        proto_payload = data.get('protoPayload', {})
        return {
            "timestamp": data.get('timestamp'),
            "severity": data.get('severity'),
            "method_name": proto_payload.get('methodName'),
            "resource_name": proto_payload.get('resourceName'),
            "auth_info": proto_payload.get('authenticationInfo', {}),
            "request": proto_payload.get('request', {}),
            "response": proto_payload.get('response', {}),
            "resource": data.get('resource', {}),
            "source": "gcp_audit"
        }
    except:
        return None


def parse_azure_activity_log(line: str, source: str = "azure_activity") -> Optional[Dict]:
    """Parse Azure Activity Logs"""
    try:
        import json
        data = json.loads(line)
        return {
            "timestamp": data.get('time'),
            "operation_name": data.get('operationName'),
            "resource_id": data.get('resourceId'),
            "resource_group": data.get('resourceGroup'),
            "subscription_id": data.get('subscriptionId'),
            "caller": data.get('caller'),
            "category": data.get('category'),
            "result": data.get('resultType'),
            "source": "azure_activity"
        }
    except:
        return None


def parse_kubernetes_audit(line: str, source: str = "k8s_audit") -> Optional[Dict]:
    """Parse Kubernetes Audit Logs"""
    try:
        import json
        data = json.loads(line)
        return {
            "timestamp": data.get('timestamp'),
            "verb": data.get('verb'),
            "user": data.get('user', {}).get('username'),
            "groups": data.get('user', {}).get('groups', []),
            "source_ip": data.get('sourceIPs', []),
            "user_agent": data.get('userAgent'),
            "object_ref": data.get('objectRef', {}),
            "request_uri": data.get('requestURI'),
            "verb": data.get('verb'),
            "response_status": data.get('responseStatus', {}),
            "source": "k8s_audit"
        }
    except:
        return None


def parse_docker_log(line: str, source: str = "docker") -> Optional[Dict]:
    """Parse Docker container logs"""
    try:
        import json
        data = json.loads(line)
        return {
            "timestamp": data.get("time", ""),
            "message": data.get("log", "").strip(),
            "stream": data.get("stream", ""),
            "container_id": data.get("container", {}).get("id", ""),
            "container_name": data.get("container", {}).get("name", ""),
            "source": "docker"
        }
    except:
        return None


def parse_syslog_ng(line: str, source: str = "syslog_ng") -> Optional[Dict]:
    """Parse syslog-ng format"""
    # syslog-ng with custom template
    return parse_syslog(line, source)


def parse_rsyslog(line: str, source: str = "rsyslog") -> Optional[Dict]:
    """Parse rsyslog format"""
    return parse_syslog(line, source)


def parse_journald(line: str, source: str = "journald") -> Optional[Dict]:
    """Parse systemd journald logs"""
    # journald JSON format
    try:
        import json
        data = json.loads(line)
        return {
            "timestamp": data.get("__REALTIME_TIMESTAMP"),
            "message": data.get("MESSAGE"),
            "priority": data.get("PRIORITY"),
            "syslog_facility": data.get("SYSLOG_FACILITY"),
            "syslog_identifier": data.get("SYSLOG_IDENTIFIER"),
            "pid": data.get("_PID"),
            "uid": data.get("_UID"),
            "gid": data.get("_GID"),
            "comm": data.get("COMM"),
            "exe": data.get("_EXE"),
            "cmdline": data.get("_CMDLINE"),
            "systemd_unit": data.get("_SYSTEMD_UNIT"),
            "source": "journald"
        }
    except:
        return None


def auto_detect_parser(line: str) -> str:
    """Auto-detect log format"""
    line_stripped = line.strip()
    
    if line_stripped.startswith('{'):
        return 'json'
    elif line.startswith('<'):
        return 'syslog'
    elif line.startswith('#'):
        return 'comment'
    elif re.match(r'^\S+\s+\S+\s+\S+\s+\[.*\]\s+".*"', line):
        return 'apache'
    elif re.match(r'^\d+\.\d+\.\d+\.\d+\s', line):
        return 'apache'
    elif line.startswith('CEF:'):
        return 'cef'
    elif line.startswith('{'):
        return 'json'
    elif 'CEF:' in line:
        return 'cef'
    elif 'date=' in line and 'time=' in line:
        return 'fortigate'
    elif 'CEF:' in line:
        return 'cef'
    elif '"log":"' in line and '"stream"' in line:
        return 'docker'
    elif '"event_type":"alert"' in line:
        return 'suricata'
    elif '"event_type"' in line and 'Records' in line:
        return 'cloudtrail'
    elif 'protoPayload' in line:
        return 'gcp_audit'
    elif 'operationName' in line and 'resourceId' in line:
        return 'azure_activity'
    elif 'kubernetes.io' in line or 'k8s.io' in line:
        return 'k8s_audit'
    elif line.startswith('{') and '"log"' in line and '"stream"' in line:
        return 'docker'
    elif 'id="firewall"' in line or 'id="traffic"' in line:
        return 'paloalto'
    elif 'date=' in line and 'time=' in line and 'devname=' in line:
        return 'fortigate'
    elif '"event_type":"alert"' in line:
        return 'suricata'
    elif line.startswith('#'):
        return 'zeek'
    elif 'Records' in line and 'eventTime' in line:
        return 'cloudtrail'
    elif 'protoPayload' in line:
        return 'gcp_audit'
    elif 'operationName' in line and 'resourceId' in line:
        return 'azure_activity'
    elif 'kubernetes.io' in line or 'k8s.io' in line:
        return 'k8s_audit'
    elif line.startswith('{') and '"log"' in line and '"stream"' in line:
        return 'docker'
    else:
        return 'syslog'


def parse_log_line(line: str, source: str = "auto") -> Optional[Dict]:
    """Main entry point for parsing any log line"""
    if source == "auto":
        source = auto_detect_parser(line)
    
    parsers = {
        'syslog': parse_syslog,
        'json': parse_json_log,
        'apache': parse_apache_log,
        'nginx': parse_nginx_log,
        'cisco_asa': parse_cisco_asa_log,
        'paloalto': parse_paloalto_log,
        'fortigate': parse_fortigate_log,
        'suricata': parse_suricata_eve,
        'zeek': parse_zeek_log,
        'cloudtrail': parse_cloudtrail_log,
        'gcp_audit': parse_gcp_audit_log,
        'azure_activity': parse_azure_activity_log,
        'k8s_audit': parse_kubernetes_audit,
        'docker': parse_docker_log,
        'journald': parse_journald,
        'cisco_asa': parse_cisco_asa_log,
        'paloalto': parse_paloalto_log,
        'fortigate': parse_fortigate_log,
        'suricata': parse_suricata_eve,
        'zeek': parse_zeek_log,
        'cloudtrail': parse_cloudtrail_log,
        'gcp_audit': parse_gcp_audit_log,
        'azure_activity': parse_azure_activity_log,
        'k8s_audit': parse_kubernetes_audit,
        'docker': parse_docker_log,
        'journald': parse_journald,
    }
    
    parser = parsers.get(source, parse_syslog)
    return parser(line)