import json
import re
from typing import Any, Dict

from .utils import parse_timestamp, safe_json_load

# Apache/Nginx combined log format
APACHE_LOG_PATTERN = re.compile(
    r"^(?P<remote_addr>\S+) \S+ \S+ \[(?P<time_local>[^\]]+)\] \"(?P<request>[A-Z]+) (?P<request_uri>\S+) [^\"]+\" (?P<status>\d{3}) (?P<body_bytes_sent>\d+)(?: \"(?P<http_referer>[^\"]*)\" \"(?P<http_user_agent>[^\"]*)\")?"
)

# Standard Syslog format (e.g. "Jun 24 11:15:00 hostname sshd[123]: Failed password")
SYSLOG_PATTERN = re.compile(
    r"^(?P<time_local>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<process>[^:]+):\s+(?P<message>.*)$"
)

# Key=Value format (e.g. "ts=2026-06-24 level=INFO msg=hello")
KV_PATTERN = re.compile(r"([a-zA-Z0-9_]+)=([^\s]+)")


def detect_log_format(raw_message: str) -> str:
    """Heuristically determine the format of a raw log line."""
    raw_message = raw_message.strip()
    
    # Try JSON
    if raw_message.startswith("{") and raw_message.endswith("}"):
        try:
            json.loads(raw_message)
            return "json"
        except ValueError:
            pass

    # Try Regexes
    if APACHE_LOG_PATTERN.match(raw_message):
        return "apache_or_nginx"
        
    if SYSLOG_PATTERN.match(raw_message):
        return "syslog"
        
    # Try Key-Value
    if len(KV_PATTERN.findall(raw_message)) > 2:
        return "key_value"
        
    # Try CSV
    if raw_message.count(",") > 3 and not "{" in raw_message:
        return "csv"
        
    return "text"


def normalize_log_entry(raw_message: str) -> Dict[str, Any]:
    """Parse a raw log string into a structured dictionary."""
    raw_message = raw_message.strip()
    format_name = detect_log_format(raw_message)
    
    normalized: Dict[str, Any] = {
        "raw_message": raw_message,
        "format": format_name,
    }

    if format_name == "json":
        parsed = safe_json_load(raw_message)
        if isinstance(parsed, dict):
            normalized.update(parsed)
            
    elif format_name == "apache_or_nginx":
        match = APACHE_LOG_PATTERN.match(raw_message)
        if match:
            normalized.update(match.groupdict())
            normalized["timestamp"] = parse_timestamp(normalized.get("time_local", ""))
            if "request" in normalized:
                normalized["http_method"] = normalized["request"]
                
    elif format_name == "syslog":
        match = SYSLOG_PATTERN.match(raw_message)
        if match:
            normalized.update(match.groupdict())
            # Simple timestamp conversion (syslog doesn't include year by default)
            normalized["timestamp"] = parse_timestamp(normalized.get("time_local", ""))
            
    elif format_name == "key_value":
        pairs = KV_PATTERN.findall(raw_message)
        for key, value in pairs:
            normalized[key] = value
            
    elif format_name == "csv":
        parts = raw_message.split(",")
        normalized["csv_fields"] = [part.strip() for part in parts]
        
    else:
        # Fallback for plain text or generic logs. 
        # Tries to pull out timestamps or IP addresses if possible.
        normalized["message"] = raw_message
        
    # Ensure every entry has at least a message field
    if "message" not in normalized and "raw_message" in normalized:
         normalized["message"] = normalized["raw_message"]

    return normalized
