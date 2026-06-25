from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List

from .parsing import normalize_log_entry


def extract_features(raw_message: str) -> Dict[str, Any]:
    """Extract standard features from a raw log entry for ML processing."""
    entry = normalize_log_entry(raw_message)
    
    features: Dict[str, Any] = {}
    
    # 1. Standard Identity and Context Extraction
    features["timestamp"] = entry.get("timestamp")
    features["source_ip"] = entry.get("remote_addr") or entry.get("src_ip") or entry.get("source_ip") or "unknown"
    features["destination_ip"] = entry.get("dst_ip") or entry.get("destination_ip") or "unknown"
    features["username"] = entry.get("user") or entry.get("username") or "unknown"
    features["hostname"] = entry.get("host") or entry.get("hostname") or "unknown"
    features["process_id"] = entry.get("pid") or entry.get("process") or "unknown"
    
    # 2. HTTP / Web specific features
    features["http_method"] = entry.get("http_method") or "unknown"
    features["url"] = entry.get("request_uri") or entry.get("url") or ""
    features["status_code"] = int(entry.get("status", 0)) if entry.get("status") else 0
    features["bytes_sent"] = int(entry.get("body_bytes_sent", 0)) if entry.get("body_bytes_sent") else 0
    features["user_agent"] = entry.get("http_user_agent") or ""
    
    # 3. Log Metadata
    features["message_length"] = len(entry.get("raw_message", ""))
    features["severity"] = str(entry.get("level") or entry.get("severity") or "info").lower()
    features["format"] = entry.get("format", "unknown")
    
    # 4. Numeric metrics (if present in JSON logs)
    numeric_metrics = defaultdict(float)
    for metric in ["cpu", "memory", "disk", "network"]:
        value = entry.get(metric)
        if value is not None:
            try:
                numeric_metrics[metric] = float(value)
            except ValueError:
                numeric_metrics[metric] = 0.0
    features.update(numeric_metrics)
    
    # Keep raw message for NLP/Transformer models downstream
    features["raw_message"] = entry.get("raw_message", "")
    
    return features


def aggregate_window(features_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Perform sliding-window feature extraction on a batch of logs.
    e.g., failed logins per IP, total requests per minute, etc.
    """
    if not features_list:
        return {}
        
    aggregated = {
        "total_events": len(features_list),
        "unique_sources": len({f.get("source_ip") for f in features_list if f.get("source_ip") != "unknown"}),
        "unique_users": len({f.get("username") for f in features_list if f.get("username") != "unknown"}),
        "avg_message_length": sum(f.get("message_length", 0) for f in features_list) / max(1, len(features_list)),
    }
    
    # High-level behavioral counting
    failed_logins = 0
    auth_sources = set()
    for f in features_list:
        msg = f.get("raw_message", "").lower()
        if "failed" in msg and ("password" in msg or "login" in msg):
            failed_logins += 1
            if f.get("source_ip") != "unknown":
                auth_sources.add(f.get("source_ip"))
                
    aggregated["failed_login_count"] = failed_logins
    aggregated["suspicious_auth_sources"] = len(auth_sources)
    
    return aggregated
