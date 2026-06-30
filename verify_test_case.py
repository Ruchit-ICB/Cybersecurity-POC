import sys
from cybersec_platform.threat_detection import ThreatDetector
from cybersec_platform.feature_engineering import extract_features
from cybersec_platform.parsing import normalize_log_entry

test_log = """2026-06-29 18:12:04 CORE-GW-04 INFO Session initialized client_ip=172.16.24.88

2026-06-29 18:12:08 NETWORK INFO latency_ms=165 packet_loss=2.3% jitter_ms=12
2026-06-29 18:12:10 DNS WARN response_time_ms=240

2026-06-29 18:12:14 FIREWALL WARN inbound_connections=412 unique_ports=165 src_ip=203.0.113.45 duration=25s
2026-06-29 18:12:16 IDS ALERT signature=TCP_PORT_SCAN severity=MEDIUM confidence=0.89
2026-06-29 18:12:18 FIREWALL INFO action=BLOCK src_ip=203.0.113.45

2026-06-29 18:12:22 VULN_SCAN WARN host=172.16.24.88 service=ssh version=OpenSSH_7.2
2026-06-29 18:12:24 VULN_SCAN ALERT cve=CVE-2016-10012 severity=HIGH patch_status=UNPATCHED

2026-06-29 18:12:28 AUTH INFO login_status=SUCCESS user=admin mfa=ENABLED
2026-06-29 18:12:31 TRAFFIC INFO p2p_signatures=NONE malware_signatures=NONE c2_indicators=NONE

2026-06-29 18:12:35 SERVICE INFO internet=ACTIVE routing=STABLE
"""

detector = ThreatDetector()
lines = [l.strip() for l in test_log.splitlines() if l.strip()]
features = [extract_features(normalize_log_entry(l)) for l in lines]
detections = detector.detect(features)

print("="*60)
print(f"VERIFYING TEST CASE: {len(detections)} detections found")
print("="*60)
for d in detections:
    print(f"Type:       {d.get('threat_type')}")
    print(f"Status:     {d.get('threat_status')}")
    print(f"Severity:   {d.get('severity')}")
    print(f"Confidence: {d.get('confidence')}")
    print(f"IP:         {d.get('source_ip')}")
    print(f"Evidence:   {d.get('evidence')}")
    print("-"*60)
