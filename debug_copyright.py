from datetime import datetime, timezone
from cybersec_platform.threat_detection import ThreatDetector
from cybersec_platform.feature_engineering import extract_features

detector = ThreatDetector()
now = datetime.now(timezone.utc)

log = '{"timestamp": "2026-06-29T10:04:17.566565+00:00Z", "level": "WARN", "message": "Copyright infringement: torrent traffic from 10.0.0.1 — DMCA violation detected"}'

print("Testing Copyright Infringement Detection")
print("=" * 80)
print(f"Log: {log}\n")

# Extract features and detect
features = extract_features(log)
print(f"Features: {features}\n")

all_detections = detector.detect([features])
print(f"Total detections: {len(all_detections)}\n")

for i, det in enumerate(all_detections):
    print(f"Detection {i}:")
    print(f"  threat_type: {det.get('threat_type')}")
    print(f"  domain: {det.get('domain')}")
    print(f"  classification_type: {det.get('classification_type')}")
    print(f"  threat_status: {det.get('threat_status')}")
    print(f"  severity: {det.get('severity')}")
    print(f"  confidence: {det.get('confidence')}")
    print(f"  explanation: {det.get('explanation')[:100]}...")
    print()

security_threats = []
conditions = []
seen_threats = set()
seen_conditions = set()

for detection in all_detections:
    threat_status = detection.get('threat_status', 'NONE')
    domain = detection.get('domain', 'SECURITY_THREATS')
    classification_type = detection.get('classification_type', 'Threat')
    
    print(f"Filtering check:")
    print(f"  threat_status: {threat_status}")
    print(f"  domain: {domain}")
    print(f"  classification_type: {classification_type}")
    
    is_threat_or_compliance = (
        (threat_status in ['SUSPICIOUS', 'CONFIRMED'] and domain == 'SECURITY_THREATS') or
        (classification_type in ['Threat', 'Classification'] and domain in ['SECURITY_THREATS', 'COMPLIANCE'])
    )
    
    print(f"  is_threat_or_compliance: {is_threat_or_compliance}")
    print()

print("=" * 80)
print(f"Analysis result: {detector.local_analyze_log(log)}")