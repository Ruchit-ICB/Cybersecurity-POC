
from datetime import datetime, timezone
from cybersec_platform.threat_detection import ThreatDetector

detector = ThreatDetector()

log = (
    '{"timestamp": "2026-06-24T12:00:00Z", "level": "WARN", '
    '"message": "Failed SSH login from 192.168.1.50"}'
)
result = detector.local_analyze_log(log)
print("Result for failed SSH:")
print(result)

print("\n--- Now let's call detect directly ---")
from cybersec_platform.feature_engineering import extract_features
features_list = [extract_features(log)]
detections = detector.detect(features_list)
print("Detections from detect():", detections)
for det in detections:
    print("  Detection confidence:", det.get("confidence"))
