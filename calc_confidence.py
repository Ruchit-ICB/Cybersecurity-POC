
import hashlib

from cybersec_platform.feature_engineering import extract_features
from cybersec_platform.threat_detection import ThreatDetector, INDICATOR_PATTERNS

detector = ThreatDetector()
log = (
    '{"timestamp": "2026-06-24T12:00:00Z", "level": "WARN", '
    '"message": "Failed SSH login from 192.168.1.50"}'
)

features = extract_features(log)
isp_features = [features]
print("Features:")
for k, v in features.items():
    print(f"  {k}: {v}")

# Let's run the calculations from detect()
X_numeric = []
for row in isp_features:
    X_numeric.append([
        row.get("message_length", 0),
        row.get("status_code", 0),
        row.get("bytes_sent", 0),
        row.get("cpu", 0.0),
        row.get("memory", 0.0),
        row.get("network_tx", 0.0),
        row.get("network_rx", 0.0)
    ])

anomalies = detector.anomaly_detector.predict(X_numeric)
anomaly_scores = detector.anomaly_detector.anomaly_scores(X_numeric)
classifications = detector.classifier.predict(X_numeric)
confidences = detector.classifier.predict_proba(X_numeric)
print(f"Anomaly scores: {anomaly_scores}")
print(f"Classifier confidences: {confidences}")

pattern = [x for x in INDICATOR_PATTERNS if x["name"] == "Brute-Force Authentication"][0]
sev = pattern["severity"]
base = {"critical":0.95,"high":0.88,"medium":0.80,"low":0.70}[sev]

print(f"sev: {sev}, base: {base}")

msg = features["raw_message"]
pat_idx = 0

has_direct = detector._has_direct_indicator(pattern["name"], msg)
print(f"has_direct: {has_direct}")
anom = anomaly_scores[0]
clf_conf = confidences[0]

seed = hashlib.md5(f"{msg}:{pattern['name']}:{pat_idx}".encode()).hexdigest()
jitter = (int(seed[:8], 16) % 1000)/10000.0 -0.05
print(f"seed: {seed}")
print(f"jitter: {jitter}")

raw_conf = 0.7 * base + 0.2 * anom + 0.1 * clf_conf + jitter + (0.15 if has_direct else 0)
confidence = round(min(0.99, max(0.30, raw_conf)), 3)

print(f"raw_conf: {raw_conf}")
print(f"confidence: {confidence}")

threat_status = detector._determine_threat_status(confidence)
print("threat status:", threat_status)
