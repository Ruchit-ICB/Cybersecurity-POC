#!/usr/bin/env python3
"""Debug script to identify which attack templates are failing."""

from datetime import datetime, timezone
from cybersec_platform.threat_detection import ThreatDetector
from cybersec_platform.integrations import ATTACK_TEMPLATES

detector = ThreatDetector()
now = datetime.now(timezone.utc)

print("Testing ATTACK_TEMPLATES...")
print("=" * 80)

failed = []
passed = []

for i, template in enumerate(ATTACK_TEMPLATES):
    log = template("10.0.0.1", now)
    analysis = detector.local_analyze_log(log)
    
    if analysis["status"] != "threat":
        failed.append((i, log, analysis))
        print(f"❌ FAIL [{i}]: {log[:100]}")
        print(f"   Status: {analysis['status']}, Probability: {analysis['probability']}%")
        print(f"   Reason: {analysis['reason']}")
    else:
        passed.append((i, log, analysis))

print("\n" + "=" * 80)
print(f"Results: {len(passed)} passed, {len(failed)} failed out of {len(ATTACK_TEMPLATES)} total")
print("=" * 80)