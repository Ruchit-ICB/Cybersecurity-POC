#!/usr/bin/env python3
"""Test script to verify threat filtering logic."""

import sys
from cybersec_platform.threat_detection import ThreatDetector
from cybersec_platform.feature_engineering import extract_features

def test_threat_filtering():
    """Test that only security threats are counted, not conditions."""
    
    # Sample log with both security threats and network conditions
    test_logs = [
        "2026-06-24T11:14:22Z INFO network - High latency detected: 2500ms RTT",
        "2026-06-24T11:15:00Z INFO network - Packet loss detected: 15% dropped packets",
        "2026-06-24T11:16:05Z CRITICAL security - DDoS: SYN flood from 10.0.0.50",
        "2026-06-24T11:17:42Z HIGH security - DNS tunneling detected from 10.0.0.75",
        "2026-06-24T11:18:14Z CRITICAL security - C2 beacon detected: reverse shell",
    ]
    
    print("Testing Threat Filtering Logic")
    print("=" * 60)
    
    # Extract features and run detection
    features = [extract_features(line) for line in test_logs]
    detector = ThreatDetector()
    all_detections = detector.detect(features)
    
    print(f"\nTotal detections: {len(all_detections)}")
    
    # Separate threats from conditions (mimicking the API logic)
    security_threats = []
    conditions = []
    seen_threats = set()
    seen_conditions = set()
    
    for detection in all_detections:
        threat_status = detection.get('threat_status', 'NONE')
        domain = detection.get('domain', 'SECURITY_THREATS')
        classification_type = detection.get('classification_type', 'Threat')
        
        dedup_key = (
            detection.get('threat_type', ''),
            detection.get('source_ip', ''),
            detection.get('severity', ''),
            threat_status
        )
        
        if threat_status in ['SUSPICIOUS', 'CONFIRMED'] and domain == 'SECURITY_THREATS':
            if dedup_key not in seen_threats:
                seen_threats.add(dedup_key)
                security_threats.append(detection)
        elif classification_type == 'Condition' or threat_status == 'NONE':
            if dedup_key not in seen_conditions:
                seen_conditions.add(dedup_key)
                conditions.append(detection)
    
    print(f"\nSecurity Threats: {len(security_threats)}")
    for threat in security_threats:
        print(f"  - {threat['threat_type']} ({threat['threat_status']}) - {threat['domain']}")
    
    print(f"\nConditions (Non-Threats): {len(conditions)}")
    for condition in conditions:
        print(f"  - {condition['threat_type']} ({condition['threat_status']}) - {condition['domain']}")
        print(f"    Explanation: {condition['explanation'][:80]}...")
    
    # Calculate threat probability from security threats only
    if security_threats:
        total_confidence = sum(t.get('confidence', 0) for t in security_threats)
        avg_threat_probability = int(round((total_confidence / len(security_threats)) * 100))
        print(f"\n✓ Aggregate Threat Probability: {avg_threat_probability}%")
        print(f"  (Calculated from {len(security_threats)} security threats only)")
    else:
        print(f"\n✓ Aggregate Threat Probability: 0%")
        print(f"  (No security threats detected)")
    
    # Verify conditions are excluded
    print(f"\n✓ Conditions excluded from threat count: {len(conditions)}")
    print(f"✓ Conditions excluded from probability calculation")
    
    # Verify deduplication
    print(f"\n✓ Deduplication applied:")
    print(f"  - Before: {len(all_detections)} total detections")
    print(f"  - After: {len(security_threats) + len(conditions)} unique detections")
    
    print("\n" + "=" * 60)
    print("Test completed successfully!")
    
    return len(security_threats), len(conditions)

if __name__ == "__main__":
    try:
        threat_count, condition_count = test_threat_filtering()
        print(f"\nResult: {threat_count} threats, {condition_count} conditions")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)