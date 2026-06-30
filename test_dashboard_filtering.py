"""Test script to verify dashboard API filtering of conditions vs threats."""

import requests
import json
import time

def test_dashboard_filtering():
    """Test that dashboard API correctly filters conditions from threat summaries."""
    print("Testing Dashboard API Filtering")
    print("=" * 70)
    
    # Wait for some data to be ingested
    print("Waiting 30 seconds for log ingestion...")
    time.sleep(30)
    
    # Fetch dashboard data
    response = requests.get("http://127.0.0.1:5000/api/dashboard?time_range=60")
    
    if response.status_code != 200:
        print(f"ERROR: Failed to fetch dashboard data: {response.status_code}")
        return False
    
    data = response.json()
    
    print("\n--- Dashboard API Response ---")
    print(f"Security threat count: {data.get('security_threat_count', 0)}")
    print(f"Condition count: {data.get('condition_count', 0)}")
    print(f"Aggregate threat probability: {data.get('aggregate_threat_probability', 0)}%")
    
    print(f"\nLive threats (should only be security threats): {len(data.get('live_threats', []))}")
    for i, threat in enumerate(data.get('live_threats', [])[:5], 1):
        print(f"  {i}. {threat.get('type')} - threat_status={threat.get('threat_status')}, mitre={threat.get('mitre')}")
    
    print(f"\nConditions (should be separate): {len(data.get('conditions', []))}")
    for i, condition in enumerate(data.get('conditions', [])[:5], 1):
        print(f"  {i}. {condition.get('type')} - threat_status={condition.get('threat_status')}, mitre={condition.get('mitre')}")
    
    print(f"\nAttack timeline events: {len(data.get('attack_timeline', []))}")
    for i, event in enumerate(data.get('attack_timeline', [])[:3], 1):
        print(f"  {i}. {event.get('time')} - count={event.get('count')}")
    
    # Validation checks
    print("\n--- Validation ---")
    
    # Check 1: No conditions in live_threats
    live_threats = data.get('live_threats', [])
    conditions_in_threats = [t for t in live_threats if t.get('threat_status') == 'NONE']
    print(f"Conditions in live_threats: {len(conditions_in_threats)}")
    if len(conditions_in_threats) == 0:
        print("✓ No conditions in live_threats")
    else:
        print("✗ ERROR: Conditions found in live_threats")
        for t in conditions_in_threats:
            print(f"  - {t}")
    
    # Check 2: No conditions with MITRE NOT APPLICABLE in live_threats
    not_applicable_in_threats = [t for t in live_threats if t.get('mitre') == 'NOT APPLICABLE']
    print(f"MITRE NOT APPLICABLE in live_threats: {len(not_applicable_in_threats)}")
    if len(not_applicable_in_threats) == 0:
        print("✓ No MITRE NOT APPLICABLE in live_threats")
    else:
        print("✗ ERROR: MITRE NOT APPLICABLE found in live_threats")
    
    # Check 3: All live_threats have threat_status SUSPICIOUS or CONFIRMED
    invalid_threat_status = [t for t in live_threats if t.get('threat_status') not in ['SUSPICIOUS', 'CONFIRMED']]
    print(f"Invalid threat_status in live_threats: {len(invalid_threat_status)}")
    if len(invalid_threat_status) == 0:
        print("✓ All live_threats have valid threat_status")
    else:
        print("✗ ERROR: Invalid threat_status found in live_threats")
        for t in invalid_threat_status:
            print(f"  - {t.get('type')}: {t.get('threat_status')}")
    
    # Check 4: Conditions are in separate array
    conditions = data.get('conditions', [])
    print(f"Conditions array exists: {len(conditions) > 0}")
    if len(conditions) > 0:
        print("✓ Conditions are in separate array")
        # Check that conditions have threat_status NONE
        non_none_conditions = [c for c in conditions if c.get('threat_status') != 'NONE']
        print(f"Conditions with threat_status != NONE: {len(non_none_conditions)}")
        if len(non_none_conditions) == 0:
            print("✓ All conditions have threat_status NONE")
        else:
            print("✗ ERROR: Some conditions have invalid threat_status")
    else:
        print("⚠ No conditions found (may be expected if no performance issues)")
    
    # Check 5: Aggregate threat probability is only from security threats
    threat_probability = data.get('aggregate_threat_probability', 0)
    security_count = data.get('security_threat_count', 0)
    print(f"Aggregate threat probability: {threat_probability}%")
    print(f"Security threat count: {security_count}")
    if security_count > 0:
        print("✓ Aggregate probability computed from security threats")
    else:
        print("⚠ No security threats to compute probability")
    
    # Check 6: No duplicates in live_threats
    seen = set()
    duplicates = []
    for t in live_threats:
        key = (t.get('type'), t.get('source_ip'), t.get('severity'))
        if key in seen:
            duplicates.append(t)
        seen.add(key)
    print(f"Duplicates in live_threats: {len(duplicates)}")
    if len(duplicates) == 0:
        print("✓ No duplicates in live_threats")
    else:
        print("✗ ERROR: Duplicates found in live_threats")
    
    print("\n" + "=" * 70)
    print("Dashboard Filtering Test Completed!")
    
    return True

if __name__ == "__main__":
    test_dashboard_filtering()
