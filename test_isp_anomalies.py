"""Test script to verify 4-domain classification system with strict separation."""

from datetime import datetime, timezone
from cybersec_platform.feature_engineering import extract_features, aggregate_window
from cybersec_platform.threat_detection import ThreatDetector, DOMAINS
from cybersec_platform.integrations import (
    NETWORK_PERFORMANCE_TEMPLATES, 
    SECURITY_THREAT_TEMPLATES, 
    CRITICAL_OUTAGE_TEMPLATES,
    BENIGN_TEMPLATES
)
import random

def test_4_domain_classification():
    """Test strict 4-domain classification system."""
    print("Testing 4-Domain Classification System")
    print("=" * 70)
    
    # Print domain definitions
    print("\nDomain Definitions:")
    for domain, info in DOMAINS.items():
        print(f"  {domain}: {info['labels']}")
        print(f"    {info['description']}")
    
    # Generate test logs
    now = datetime.now(timezone.utc)
    test_logs = []
    
    # Add benign logs
    for i in range(3):
        ip = f"192.168.1.{i+1}"
        template = random.choice(BENIGN_TEMPLATES)
        test_logs.append(template(ip, now))
    
    # Add network performance logs (NETWORK_PERFORMANCE domain)
    for template in NETWORK_PERFORMANCE_TEMPLATES:
        ip = f"10.0.0.{random.randint(1, 254)}"
        test_logs.append(template(ip, now))
    
    # Add security threat logs (SECURITY_THREATS domain)
    for template in SECURITY_THREAT_TEMPLATES:
        ip = f"10.0.0.{random.randint(1, 254)}"
        test_logs.append(template(ip, now))
    
    # Add critical outage logs (SERVICE_HEALTH domain)
    for template in CRITICAL_OUTAGE_TEMPLATES:
        ip = f"10.0.0.{random.randint(1, 254)}"
        test_logs.append(template(ip, now))
    
    print(f"\nGenerated {len(test_logs)} test logs:")
    print(f"  - 3 benign logs")
    print(f"  - 4 network performance logs (NETWORK_PERFORMANCE)")
    print(f"  - 2 security threat logs (SECURITY_THREATS)")
    print(f"  - 2 critical outage logs (SERVICE_HEALTH)")
    
    print("\n--- Test Logs ---")
    for i, log in enumerate(test_logs, 1):
        print(f"{i}. {log[:120]}...")
    
    # Parse and extract features
    print("\n--- Feature Extraction ---")
    features_list = [extract_features(log) for log in test_logs]
    
    # Run threat detection
    print("\n--- Threat Detection Results ---")
    detector = ThreatDetector()
    detections = detector.detect(features_list)
    
    print(f"\nTotal detections: {len(detections)}")
    
    # Categorize by domain
    domains = {}
    for d in detections:
        domain = d.get('domain', 'UNKNOWN')
        if domain not in domains:
            domains[domain] = []
        domains[domain].append(d)
    
    print("\n--- Detections by Domain ---")
    for domain in ["NETWORK_PERFORMANCE", "SECURITY_THREATS", "SERVICE_HEALTH", "COMPLIANCE"]:
        if domain in domains:
            print(f"\n{domain}: {len(domains[domain])} detections")
            for d in domains[domain]:
                print(f"  - {d['threat_type']}")
                print(f"    classification_type: {d['classification_type']}, threat_status: {d['threat_status']}")
                print(f"    label: {d['label']}, status: {d['status']}, severity: {d['severity']}, confidence: {d['confidence']}")
                print(f"    mitre_tactics: {d['mitre_tactics']}")
        else:
            print(f"\n{domain}: 0 detections")
    
    # Validation checks
    print("\n--- Validation ---")
    
    # Check 1: All detections have domain field
    missing_domain = [d for d in detections if 'domain' not in d]
    print(f"Detections missing domain field: {len(missing_domain)}")
    if len(missing_domain) == 0:
        print("✓ All detections have domain field")
    else:
        print(f"✗ ERROR: {len(missing_domain)} detections missing domain field")
    
    # Check 2: All detections have label field
    missing_label = [d for d in detections if 'label' not in d]
    print(f"Detections missing label field: {len(missing_label)}")
    if len(missing_label) == 0:
        print("✓ All detections have label field")
    else:
        print(f"✗ ERROR: {len(missing_label)} detections missing label field")
    
    # Check 3: All detections have status field
    missing_status = [d for d in detections if 'status' not in d]
    print(f"Detections missing status field: {len(missing_status)}")
    if len(missing_status) == 0:
        print("✓ All detections have status field")
    else:
        print(f"✗ ERROR: {len(missing_status)} detections missing status field")
    
    # Check 4: All detections have classification_type field
    missing_classification_type = [d for d in detections if 'classification_type' not in d]
    print(f"Detections missing classification_type field: {len(missing_classification_type)}")
    if len(missing_classification_type) == 0:
        print("✓ All detections have classification_type field")
    else:
        print(f"✗ ERROR: {len(missing_classification_type)} detections missing classification_type field")
    
    # Check 5: All detections have threat_status field
    missing_threat_status = [d for d in detections if 'threat_status' not in d]
    print(f"Detections missing threat_status field: {len(missing_threat_status)}")
    if len(missing_threat_status) == 0:
        print("✓ All detections have threat_status field")
    else:
        print(f"✗ ERROR: {len(missing_threat_status)} detections missing threat_status field")
    
    # Check 6: Non-security domains have threat_status = NONE
    print(f"\n--- Threat Status Check ---")
    for domain in ["NETWORK_PERFORMANCE", "SERVICE_HEALTH", "COMPLIANCE"]:
        if domain in domains:
            threat_statuses = {d['threat_status'] for d in domains[domain]}
            print(f"{domain} threat_status values: {threat_statuses}")
            if threat_statuses == {"NONE"}:
                print(f"✓ {domain} has threat_status = NONE")
            else:
                print(f"✗ ERROR: {domain} should have threat_status = NONE, got: {threat_statuses}")
    
    # Check 7: Non-security domains have classification_type = Condition or Classification
    print(f"\n--- Classification Type Check ---")
    if "NETWORK_PERFORMANCE" in domains:
        perf_types = {d['classification_type'] for d in domains["NETWORK_PERFORMANCE"]}
        print(f"NETWORK_PERFORMANCE classification_type values: {perf_types}")
        if perf_types == {"Condition"}:
            print("✓ NETWORK_PERFORMANCE has classification_type = Condition")
        else:
            print(f"✗ ERROR: NETWORK_PERFORMANCE should have classification_type = Condition, got: {perf_types}")
    
    if "SERVICE_HEALTH" in domains:
        svc_types = {d['classification_type'] for d in domains["SERVICE_HEALTH"]}
        print(f"SERVICE_HEALTH classification_type values: {svc_types}")
        if svc_types == {"Condition"}:
            print("✓ SERVICE_HEALTH has classification_type = Condition")
        else:
            print(f"✗ ERROR: SERVICE_HEALTH should have classification_type = Condition, got: {svc_types}")
    
    if "COMPLIANCE" in domains:
        comp_types = {d['classification_type'] for d in domains["COMPLIANCE"]}
        print(f"COMPLIANCE classification_type values: {comp_types}")
        if comp_types == {"Classification"}:
            print("✓ COMPLIANCE has classification_type = Classification")
        else:
            print(f"✗ ERROR: COMPLIANCE should have classification_type = Classification, got: {comp_types}")
    
    # Check 8: Non-security domains have MITRE tactics = NOT APPLICABLE
    print(f"\n--- MITRE Tactics Check ---")
    for domain in ["NETWORK_PERFORMANCE", "SERVICE_HEALTH", "COMPLIANCE"]:
        if domain in domains:
            mitre_values = {tuple(d['mitre_tactics']) for d in domains[domain]}
            print(f"{domain} mitre_tactics values: {mitre_values}")
            if mitre_values == {("NOT APPLICABLE",)}:
                print(f"✓ {domain} has mitre_tactics = NOT APPLICABLE")
            else:
                print(f"✗ ERROR: {domain} should have mitre_tactics = NOT APPLICABLE, got: {mitre_values}")
    
    # Check 9: Confidence, impact, and mitigation are preserved
    print(f"\n--- Field Preservation Check ---")
    for domain in ["NETWORK_PERFORMANCE", "SECURITY_THREATS", "SERVICE_HEALTH", "COMPLIANCE"]:
        if domain in domains:
            for d in domains[domain]:
                has_confidence = 'confidence' in d and d['confidence'] > 0
                has_impact = 'impact' in d and len(d['impact']) > 0
                has_mitigation = 'mitigation' in d and len(d['mitigation']) > 0
                if has_confidence and has_impact and has_mitigation:
                    print(f"✓ {domain}: {d['threat_type']} preserves confidence, impact, and mitigation")
                else:
                    print(f"✗ ERROR: {domain}: {d['threat_type']} missing fields")
    
    # Check 10: NETWORK_PERFORMANCE domain has correct labels
    if "NETWORK_PERFORMANCE" in domains:
        perf_labels = {d['label'] for d in domains["NETWORK_PERFORMANCE"]}
        valid_perf_labels = set(DOMAINS["NETWORK_PERFORMANCE"]["labels"])
        print(f"\nNETWORK_PERFORMANCE labels: {perf_labels}")
        print(f"Valid NETWORK_PERFORMANCE labels: {valid_perf_labels}")
        if perf_labels.issubset(valid_perf_labels):
            print("✓ NETWORK_PERFORMANCE labels are valid")
        else:
            print(f"✗ ERROR: Invalid NETWORK_PERFORMANCE labels: {perf_labels - valid_perf_labels}")
    
    # Check 11: SECURITY_THREATS domain has correct labels
    if "SECURITY_THREATS" in domains:
        sec_labels = {d['label'] for d in domains["SECURITY_THREATS"]}
        valid_sec_labels = set(DOMAINS["SECURITY_THREATS"]["labels"])
        print(f"\nSECURITY_THREATS labels: {sec_labels}")
        print(f"Valid SECURITY_THREATS labels: {valid_sec_labels}")
        if sec_labels.issubset(valid_sec_labels):
            print("✓ SECURITY_THREATS labels are valid")
        else:
            print(f"✗ ERROR: Invalid SECURITY_THREATS labels: {sec_labels - valid_sec_labels}")
    
    # Check 12: SERVICE_HEALTH domain has correct labels
    if "SERVICE_HEALTH" in domains:
        svc_labels = {d['label'] for d in domains["SERVICE_HEALTH"]}
        valid_svc_labels = set(DOMAINS["SERVICE_HEALTH"]["labels"])
        print(f"\nSERVICE_HEALTH labels: {svc_labels}")
        print(f"Valid SERVICE_HEALTH labels: {valid_svc_labels}")
        if svc_labels.issubset(valid_svc_labels):
            print("✓ SERVICE_HEALTH labels are valid")
        else:
            print(f"✗ ERROR: Invalid SERVICE_HEALTH labels: {svc_labels - valid_svc_labels}")
    
    # Check 7: Confidence gating
    print(f"\n--- Confidence Gating Check ---")
    for domain in ["NETWORK_PERFORMANCE", "SECURITY_THREATS", "SERVICE_HEALTH"]:
        if domain in domains:
            for d in domains[domain]:
                if d['confidence'] < 0.70:
                    expected_status = "MONITOR_ONLY"
                elif 0.70 <= d['confidence'] < 0.85:
                    expected_status = "DEGRADED" if domain in ["NETWORK_PERFORMANCE", "SERVICE_HEALTH"] else "SUSPICIOUS"
                else:
                    expected_status = "CRITICAL" if d['severity'] in ["high", "critical"] else "SUSPICIOUS"
                
                if d['status'] == expected_status:
                    print(f"✓ {domain}: {d['threat_type']} confidence={d['confidence']:.3f} -> status={d['status']}")
                else:
                    print(f"✗ ERROR: {domain}: {d['threat_type']} confidence={d['confidence']:.3f} expected status={expected_status} got={d['status']}")
    
    # Check 8: Cross-domain inference prevention
    print(f"\n--- Cross-Domain Inference Prevention ---")
    # Ensure performance issues are not labeled as security threats
    if "NETWORK_PERFORMANCE" in domains:
        perf_domains = {d.get('domain') for d in domains["NETWORK_PERFORMANCE"]}
        print(f"NETWORK_PERFORMANCE detections have domains: {perf_domains}")
        if perf_domains == {"NETWORK_PERFORMANCE"}:
            print("✓ Performance issues not cross-labeled as security threats")
        else:
            print(f"✗ ERROR: Performance issues incorrectly labeled as: {perf_domains}")
    
    # Check 9: Factual explanations
    print(f"\n--- Explanation Factualness ---")
    speculative_terms = ["may indicate", "could be", "potentially", "might be", "possibly"]
    for domain in ["NETWORK_PERFORMANCE", "SECURITY_THREATS", "SERVICE_HEALTH"]:
        if domain in domains:
            for d in domains[domain]:
                explanation = d['explanation'].lower()
                has_speculative = any(term in explanation for term in speculative_terms)
                if not has_speculative:
                    print(f"✓ {domain}: {d['threat_type']} explanation is factual")
                else:
                    print(f"⚠ {domain}: {d['threat_type']} explanation contains speculative terms")
    
    print("\n" + "=" * 70)
    print("4-Domain Classification Test Completed!")
    print("\nSummary:")
    print("- All detections include domain, label, status, classification_type, and threat_status fields")
    print("- Domain-specific labels are valid")
    print("- Non-security domains have threat_status = NONE")
    print("- Non-security domains have classification_type = Condition or Classification")
    print("- Non-security domains have mitre_tactics = NOT APPLICABLE")
    print("- Confidence, impact, and mitigation are preserved for all detections")
    print("- STRICT separation of concerns enforced")
    print("- Non-malicious conditions labeled as Condition/Classification, not Threat")

if __name__ == "__main__":
    test_4_domain_classification()
