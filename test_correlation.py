from datetime import datetime, timezone
from cybersec_platform.feature_engineering import extract_features
from cybersec_platform.threat_detection import ThreatDetector

def test_brute_force_correlation():
    
    print("Testing Brute-Force Attack Correlation")
    print("=" * 70)
    
    
    test_logs = []
    source_ip = "192.168.1.100"
    
    for i in range(10):
        log = f'{{"timestamp": "{datetime.now(timezone.utc).isoformat()}Z", "level": "WARN", "service": "ssh", "message": "Failed password for root from {source_ip} port {2222+i}", "src_ip": "{source_ip}"}}'
        test_logs.append(log)
    
    
    lockout_log = f'{{"timestamp": "{datetime.now(timezone.utc).isoformat()}Z", "level": "ERROR", "service": "ssh", "message": "Account locked due to multiple failed attempts from {source_ip}", "src_ip": "{source_ip}"}}'
    test_logs.append(lockout_log)
    
    print(f"Generated {len(test_logs)} test logs (10 failed logins + 1 lockout)")
    
    
    features_list = [extract_features(log) for log in test_logs]
    detector = ThreatDetector()
    detections = detector.detect(features_list)
    
    print(f"\nTotal detections: {len(detections)}")
    
    # Check for correlated brute-force detection
    correlated_detections = [d for d in detections if d['category'] == 'Correlated Detection']
    print(f"Correlated detections: {len(correlated_detections)}")
    
    for d in correlated_detections:
        print(f"\nCorrelated Detection:")
        print(f"  Domain: {d['domain']}")
        print(f"  Classification: {d['threat_type']}")
        print(f"  Threat Status: {d['threat_status']}")
        print(f"  Severity: {d['severity']}")
        print(f"  Confidence: {d['confidence']:.0%}")
        print(f"  MITRE ATT&CK: {d['mitre_tactics']}")
        print(f"  Explanation: {d['explanation']}")
        print(f"  Impact: {d['impact']}")
        print(f"  Mitigation: {d['mitigation']}")
    
    
    if correlated_detections:
        bf_det = correlated_detections[0]
        assert bf_det['domain'] == 'SECURITY_THREATS', "Should be SECURITY_THREATS domain"
        assert bf_det['threat_type'] == 'Brute-Force Attack', "Should be Brute-Force Attack"
        assert bf_det['threat_status'] in ['SUSPICIOUS', 'CONFIRMED'], "Should have threat status"
        assert bf_det['confidence'] >= 0.70, "Confidence should be >= 70%"
        assert bf_det['mitre_tactics'] == ['T1110'], "Should have MITRE T1110"
        print("\n✓ Brute-force correlation test PASSED")
    else:
        print("\n✗ ERROR: No correlated brute-force detection found")
    
    return len(correlated_detections) > 0

def test_ddos_correlation():
    
    print("\n" + "=" * 70)
    print("Testing DDoS Attack Correlation")
    print("=" * 70)
    
    
    test_logs = []
    
    for i in range(20):
        source_ip = f"10.0.{i//256}.{i%256}"
        log = f'{{"timestamp": "{datetime.now(timezone.utc).isoformat()}Z", "level": "WARN", "service": "firewall", "message": "High pps detected from {source_ip}, rate limit exceeded", "src_ip": "{source_ip}"}}'
        test_logs.append(log)
    
    
    flood_log = f'{{"timestamp": "{datetime.now(timezone.utc).isoformat()}Z", "level": "CRITICAL", "service": "network", "message": "SYN flood detected from multiple sources", "src_ip": "multiple"}}'
    test_logs.append(flood_log)
    
    print(f"Generated {len(test_logs)} test logs (20 traffic events + 1 flood signature)")
    
    # Extract features and run detection
    features_list = [extract_features(log) for log in test_logs]
    detector = ThreatDetector()
    detections = detector.detect(features_list)
    
    print(f"\nTotal detections: {len(detections)}")
    
    # Check for correlated DDoS detection
    correlated_detections = [d for d in detections if d['category'] == 'Correlated Detection']
    print(f"Correlated detections: {len(correlated_detections)}")
    
    for d in correlated_detections:
        print(f"\nCorrelated Detection:")
        print(f"  Domain: {d['domain']}")
        print(f"  Classification: {d['threat_type']}")
        print(f"  Threat Status: {d['threat_status']}")
        print(f"  Severity: {d['severity']}")
        print(f"  Confidence: {d['confidence']:.0%}")
        print(f"  MITRE ATT&CK: {d['mitre_tactics']}")
        print(f"  Explanation: {d['explanation']}")
        print(f"  Impact: {d['impact']}")
        print(f"  Mitigation: {d['mitigation']}")
    
    # Validation
    if correlated_detections:
        ddos_det = correlated_detections[0]
        assert ddos_det['domain'] == 'SECURITY_THREATS', "Should be SECURITY_THREATS domain"
        assert ddos_det['threat_type'] == 'DDoS Attack', "Should be DDoS Attack"
        assert ddos_det['threat_status'] in ['SUSPICIOUS', 'CONFIRMED'], "Should have threat status"
        assert ddos_det['confidence'] >= 0.70, "Confidence should be >= 70%"
        assert ddos_det['mitre_tactics'] == ['T1498'], "Should have MITRE T1498"
        print("\n✓ DDoS correlation test PASSED")
    else:
        print("\n✗ ERROR: No correlated DDoS detection found")
    
    return len(correlated_detections) > 0

def test_malware_correlation():
    """Test malware detection via correlation."""
    print("\n" + "=" * 70)
    print("Testing Malware Detection Correlation")
    print("=" * 70)
    
    # Generate malware events with C2 communication
    test_logs = []
    
    # Known signature detection
    sig_log = f'{{"timestamp": "{datetime.now(timezone.utc).isoformat()}Z", "level": "CRITICAL", "service": "ids", "message": "Known malware signature detected: Emotet payload", "src_ip": "10.0.0.50"}}'
    test_logs.append(sig_log)
    
    # C2 beacon
    c2_log = f'{{"timestamp": "{datetime.now(timezone.utc).isoformat()}Z", "level": "WARN", "service": "network", "message": "C2 beacon callback detected to known C2 domain", "src_ip": "10.0.0.50"}}'
    test_logs.append(c2_log)
    
    # Payload detection
    payload_log = f'{{"timestamp": "{datetime.now(timezone.utc).isoformat()}Z", "level": "CRITICAL", "service": "endpoint", "message": "Ransomware encryption detected on file system", "src_ip": "10.0.0.50"}}'
    test_logs.append(payload_log)
    
    print(f"Generated {len(test_logs)} test logs (signature + C2 + payload)")
    
    # Extract features and run detection
    features_list = [extract_features(log) for log in test_logs]
    detector = ThreatDetector()
    detections = detector.detect(features_list)
    
    print(f"\nTotal detections: {len(detections)}")
    
    # Check for correlated malware detection
    correlated_detections = [d for d in detections if d['category'] == 'Correlated Detection']
    print(f"Correlated detections: {len(correlated_detections)}")
    
    for d in correlated_detections:
        print(f"\nCorrelated Detection:")
        print(f"  Domain: {d['domain']}")
        print(f"  Classification: {d['threat_type']}")
        print(f"  Threat Status: {d['threat_status']}")
        print(f"  Severity: {d['severity']}")
        print(f"  Confidence: {d['confidence']:.0%}")
        print(f"  MITRE ATT&CK: {d['mitre_tactics']}")
        print(f"  Explanation: {d['explanation']}")
        print(f"  Impact: {d['impact']}")
        print(f"  Mitigation: {d['mitigation']}")
    
    # Validation
    if correlated_detections:
        malware_det = correlated_detections[0]
        assert malware_det['domain'] == 'SECURITY_THREATS', "Should be SECURITY_THREATS domain"
        assert malware_det['threat_type'] in ['Malware Activity', 'Ransomware', 'C2 Communication'], "Should be malware-related"
        assert malware_det['threat_status'] in ['SUSPICIOUS', 'CONFIRMED'], "Should have threat status"
        assert malware_det['confidence'] >= 0.70, "Confidence should be >= 70%"
        print("\n✓ Malware correlation test PASSED")
    else:
        print("\n✗ ERROR: No correlated malware detection found")
    
    return len(correlated_detections) > 0

def test_scan_correlation():
    """Test scanning/reconnaissance detection via correlation."""
    print("\n" + "=" * 70)
    print("Testing Network Scanning Correlation")
    print("=" * 70)
    
    # Generate scan events from same source
    test_logs = []
    source_ip = "192.168.1.200"
    
    for i in range(5):
        port = 22 + i
        log = f'{{"timestamp": "{datetime.now(timezone.utc).isoformat()}Z", "level": "WARN", "service": "firewall", "message": "Port scan detected from {source_ip} targeting port {port}", "src_ip": "{source_ip}"}}'
        test_logs.append(log)
    
    # Add OS detection
    os_det_log = f'{{"timestamp": "{datetime.now(timezone.utc).isoformat()}Z", "level": "WARN", "service": "ids", "message": "OS detection attempt from {source_ip}", "src_ip": "{source_ip}"}}'
    test_logs.append(os_det_log)
    
    print(f"Generated {len(test_logs)} test logs (5 port scans + 1 OS detection)")
    
    
    features_list = [extract_features(log) for log in test_logs]
    detector = ThreatDetector()
    detections = detector.detect(features_list)
    
    print(f"\nTotal detections: {len(detections)}")
    correlated_detections = [d for d in detections if d['category'] == 'Correlated Detection']
    print(f"Correlated detections: {len(correlated_detections)}")
    for d in correlated_detections:
        print(f"\nCorrelated Detection:")
        print(f"  Domain: {d['domain']}")
        print(f"  Classification: {d['threat_type']}")
        print(f"  Threat Status: {d['threat_status']}")
        print(f"  Severity: {d['severity']}")
        print(f"  Confidence: {d['confidence']:.0%}")
        print(f"  MITRE ATT&CK: {d['mitre_tactics']}")
        print(f"  Explanation: {d['explanation']}")
        print(f"  Impact: {d['impact']}")
        print(f"  Mitigation: {d['mitigation']}")
    
    if correlated_detections:
        scan_det = correlated_detections[0]
        assert scan_det['domain'] == 'SECURITY_THREATS', "Should be SECURITY_THREATS domain"
        assert scan_det['threat_type'] == 'Network Scanning / Reconnaissance', "Should be Network Scanning"
        assert scan_det['threat_status'] in ['SUSPICIOUS', 'CONFIRMED'], "Should have threat status"
        assert scan_det['confidence'] >= 0.70, "Confidence should be >= 70%"
        assert scan_det['mitre_tactics'] == ['T1046'], "Should have MITRE T1046"
        print("\n✓ Scan correlation test PASSED")
    else:
        print("\n✗ ERROR: No correlated scan detection found")
    
    return len(correlated_detections) > 0

def test_no_false_positives():
    print("\n" + "=" * 70)
    print("Testing No False Positives (Performance Issues)")
    print("=" * 70)
    test_logs = [
        '{"timestamp": "2026-06-29T10:00:00Z", "level": "INFO", "service": "network", "message": "High latency detected: 500ms", "src_ip": "10.0.0.1"}',
        '{"timestamp": "2026-06-29T10:00:01Z", "level": "INFO", "service": "network", "message": "Packet loss detected: 5%", "src_ip": "10.0.0.1"}',
        '{"timestamp": "2026-06-29T10:00:02Z", "level": "INFO", "service": "bandwidth", "message": "Bandwidth spike detected: 1Gbps", "src_ip": "10.0.0.1"}',
    ]
    
    print(f"Generated {len(test_logs)} performance issue logs")
    
    # Extract features and run detection
    features_list = [extract_features(log) for log in test_logs]
    detector = ThreatDetector()
    detections = detector.detect(features_list)
    
    print(f"\nTotal detections: {len(detections)}")
    
    # Check that no correlated threat detections exist
    correlated_detections = [d for d in detections if d['category'] == 'Correlated Detection']
    print(f"Correlated detections: {len(correlated_detections)}")
    
    # Check that all detections are network performance conditions
    for d in detections:
        print(f"\nDetection:")
        print(f"  Domain: {d['domain']}")
        print(f"  Classification Type: {d['classification_type']}")
        print(f"  Threat Status: {d['threat_status']}")
        print(f"  MITRE ATT&CK: {d['mitre_tactics']}")
    
    # Validation
    assert len(correlated_detections) == 0, "Should have no correlated threat detections"
    for d in detections:
        assert d['domain'] in ['NETWORK_PERFORMANCE', 'SERVICE_HEALTH'], "Should be non-security domain"
        assert d['threat_status'] == 'NONE', "Should have threat_status = NONE"
        assert d['mitre_tactics'] == ['NOT APPLICABLE'], "Should have MITRE = NOT APPLICABLE"
    
    print("\n✓ No false positives test PASSED")
    return True

if __name__ == "__main__":
    print("Event Correlation Engine Test Suite")
    print("=" * 70)
    
    results = []
    results.append(("Brute-Force", test_brute_force_correlation()))
    results.append(("DDoS", test_ddos_correlation()))
    results.append(("Malware", test_malware_correlation()))
    results.append(("Scanning", test_scan_correlation()))
    results.append(("No False Positives", test_no_false_positives()))
    print("\n" + "=" * 70)
    print("Test Summary:")
    for test_name, passed in results:
        status = "PASSED" if passed else "FAILED"
        print(f"  {test_name}: {status}")
    
    all_passed = all(result[1] for result in results)
    print("\n" + ("=" * 70))
    if all_passed:
        print("All tests PASSED ✓")
    else:
        print("Some tests FAILED ✗")
