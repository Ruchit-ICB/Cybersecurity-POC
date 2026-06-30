"""
Comprehensive Threat Intelligence Analysis Engine
Analyzes ISP, network, and SIEM logs with strict evidence-based criteria.
"""

import json
import re
import random
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any
from collections import defaultdict

from cybersec_platform.parsing import normalize_log_entry
from cybersec_platform.feature_engineering import extract_features
from cybersec_platform.threat_detection import ThreatDetector, get_domain_label


class StrictThreatIntelligenceEngine:
    """
    Expert threat intelligence engine with primary focus on accuracy,
    evidence-based reasoning, and minimal false positives.
    """
    
    def __init__(self):
        self.detector = ThreatDetector()
        self.findings = []
        self.operational_conditions = []
        
    def _requires_direct_evidence(self, threat_type: str) -> bool:
        """
        Certain threat types require explicit direct evidence.
        C2 communication, DNS tunneling, and data exfiltration need clear indicators.
        """
        direct_evidence_threats = [
            "C2 Beacon / Command & Control",
            "DNS Tunneling / Exfiltration",
            "Data Exfiltration",
            "Database Exfiltration / Dump",
            "Credential Dumping",
            "Ransomware Activity",
            "BGP Hijacking",
            "Router Compromise"
        ]
        return threat_type in direct_evidence_threats
    
    def _has_supporting_evidence(self, detection: Dict[str, Any], all_detections: List[Dict[str, Any]]) -> bool:
        """
        Check if detection has at least two independent supporting indicators.
        """
        threat_type = detection.get('threat_type', '')
        source_ip = detection.get('source_ip', '')
        
        supporting_indicators = 0
        
        # Check for multiple detections of same type from same source
        same_type_same_source = sum(
            1 for d in all_detections 
            if d.get('threat_type') == threat_type 
            and d.get('source_ip') == source_ip
            and d != detection
        )
        if same_type_same_source >= 1:
            supporting_indicators += 1
        
        # Check for IDS/firewall actions
        raw_msg = detection.get('raw_message', '').lower()
        if any(term in raw_msg for term in ['blocked', 'dropped', 'denied', 'firewall', 'ids', 'ips']):
            supporting_indicators += 1
        
        # Check for authentication events (lockouts, failures)
        if any(term in raw_msg for term in ['lockout', 'failed', 'authentication failure']):
            supporting_indicators += 1
        
        # Check for severity level
        if detection.get('severity') in ['critical', 'high']:
            supporting_indicators += 1
        
        return supporting_indicators >= 2
    
    def _is_operational_condition(self, detection: Dict[str, Any]) -> bool:
        """
        Strictly separate operational conditions from security threats.
        """
        domain = detection.get('domain', '')
        classification_type = detection.get('classification_type', '')
        
        # Network performance conditions
        if domain == 'NETWORK_PERFORMANCE':
            return True
        
        # Service health conditions
        if domain == 'SERVICE_HEALTH':
            return True
        
        # Check for performance-related keywords
        raw_msg = detection.get('raw_message', '').lower()
        performance_keywords = [
            'latency', 'packet loss', 'jitter', 'congestion', 'dns delay',
            'retransmission', 'routing change', 'bandwidth spike', 'degraded performance',
            'temporary outage', 'high latency', 'slow response', 'timeout'
        ]
        
        if any(keyword in raw_msg for keyword in performance_keywords):
            # Only classify as condition if there's NO malicious context
            malicious_keywords = [
                'ddos', 'attack', 'flood', 'scan', 'malware', 'c2', 'beacon',
                'exfiltration', 'breach', 'intrusion', 'exploit'
            ]
            has_malicious_context = any(keyword in raw_msg for keyword in malicious_keywords)
            if not has_malicious_context:
                return True
        
        return False
    
    def _compute_confidence_score(self, detection: Dict[str, Any], all_detections: List[Dict[str, Any]]) -> float:
        """
        Compute conservative confidence scores based on evidence quality.
        """
        base_confidence = detection.get('confidence', 0.5)
        threat_type = detection.get('threat_type', '')
        
        # Reduce confidence for threats requiring direct evidence
        if self._requires_direct_evidence(threat_type):
            # Check for explicit indicators
            raw_msg = detection.get('raw_message', '').lower()
            has_explicit_indicator = any(term in raw_msg for term in [
                'detected', 'signature', 'known', 'confirmed', 'alert'
            ])
            
            if not has_explicit_indicator:
                base_confidence *= 0.7  # Reduce confidence if no explicit indicator
        
        # Boost confidence if multiple supporting indicators present
        if self._has_supporting_evidence(detection, all_detections):
            base_confidence = min(1.0, base_confidence * 1.2)
        
        # Ensure confidence is within bounds
        return max(0.0, min(1.0, base_confidence))
    
    def _map_to_mitre_attack(self, threat_type: str, raw_message: str) -> str:
        """
        Map detected threats to MITRE ATT&CK techniques.
        """
        mitre_mapping = {
            'Port Scanning / Reconnaissance': 'T1046',
            'Network Reconnaissance': 'T1018',
            'DDoS / Volumetric Attack': 'T1498',
            'Amplification Attack': 'T1498',
            'DNS Tunneling / Exfiltration': 'T1048.003',
            'DNS Cache Poisoning': 'T1055',
            'DNS Water Torture / NXDOMAIN Flood': 'T1498',
            'C2 Beacon / Command & Control': 'T1102',
            'Tor / Anonymous Proxy Detected': 'T1090.003',
            'Cryptominer / Coin Miner': 'T1496',
            'Malware Distribution': 'T1105',
            'Ransomware Activity': 'T1486',
            'Fileless Malware / LOLBins': 'T1059.001',
            'Data Exfiltration': 'T1041',
            'Database Exfiltration / Dump': 'T1005',
            'Phishing Kit': 'T1566',
            'Credential Dumping': 'T1003',
            'Brute-Force Authentication': 'T1110',
            'Password Spraying': 'T1110.003',
            'Credential Exposure in Logs': 'T1552',
            'BGP Hijacking': 'T1565',
            'Man-in-the-Middle (MitM)': 'T1557',
            'Router Compromise': 'T1562',
            'Lateral Movement / Pass-the-Hash': 'T1550.002',
            'Spam Campaign': 'T1566',
            'Port Forwarding Abuse': 'T1090',
            'Proxy Abuse': 'T1090',
            'Copyright Infringement / Torrenting': 'T1048',
            'Account Sharing': 'T1078',
            'VoIP Fraud': 'T1204',
            'TDoS Attack': 'T1498',
            'SIP Registration Attack': 'T1110',
            'Eavesdropping': 'T1123',
            'IoT Botnet': 'T1190',
            'Smart Home Abuse': 'T1190',
            'CCTV Camera Compromise': 'T1190',
            'Smart Meter Tampering': 'T1528',
            'Firewall / Security Control Disabled': 'T1562',
            'SSH Key / Authorized Keys Tampering': 'T1098.004',
            'API Abuse / Scraping': 'T1190',
        }
        
        return mitre_mapping.get(threat_type, 'NOT APPLICABLE')
    
    def analyze_logs(self, logs: List[str]) -> Dict[str, Any]:
        """
        Main analysis function that processes logs and generates threat intelligence.
        """
        self.findings = []
        self.operational_conditions = []
        
        # Parse and extract features from all logs
        parsed_logs = []
        for log in logs:
            parsed = normalize_log_entry(log)
            features = extract_features(parsed)
            parsed_logs.append(features)
        
        # Run threat detection
        all_detections = self.detector.detect(parsed_logs)
        
        # Process each detection with strict criteria
        for detection in all_detections:
            # Skip operational conditions
            if self._is_operational_condition(detection):
                self.operational_conditions.append(detection)
                continue
            
            # Compute conservative confidence score
            confidence = self._compute_confidence_score(detection, all_detections)
            
            # Apply confidence thresholds
            if confidence < 0.40:
                threat_status = "Informational"
                severity = "Low"
            elif 0.40 <= confidence < 0.70:
                threat_status = "Monitor"
                severity = "Medium"
            elif 0.70 <= confidence < 0.85:
                threat_status = "Suspicious"
                severity = "High"
            else:
                threat_status = "Confirmed"
                severity = "Critical"
            
            # For threats requiring direct evidence, enforce higher threshold
            if self._requires_direct_evidence(detection.get('threat_type', '')):
                if confidence < 0.70:
                    threat_status = "Monitor"
                    severity = "Medium"
                elif confidence < 0.85:
                    threat_status = "Suspicious"
                    severity = "High"
            
            # Only include confirmed or suspicious threats
            if threat_status in ["Confirmed", "Suspicious", "Monitor"]:
                mitre_technique = self._map_to_mitre_attack(
                    detection.get('threat_type', ''),
                    detection.get('raw_message', '')
                )
                
                finding = {
                    "timestamp": detection.get('timestamp'),
                    "source_ip": detection.get('source_ip'),
                    "domain": detection.get('domain', 'SECURITY_THREATS'),
                    "classification": detection.get('threat_type'),
                    "threat_status": threat_status,
                    "severity": severity,
                    "confidence": f"{int(confidence * 100)}%",
                    "mitre_attack": mitre_technique,
                    "evidence": detection.get('evidence', 'Pattern match'),
                    "impact": detection.get('impact', 'Potential security risk'),
                    "mitigation": detection.get('mitigation', 'Review and investigate'),
                    "explanation": detection.get('explanation', 'Threat pattern detected')
                }
                
                self.findings.append(finding)
        
        # Remove duplicates based on threat_type, source_ip, and threat_status
        seen = set()
        unique_findings = []
        for finding in self.findings:
            dedup_key = (
                finding['classification'],
                finding['source_ip'],
                finding['threat_status']
            )
            if dedup_key not in seen:
                seen.add(dedup_key)
                unique_findings.append(finding)
        
        self.findings = unique_findings
        
        # Calculate aggregate threat score (only from confirmed findings)
        confirmed_findings = [f for f in self.findings if f['threat_status'] == 'Confirmed']
        if confirmed_findings:
            threat_score = sum(int(f['confidence'].rstrip('%')) for f in confirmed_findings) / len(confirmed_findings)
        else:
            threat_score = 0
        
        return {
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
            "total_logs_analyzed": len(logs),
            "total_findings": len(self.findings),
            "confirmed_threats": len([f for f in self.findings if f['threat_status'] == 'Confirmed']),
            "suspicious_threats": len([f for f in self.findings if f['threat_status'] == 'Suspicious']),
            "monitor_items": len([f for f in self.findings if f['threat_status'] == 'Monitor']),
            "operational_conditions": len(self.operational_conditions),
            "aggregate_threat_score": f"{int(threat_score)}%",
            "findings": self.findings,
            "operational_conditions_summary": [
                {
                    "classification": cond.get('threat_type'),
                    "domain": cond.get('domain'),
                    "note": "Operational condition - not a security threat"
                } for cond in self.operational_conditions
            ]
        }
    
    def generate_report(self, analysis_results: Dict[str, Any]) -> str:
        """
        Generate a comprehensive threat intelligence report.
        """
        report = []
        report.append("=" * 80)
        report.append("THREAT INTELLIGENCE ANALYSIS REPORT")
        report.append("=" * 80)
        report.append(f"Analysis Timestamp: {analysis_results['analysis_timestamp']}")
        report.append(f"Total Logs Analyzed: {analysis_results['total_logs_analyzed']}")
        report.append("")
        
        # Executive Summary
        report.append("-" * 80)
        report.append("EXECUTIVE SUMMARY")
        report.append("-" * 80)
        report.append(f"Aggregate Threat Score: {analysis_results['aggregate_threat_score']}")
        report.append(f"Confirmed Threats: {analysis_results['confirmed_threats']}")
        report.append(f"Suspicious Activities: {analysis_results['suspicious_threats']}")
        report.append(f"Monitor Items: {analysis_results['monitor_items']}")
        report.append(f"Operational Conditions: {analysis_results['operational_conditions']}")
        report.append("")
        
        # Threat Findings
        if analysis_results['findings']:
            report.append("-" * 80)
            report.append("SECURITY THREAT FINDINGS")
            report.append("-" * 80)
            
            for idx, finding in enumerate(analysis_results['findings'], 1):
                report.append(f"\n[Finding #{idx}]")
                report.append(f"  Timestamp: {finding['timestamp']}")
                report.append(f"  Source IP: {finding['source_ip']}")
                report.append(f"  Domain: {finding['domain']}")
                report.append(f"  Classification: {finding['classification']}")
                report.append(f"  Threat Status: {finding['threat_status']}")
                report.append(f"  Severity: {finding['severity']}")
                report.append(f"  Confidence: {finding['confidence']}")
                report.append(f"  MITRE ATT&CK: {finding['mitre_attack']}")
                report.append(f"  Evidence: {finding['evidence']}")
                report.append(f"  Impact: {finding['impact']}")
                report.append(f"  Mitigation: {finding['mitigation']}")
                report.append(f"  Explanation: {finding['explanation']}")
        
        # Operational Conditions
        if analysis_results['operational_conditions_summary']:
            report.append("")
            report.append("-" * 80)
            report.append("OPERATIONAL CONDITIONS (Non-Security)")
            report.append("-" * 80)
            for cond in analysis_results['operational_conditions_summary']:
                report.append(f"  - {cond['classification']}: {cond['note']}")
        
        report.append("")
        report.append("=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)
        
        return "\n".join(report)


def generate_realistic_isp_logs(num_logs: int = 50) -> List[str]:
    """
    Generate realistic ISP/network/SIEM log samples for analysis.
    """
    logs = []
    now = datetime.now(timezone.utc)
    
    # Define realistic log templates
    log_templates = [
        # Normal operational logs
        lambda: f'{{"timestamp": "{(now - timedelta(seconds=random.randint(0, 3600))).isoformat()}Z", "level": "INFO", "service": "dhcp", "message": "DHCP lease assigned", "src_ip": "192.168.1.{random.randint(2, 200)}", "lease_time": 86400}}',
        lambda: f'{{"timestamp": "{(now - timedelta(seconds=random.randint(0, 3600))).isoformat()}Z", "level": "INFO", "service": "dns", "message": "DNS query resolved", "query": "example.com", "response_ip": "93.184.216.34"}}',
        lambda: f'{{"timestamp": "{(now - timedelta(seconds=random.randint(0, 3600))).isoformat()}Z", "level": "INFO", "service": "firewall", "message": "Connection allowed", "src_ip": "10.0.0.{random.randint(1, 50)}", "dst_port": 443, "protocol": "TCP"}}',
        
        # Network performance conditions (should be classified as conditions, not threats)
        lambda: f'{{"timestamp": "{(now - timedelta(seconds=random.randint(0, 3600))).isoformat()}Z", "level": "INFO", "service": "network", "message": "High latency detected from 192.168.1.100, rtt_ms: {random.randint(200, 500)} - degraded performance", "src_ip": "192.168.1.100", "rtt_ms": {random.randint(200, 500)}}}',
        lambda: f'{{"timestamp": "{(now - timedelta(seconds=random.randint(0, 3600))).isoformat()}Z", "level": "INFO", "service": "network", "message": "Packet loss detected from 192.168.1.101, dropped_packets: {random.randint(10, 50)} - connection unstable", "src_ip": "192.168.1.101", "dropped_packets": {random.randint(10, 50)}}}',
        
        # Security threats with explicit evidence
        lambda: f'{{"timestamp": "{(now - timedelta(seconds=random.randint(0, 3600))).isoformat()}Z", "level": "CRITICAL", "message": "DDoS: SYN flood from {random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)} — 80,000 packets/second detected, connection limit reached"}}',
        lambda: f'{{"timestamp": "{(now - timedelta(seconds=random.randint(0, 3600))).isoformat()}Z", "level": "WARN", "message": "Port scan detected: nmap SYN scan from {random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)} - 1024 ports scanned in 2s"}}',
        lambda: f'{{"timestamp": "{(now - timedelta(seconds=random.randint(0, 3600))).isoformat()}Z", "level": "HIGH", "message": "Brute-force authentication: SSH login attempts from {random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)} — 1000 failed attempts in 5 minutes"}}',
        lambda: f'{{"timestamp": "{(now - timedelta(seconds=random.randint(0, 3600))).isoformat()}Z", "level": "CRITICAL", "message": "C2 beacon detected: reverse shell callback to {random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}:4444 — backdoor installed"}}',
        lambda: f'{{"timestamp": "{(now - timedelta(seconds=random.randint(0, 3600))).isoformat()}Z", "level": "HIGH", "message": "DNS tunneling: unusually long DNS query from {random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)} — base64 encoded payload in subdomain"}}',
        lambda: f'{{"timestamp": "{(now - timedelta(seconds=random.randint(0, 3600))).isoformat()}Z", "level": "CRITICAL", "message": "Data exfiltration detected: 2.4GB outbound transfer to {random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)} on port 443"}}',
        lambda: f'{{"timestamp": "{(now - timedelta(seconds=random.randint(0, 3600))).isoformat()}Z", "level": "WARN", "message": "Bittorrent handshake detected from {random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)} on port 6881 - tracker connection established"}}',
        lambda: f'{{"timestamp": "{(now - timedelta(seconds=random.randint(0, 3600))).isoformat()}Z", "level": "CRITICAL", "message": "Credential dumping detected: lsass.exe memory access by unknown process from {random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"}}',
        lambda: f'{{"timestamp": "{(now - timedelta(seconds=random.randint(0, 3600))).isoformat()}Z", "level": "HIGH", "message": "Malware distribution: {random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)} serving Emotet payload via HTTP download"}}',
        lambda: f'{{"timestamp": "{(now - timedelta(seconds=random.randint(0, 3600))).isoformat()}Z", "level": "CRITICAL", "message": "Ransomware encryption detected in /home/user/docs — files renamed to .encrypted"}}',
    ]
    
    for _ in range(num_logs):
        template = random.choice(log_templates)
        logs.append(template())
    
    return logs


def main():
    """
    Main execution function for threat intelligence analysis.
    """
    print("Initializing Threat Intelligence Engine...")
    engine = StrictThreatIntelligenceEngine()
    
    print("Generating realistic ISP/network/SIEM logs...")
    logs = generate_realistic_isp_logs(num_logs=100)
    
    print(f"Analyzing {len(logs)} log entries...")
    results = engine.analyze_logs(logs)
    
    print("Generating comprehensive threat intelligence report...")
    report = engine.generate_report(results)
    
    # Save report to file
    with open('threat_intelligence_report.txt', 'w') as f:
        f.write(report)
    
    # Also save JSON results
    with open('threat_intelligence_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print("\n" + "=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)
    print(f"Report saved to: threat_intelligence_report.txt")
    print(f"JSON results saved to: threat_intelligence_results.json")
    print("\n")
    print(report)


if __name__ == "__main__":
    main()