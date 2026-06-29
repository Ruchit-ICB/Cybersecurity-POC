"""Test ISP network telemetry data analysis for threat detection."""

import csv
from io import StringIO
from typing import List, Dict, Any

# Sample CSV data provided by user
CSV_DATA = """timestamp,user_id,ip_address,device_type,download_mb,upload_mb,latency_ms,packet_loss_pct,signal_strength_dbm,connection_type,region,status
2026-06-29 08:15:21,U1001,192.168.1.10,Mobile,245,18,22,0.1,-58,5G,Dallas,Normal
2026-06-29 08:17:03,U1002,192.168.1.11,Laptop,1520,120,35,0.2,-61,Fiber,Dallas,Heavy_Usage
2026-06-29 08:18:50,U1003,192.168.1.12,SmartTV,4800,45,18,0.0,-55,Fiber,Dallas,Streaming
2026-06-29 08:20:11,U1004,192.168.1.13,Desktop,210,30,180,8.2,-87,WiFi,Dallas,Network_Issue
2026-06-29 08:21:44,U1005,192.168.1.14,Mobile,95,12,28,0.0,-60,5G,Dallas,Normal
2026-06-29 08:23:10,U1006,192.168.1.15,Laptop,7800,950,40,0.4,-63,Fiber,Dallas,Torrenting
2026-06-29 08:25:31,U1007,192.168.1.16,Desktop,120,10,320,12.5,-92,WiFi,Dallas,Connection_Failure
2026-06-29 08:27:55,U1008,192.168.1.17,Tablet,300,20,25,0.0,-57,5G,Dallas,Normal
2026-06-29 08:29:42,U1009,192.168.1.18,SmartTV,5200,50,20,0.1,-54,Fiber,Dallas,Streaming
2026-06-29 08:31:08,U1010,192.168.1.19,Laptop,50,5,450,18.0,-95,WiFi,Dallas,Outage"""

def parse_network_telemetry(csv_data: str) -> List[Dict[str, Any]]:
    """Parse CSV network telemetry data."""
    reader = csv.DictReader(StringIO(csv_data))
    records = []
    for row in reader:
        # Convert numeric fields
        row['download_mb'] = float(row['download_mb'])
        row['upload_mb'] = float(row['upload_mb'])
        row['latency_ms'] = float(row['latency_ms'])
        row['packet_loss_pct'] = float(row['packet_loss_pct'])
        row['signal_strength_dbm'] = float(row['signal_strength_dbm'])
        records.append(row)
    return records

def detect_network_anomalies(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect network anomalies in telemetry data."""
    anomalies = []
    
    for record in records:
        issues = []
        severity = "low"
        
        # High latency detection (>100ms is concerning)
        if record['latency_ms'] > 100:
            issues.append(f"High latency: {record['latency_ms']}ms")
            if record['latency_ms'] > 300:
                severity = "critical"
            elif record['latency_ms'] > 150:
                severity = "high"
        
        # Packet loss detection (>1% is concerning)
        if record['packet_loss_pct'] > 1.0:
            issues.append(f"High packet loss: {record['packet_loss_pct']}%")
            if record['packet_loss_pct'] > 10:
                severity = "critical"
            elif record['packet_loss_pct'] > 5:
                severity = "high"
        
        # Poor signal strength (<-70 dBm is weak)
        if record['signal_strength_dbm'] < -70:
            issues.append(f"Poor signal: {record['signal_strength_dbm']} dBm")
            if record['signal_strength_dbm'] < -90:
                severity = "critical"
            elif record['signal_strength_dbm'] < -80:
                severity = "high"
        
        # Status-based detection
        if record['status'] in ['Network_Issue', 'Connection_Failure', 'Outage']:
            issues.append(f"Status: {record['status']}")
            if record['status'] == 'Outage':
                severity = "critical"
            elif record['status'] in ['Connection_Failure']:
                severity = "high"
        
        # Suspicious bandwidth patterns
        if record['download_mb'] > 5000 and record['status'] == 'Torrenting':
            issues.append(f"High bandwidth torrenting: {record['download_mb']} MB")
            severity = "medium"
        
        if issues:
            anomalies.append({
                'timestamp': record['timestamp'],
                'user_id': record['user_id'],
                'ip_address': record['ip_address'],
                'device_type': record['device_type'],
                'issues': issues,
                'severity': severity,
                'metrics': {
                    'latency_ms': record['latency_ms'],
                    'packet_loss_pct': record['packet_loss_pct'],
                    'signal_strength_dbm': record['signal_strength_dbm'],
                    'download_mb': record['download_mb'],
                    'upload_mb': record['upload_mb']
                }
            })
    
    return anomalies

def main():
    print("=" * 70)
    print("ISP Network Telemetry Analysis")
    print("=" * 70)
    
    # Parse data
    records = parse_network_telemetry(CSV_DATA)
    print(f"\nTotal records: {len(records)}")
    
    # Detect anomalies
    anomalies = detect_network_anomalies(records)
    
    print(f"\nAnomalies detected: {len(anomalies)}")
    
    if anomalies:
        print("\n" + "=" * 70)
        print("Detailed Anomalies")
        print("=" * 70)
        
        for i, anomaly in enumerate(anomalies, 1):
            print(f"\n{i}. User: {anomaly['user_id']} ({anomaly['ip_address']})")
            print(f"   Device: {anomaly['device_type']}")
            print(f"   Timestamp: {anomaly['timestamp']}")
            print(f"   Severity: {anomaly['severity'].upper()}")
            print(f"   Issues:")
            for issue in anomaly['issues']:
                print(f"     - {issue}")
            print(f"   Metrics:")
            print(f"     - Latency: {anomaly['metrics']['latency_ms']}ms")
            print(f"     - Packet Loss: {anomaly['metrics']['packet_loss_pct']}%")
            print(f"     - Signal: {anomaly['metrics']['signal_strength_dbm']} dBm")
            print(f"     - Download: {anomaly['metrics']['download_mb']} MB")
            print(f"     - Upload: {anomaly['metrics']['upload_mb']} MB")
    else:
        print("\nNo network anomalies detected.")
    
    # Summary
    print("\n" + "=" * 70)
    print("Summary")
    print("=" * 70)
    print(f"Total users monitored: {len(records)}")
    print(f"Users with issues: {len(anomalies)}")
    print(f"Users with normal connectivity: {len(records) - len(anomalies)}")
    
    # Severity breakdown
    critical = sum(1 for a in anomalies if a['severity'] == 'critical')
    high = sum(1 for a in anomalies if a['severity'] == 'high')
    medium = sum(1 for a in anomalies if a['severity'] == 'medium')
    low = sum(1 for a in anomalies if a['severity'] == 'low')
    
    print(f"\nSeverity breakdown:")
    print(f"  Critical: {critical}")
    print(f"  High: {high}")
    print(f"  Medium: {medium}")
    print(f"  Low: {low}")

if __name__ == "__main__":
    main()
