import requests

# Test multiple distinct threats in one log block
multi_log = """Failed password for invalid user admin from 192.168.1.10 port 22 ssh2
UNION SELECT credit_card, cvv FROM payments WHERE 1=1
<script>document.cookie='steal'</script> in POST body
curl http://169.254.169.254/latest/meta-data/iam/credentials
"""

r = requests.post('http://127.0.0.1:5000/api/scan', json={'log_text': multi_log})
data = r.json()

print("=" * 70)
print("MULTI-THREAT CONFIDENCE SCORES")
print("=" * 70)
for i, d in enumerate(data.get('detections', []), 1):
    pct = d['confidence'] * 100
    print(f"\n  [{i}] {d['threat_type']}")
    print(f"      Severity:   {d['severity']}")
    print(f"      Confidence: {pct:.1f}%")
    print(f"      MITRE:      {', '.join(d.get('mitre_tactics', []))}")
    print(f"      CVE:        {d.get('cve_id', 'N/A')}")

print(f"\n{'=' * 70}")
print(f"ML Analysis: probability={data.get('ml_analysis',{}).get('probability')}%")
print(f"Reason: {data.get('ml_analysis',{}).get('reason')}")
