# ISP Log-Focused Evidence-Based Threat Detection

## Goal
Narrow the entire threat detection pipeline to analyse **ISP network logs only**. Replace the current broad, web-application-oriented signature library with an ISP-specific correlation engine that requires **direct evidence or two independent corroborating indicators** before confirming a threat. Treat latency, packet loss, jitter, congestion, and similar operational conditions as **non-threats** unless paired with explicit malicious evidence. Map confirmed threats to MITRE ATT&CK, deduplicate findings, and prioritise **precision over sensitivity**.

## User Review Required

> [!IMPORTANT]
> This is a significant refactor of `threat_detection.py`. The existing 40+ generic web-attack signatures (SQLi, XSS, SSTI, etc.) will be **removed** and replaced with ~25 ISP-focused threat categories. The THREAT_DETAILS and CATEGORY_DETAILS dictionaries will also be rewritten. Old behaviour will no longer be available.

> [!WARNING]
> The Manual Log Analysis textarea will be re-labelled to accept ISP JSON logs only. Any previously saved scan results that referenced web-attack types will no longer match.

## Open Questions
- **Benign threshold tuning**: Should latency/packet-loss logs ever contribute to a "Monitor" status, or should they be completely hidden from the threat table?
- **Deduplication window**: When the same source IP triggers the same signature within N seconds, should we collapse to one finding? If so, what should N be (e.g., 60 s)?
- **Severity escalation**: Should a "Monitor" result automatically escalate to "Confirmed" if the same indicator fires 3+ times within 5 minutes?

---

## Proposed Changes

### 1. Threat Detection Engine
#### [MODIFY] [threat_detection.py](file:///C:/Users/RuchitRathi/Cybersecurity%20POC/cybersec_platform/threat_detection.py)

**Remove** the entire `INDICATOR_PATTERNS` list (40+ web-app signatures) and replace with ~25 ISP-focused patterns organised into these categories:

| Category | Threats | MITRE | Direct Indicator |
|---|---|---|---|
| Brute-Force / Credential | SSH brute force, password spraying, SIP registration attack | T1110, T1110.003 | `failed password`, `failed login`, `SIP registration attack` |
| DDoS / Volumetric | SYN flood, UDP amplification, NTP monlist, HTTP flood, ICMP flood | T1498, T1498.001 | `SYN flood`, `UDP amplification`, `connection limit reached` |
| Port Scan / Recon | nmap, masscan, SNMP brute force, DNS zone transfer | T1046, T1595 | `nmap`, `masscan`, `ports scanned`, `AXFR` |
| DNS Attacks | DNS tunneling, cache poisoning, water torture, NXDOMAIN flood, rebinding | T1048.003, T1584.002 | `dns tunnel`, `base64.*subdomain`, `cache poisoning`, `NXDOMAIN flood` |
| C2 / Botnet | Reverse shell, Mirai, Emotet, Tor exit node, cryptominer | T1071, T1105, T1496 | `C2 beacon`, `reverse shell`, `botnet`, `stratum+tcp`, `xmrig` |
| Malware Distribution | Payload download, ransomware, fileless malware, LOLBins, worm | T1105, T1486, T1059.001 | `ransomware`, `.encrypted`, `powershell -Enc`, `certutil -decode` |
| Data Exfiltration | Large outbound transfer, database dump, ICMP tunnel, steganography | T1041, T1048, T1005 | `exfiltration`, `mysqldump`, `ICMP tunnel` |
| Credential Access | Credential dumping, credential exposure in logs, phishing kit | T1003, T1552 | `lsass`, `password=`, `credential harvesting` |
| Network Infrastructure | ARP poisoning, BGP hijack, MitM/SSL strip, lateral movement, router compromise | T1557, T1599, T1550.002 | `ARP spoof`, `BGP hijack`, `SSL strip`, `pass-the-hash` |
| ISP Abuse | Spam botnet, open proxy, copyright/DMCA, VoIP fraud, TDoS | T1498, T1071 | `spam botnet`, `DMCA`, `SIP trunk abuse`, `TDoS` |
| IoT Compromise | Mirai IoT, CCTV compromise, smart meter tampering | T1584.005 | `Mirai infection`, `default credentials`, `camera compromise` |

**New correlation engine** inside `ThreatDetector.detect()`:

```
For each log entry:
  1. Run ISP signature matching → yields list of candidate threats
  2. Check for OPERATIONAL indicators (latency, packet loss, jitter, congestion)
     → If ONLY operational indicators match and NO security indicator present:
       → Result = "Monitor" (NOT a confirmed threat)
  3. For each candidate threat:
     a. If a DIRECT indicator fires → Confirmed threat (confidence ≥ 0.70)
     b. If two INDEPENDENT corroborating indicators fire → Confirmed (confidence ≥ 0.65)
     c. If only one non-direct indicator → "Monitor" status (confidence 0.30-0.55)
  4. Deduplicate: collapse same (source_ip, threat_type) within 60s window
  5. Map to MITRE ATT&CK technique
  6. Compute conservative confidence using ML scores + evidence count
```

**Rewrite** `THREAT_DETAILS` and `CATEGORY_DETAILS` dictionaries with ISP-specific explanations, impacts, and mitigations.

---

### 2. Feature Engineering
#### [MODIFY] [feature_engineering.py](file:///C:/Users/RuchitRathi/Cybersecurity%20POC/cybersec_platform/feature_engineering.py)

Add ISP-specific feature extraction fields:
- `service` (dhcp, dns, firewall, bandwidth, voip, email, iot, network, proxy, infrastructure)
- `protocol` (TCP, UDP, ICMP, SIP, BITTORRENT, etc.)
- `dst_port` (integer)
- `usage_mbps` (float)
- `dropped_packets` (integer)
- `rtt_ms` (float)
- `is_operational_only` (boolean — true when log is a performance metric with no security indicator)

---

### 3. Mock Log Generation
#### [MODIFY] [integrations.py](file:///C:/Users/RuchitRathi/Cybersecurity%20POC/cybersec_platform/integrations.py)

The mock data is already ISP-focused. Minor changes:
- Include `NETWORK_PERFORMANCE_TEMPLATES` and `SECURITY_THREAT_TEMPLATES` in the random log mix (currently only `ATTACK_TEMPLATES` and `BENIGN_TEMPLATES` are used in `_generate_mock_log`)
- Add `CRITICAL_OUTAGE_TEMPLATES` at a low rate (~1%)

---

### 4. UI Updates
#### [MODIFY] [index.html](file:///C:/Users/RuchitRathi/Cybersecurity%20POC/templates/index.html)
- Change placeholder text from generic server log to ISP log example
- Re-label section from "Manual Log Analysis" to "ISP Log Analysis"

#### [MODIFY] [dashboard.js](file:///C:/Users/RuchitRathi/Cybersecurity%20POC/static/dashboard.js)
- Add "Monitor" badge styling (blue/info color)
- Handle `status: "Monitor"` vs `status: "Confirmed"` in incident cards
- Show evidence summary in each card (which indicators fired)

---

### 5. ML Models
#### [MODIFY] [models.py](file:///C:/Users/RuchitRathi/Cybersecurity%20POC/cybersec_platform/models.py)
- No structural changes needed; the IsolationForest and RandomForest will continue to provide anomaly scores and classification probabilities
- The confidence blending in the new correlation engine will weight ML scores appropriately

---

## Verification Plan

### Automated Tests
- `python test_confidence.py` — verify multi-threat detection with realistic ISP logs
- `python -m pytest tests/` — ensure existing parsing and feature tests still pass

### Manual Verification
1. Start server with `python run.py`
2. Paste an ISP attack log (e.g., DDoS SYN flood) → should see confirmed threat with MITRE mapping
3. Paste a latency/packet-loss log → should see "Monitor" or "Not Detected", NOT a confirmed threat
4. Paste multiple threats in one block → each should appear as a separate card with distinct confidence
5. Verify deduplication: same IP + same threat type within 60s → collapsed to one finding
