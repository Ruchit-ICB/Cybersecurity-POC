"""
Holdout accuracy test using hand-crafted synthetic logs.

Every log here uses phrasing that does NOT appear verbatim in ATTACK_TEMPLATES
or BENIGN_TEMPLATES — it paraphrases real-world ISP/SIEM log formats drawn from
publicly documented attack patterns.  This tests generalisation, not template
memorisation.

Labels
------
  "attack"  — should be detected (SUSPICIOUS or CONFIRMED)
  "benign"  — must NOT be detected
  "perf"    — operational metric; must NOT be flagged as a security threat
"""

import pytest
from cybersec_platform.feature_engineering import extract_features
from cybersec_platform.threat_detection import ThreatDetector

# ---------------------------------------------------------------------------
# Synthetic attack logs — novel phrasing, same underlying attack classes
# ---------------------------------------------------------------------------
SYNTHETIC_ATTACKS = [
    # Brute-force / credential
    ("brute_force",    '{"ts":"2026-06-28T08:12:00Z","sev":"HIGH","msg":"authentication failure: 350 invalid password attempts for user root from 198.51.100.9 in 60s"}'),
    ("brute_force",    '{"ts":"2026-06-28T08:13:00Z","sev":"HIGH","msg":"SSH login attempts exceeded threshold: 500 failed logins from 203.0.113.77 — account locked"}'),
    ("brute_force",    '{"ts":"2026-06-28T08:14:00Z","sev":"WARN","msg":"too many failed auth attempts on RADIUS from 192.0.2.44, max auth attempts reached"}'),
    ("brute_force",    '{"ts":"2026-06-28T08:15:00Z","sev":"HIGH","msg":"login failed repeatedly: credential validation failed for admin@portal.isp.net from 10.20.30.40"}'),
    ("password_spray", '{"ts":"2026-06-28T08:16:00Z","sev":"HIGH","msg":"distributed login failure: 120 different accounts failed within 2 minutes — spray attack suspected"}'),
    ("password_spray", '{"ts":"2026-06-28T08:17:00Z","sev":"WARN","msg":"lockout threshold hit across 80 customer accounts from single source — password spraying detected"}'),

    # DDoS / volumetric
    ("ddos",   '{"ts":"2026-06-28T09:00:00Z","sev":"CRITICAL","msg":"syn flood attack inbound on edge router ge-0/0/1: 95,000 pps, connection limit reached"}'),
    ("ddos",   '{"ts":"2026-06-28T09:01:00Z","sev":"CRITICAL","msg":"volumetric attack detected: udp flood targeting customer 203.0.113.100, rate limit exceeded at 40 Gbps"}'),
    ("ddos",   '{"ts":"2026-06-28T09:02:00Z","sev":"CRITICAL","msg":"ICMP flood from 198.51.100.0/24 saturating backbone link xe-1/1/0 at 100% utilisation"}'),
    ("ddos",   '{"ts":"2026-06-28T09:03:00Z","sev":"HIGH","msg":"http flood detected: botnet traffic to origin 203.0.113.55 — 18,000 requests per second"}'),
    ("amp",    '{"ts":"2026-06-28T09:04:00Z","sev":"CRITICAL","msg":"NTP monlist abuse: amplification factor 650x observed, source 198.51.100.20 sending reflection traffic"}'),
    ("amp",    '{"ts":"2026-06-28T09:05:00Z","sev":"CRITICAL","msg":"DNS reflection DDoS: UDP amplification attack amplification factor 45 via open resolvers"}'),

    # Port scan / recon
    ("portscan", '{"ts":"2026-06-28T09:10:00Z","sev":"WARN","msg":"nmap SYN scan detected from 203.0.113.5 — 2048 ports scanned in 3 seconds"}'),
    ("portscan", '{"ts":"2026-06-28T09:11:00Z","sev":"WARN","msg":"masscan sweep across ISP subnet 10.0.0.0/16 from external host 198.51.100.99"}'),
    ("portscan", '{"ts":"2026-06-28T09:12:00Z","sev":"WARN","msg":"SNMP community string brute force from 203.0.113.3 targeting CPE infrastructure"}'),
    ("portscan", '{"ts":"2026-06-28T09:13:00Z","sev":"WARN","msg":"DNS zone transfer attempt blocked: AXFR query from 192.0.2.77 to authoritative NS"}'),
    ("portscan", '{"ts":"2026-06-28T09:14:00Z","sev":"HIGH","msg":"service enumeration detected: host 10.0.0.5 probing multiple ports on customer VLAN"}'),

    # DNS attacks
    ("dns_tunnel", '{"ts":"2026-06-28T10:00:00Z","sev":"HIGH","msg":"dns tunnel traffic identified: iodine client connecting via ISP resolver from 192.0.2.50"}'),
    ("dns_tunnel", '{"ts":"2026-06-28T10:01:00Z","sev":"HIGH","msg":"high dns query rate anomaly: unusually long DNS labels observed — possible dnscat exfil channel"}'),
    ("dns_poison", '{"ts":"2026-06-28T10:02:00Z","sev":"CRITICAL","msg":"DNS cache poisoning attempt detected on resolver r1.isp.net — spoofed DNS response injected"}'),
    ("dns_poison", '{"ts":"2026-06-28T10:03:00Z","sev":"HIGH","msg":"DNS rebinding attack: malicious DNS server response redirecting internal lookup to 169.254.x.x"}'),
    ("dns_nxdomain",'{"ts":"2026-06-28T10:04:00Z","sev":"HIGH","msg":"NXDOMAIN flood: 62,000 queries per second for random subdomains — DNS water torture pattern"}'),

    # C2 / botnet
    ("c2",       '{"ts":"2026-06-28T11:00:00Z","sev":"CRITICAL","msg":"c2 beacon detected: outbound callback to 198.51.100.88:4444 every 30s — backdoor installed on host"}'),
    ("c2",       '{"ts":"2026-06-28T11:01:00Z","sev":"CRITICAL","msg":"botnet activity: Mirai botnet C2 heartbeat from infected device 10.10.10.5"}'),
    ("c2",       '{"ts":"2026-06-28T11:02:00Z","sev":"CRITICAL","msg":"reverse shell session opened from 192.0.2.100 to external C2 server — command and control confirmed"}'),
    ("tor",      '{"ts":"2026-06-28T11:03:00Z","sev":"HIGH","msg":"tor exit node egress detected: customer traffic routed through darknet traffic relay 198.51.100.7"}'),
    ("miner",    '{"ts":"2026-06-28T11:04:00Z","sev":"CRITICAL","msg":"xmrig miner process spawned on CPE device, connecting to stratum+tcp://xmr-pool.net:14444"}'),
    ("miner",    '{"ts":"2026-06-28T11:05:00Z","sev":"CRITICAL","msg":"cpu mining detected: nicehash client active on residential subscriber 203.0.113.201"}'),

    # Malware
    ("malware",    '{"ts":"2026-06-28T12:00:00Z","sev":"CRITICAL","msg":"malware distribution: customer-hosted server at 203.0.113.66 serving Emotet payload via HTTP"}'),
    ("ransomware", '{"ts":"2026-06-28T12:01:00Z","sev":"CRITICAL","msg":"ransomware encryption detected: bulk rename to .encrypted extension across /mnt/data share"}'),
    ("ransomware", '{"ts":"2026-06-28T12:02:00Z","sev":"CRITICAL","msg":"your files are encrypted — ransom note README_DECRYPT.txt dropped in 840 directories"}'),
    ("fileless",   '{"ts":"2026-06-28T12:03:00Z","sev":"HIGH","msg":"fileless malware execution: powershell -enc SQBFAFgA... spawned by winword.exe"}'),
    ("fileless",   '{"ts":"2026-06-28T12:04:00Z","sev":"HIGH","msg":"LOLBin abuse: certutil -decode C:\\tmp\\a.b64 C:\\windows\\temp\\shell.exe observed on endpoint"}'),
    ("worm",       '{"ts":"2026-06-28T12:05:00Z","sev":"CRITICAL","msg":"SMB worm propagation via EternalBlue exploit from 10.20.0.5 — WannaCry-like lateral spread"}'),

    # Data exfiltration
    ("exfil",   '{"ts":"2026-06-28T13:00:00Z","sev":"CRITICAL","msg":"exfiltration detected: 3.8 GB outbound data transfer from 10.10.1.50 to 198.51.100.33 over 443"}'),
    ("exfil",   '{"ts":"2026-06-28T13:01:00Z","sev":"HIGH","msg":"large file transfer: 15 GB upload to external S3 endpoint — potential exfiltration via GB upload to cloud storage"}'),
    ("exfil",   '{"ts":"2026-06-28T13:02:00Z","sev":"HIGH","msg":"ICMP tunneling: covert channel using ping packets from 192.0.2.30 — data exfiltration suspected"}'),
    ("db_dump", '{"ts":"2026-06-28T13:03:00Z","sev":"CRITICAL","msg":"mysqldump executed by app_user on prod-db-01 — 2.1M rows exported to /tmp/backup.sql"}'),
    ("db_dump", '{"ts":"2026-06-28T13:04:00Z","sev":"CRITICAL","msg":"database dump detected: pg_dump running against customer_db — no authorised backup scheduled"}'),

    # Credential access
    ("cred_dump",   '{"ts":"2026-06-28T14:00:00Z","sev":"CRITICAL","msg":"credential dumping detected: lsass.exe memory read by unknown process PID 3842 from 10.0.1.5"}'),
    ("cred_dump",   '{"ts":"2026-06-28T14:01:00Z","sev":"CRITICAL","msg":"mimikatz execution detected on DC01 — sekurlsa module invoked for credential extraction"}'),
    ("cred_expose", '{"ts":"2026-06-28T14:02:00Z","sev":"CRITICAL","msg":"plaintext secret in log: api_key=sk-live-aBcDeFgHiJkLmNoPqRsTuVwXyZ found in app debug output"}'),
    ("cred_expose", '{"ts":"2026-06-28T14:03:00Z","sev":"CRITICAL","msg":"credential exposure in logs: password=S3cur3P@ss! for svc_backup leaked in audit trail"}'),
    ("phishing",    '{"ts":"2026-06-28T14:04:00Z","sev":"HIGH","msg":"phishing kit detected: credential harvesting page mimicking bank login hosted at 203.0.113.80/login.php"}'),

    # Network infrastructure
    ("bgp",     '{"ts":"2026-06-28T15:00:00Z","sev":"CRITICAL","msg":"BGP hijacking detected: suspicious route announcement for 203.0.113.0/24 from AS64999 — prefix hijack confirmed"}'),
    ("mitm",    '{"ts":"2026-06-28T15:01:00Z","sev":"HIGH","msg":"ARP spoof detected on VLAN 100: 00:11:22:33:44:55 poisoning gateway 192.168.1.1 — arp poison in progress"}'),
    ("mitm",    '{"ts":"2026-06-28T15:02:00Z","sev":"HIGH","msg":"SSL strip attempt from 10.10.1.90 — certificate mismatch observed on HTTPS session to online-banking.example.com"}'),
    ("router",  '{"ts":"2026-06-28T15:03:00Z","sev":"CRITICAL","msg":"unauthorized configuration change on ISP edge router rtr-core-01 from 198.51.100.5 via SNMP write"}'),
    ("lateral", '{"ts":"2026-06-28T15:04:00Z","sev":"CRITICAL","msg":"lateral movement via pass-the-hash: NTLM relay from 10.0.0.5 to 10.0.0.20 using stolen hash"}'),
    ("lateral", '{"ts":"2026-06-28T15:05:00Z","sev":"CRITICAL","msg":"psexec remote execution detected from 10.1.1.10 to 10.1.1.20 — admin share access confirmed"}'),

    # ISP abuse
    ("spam",    '{"ts":"2026-06-28T16:00:00Z","sev":"HIGH","msg":"spam campaign: customer 203.0.113.77 sending 15,000 emails per hour — spam botnet activity"}'),
    ("proxy",   '{"ts":"2026-06-28T16:01:00Z","sev":"HIGH","msg":"open proxy on 198.51.100.40:8080 abused for malicious traffic routing — proxy abuse detected"}'),
    ("dmca",    '{"ts":"2026-06-28T16:02:00Z","sev":"WARN","msg":"copyright infringement: BitTorrent traffic from 192.0.2.60 — DMCA violation takedown notice received"}'),
    ("dmca",    '{"ts":"2026-06-28T16:03:00Z","sev":"WARN","msg":"bittorrent handshake from 192.0.2.61 port 6881 — P2P file sharing activity confirmed"}'),
    ("acct",    '{"ts":"2026-06-28T16:04:00Z","sev":"WARN","msg":"account sharing: multiple simultaneous logins from 5 different IPs detected for same customer account CID-4421"}'),

    # VoIP
    ("voip",  '{"ts":"2026-06-28T17:00:00Z","sev":"CRITICAL","msg":"VoIP fraud alert: SIP trunk abuse — 2,400 outbound calls to premium international numbers from PBX 10.5.0.1"}'),
    ("tdos",  '{"ts":"2026-06-28T17:01:00Z","sev":"CRITICAL","msg":"TDoS attack: 1,500 calls per minute flooding customer PBX at 203.0.113.111 — Telephony Denial of Service"}'),
    ("sip",   '{"ts":"2026-06-28T17:02:00Z","sev":"HIGH","msg":"SIP registration attack: brute-force SIP credentials from 198.51.100.33 against voip-gw.isp.net"}'),

    # IoT
    ("iot",   '{"ts":"2026-06-28T18:00:00Z","sev":"HIGH","msg":"IoT botnet: Mirai infection on CPE device 192.168.1.100 — default credentials exploited, joining C2 swarm"}'),
    ("cctv",  '{"ts":"2026-06-28T18:01:00Z","sev":"HIGH","msg":"CCTV camera compromise: unauthorised session accessing camera feed of customer premise 203.0.113.200"}'),
    ("meter", '{"ts":"2026-06-28T18:02:00Z","sev":"WARN","msg":"smart meter tampering: unusual power consumption pattern on meter M-99812 — potential energy fraud"}'),
]

# ---------------------------------------------------------------------------
# Benign logs — normal ISP operations, should produce zero detections
# ---------------------------------------------------------------------------
SYNTHETIC_BENIGN = [
    '{"ts":"2026-06-28T08:00:00Z","sev":"INFO","service":"dhcp","msg":"DHCP lease renewed for 192.168.5.22, lease time 86400s"}',
    '{"ts":"2026-06-28T08:01:00Z","sev":"INFO","service":"dns","msg":"DNS A record query for www.google.com resolved to 142.250.80.4 in 2ms"}',
    '{"ts":"2026-06-28T08:02:00Z","sev":"INFO","service":"bgp","msg":"BGP session established with peer AS65002, 14 prefixes received"}',
    '{"ts":"2026-06-28T08:03:00Z","sev":"INFO","service":"firewall","msg":"connection accepted: 192.168.1.5:54321 -> 1.1.1.1:443 TCP"}',
    '{"ts":"2026-06-28T08:04:00Z","sev":"INFO","service":"billing","msg":"customer CID-3310 data usage: 12.4 GB consumed this billing cycle"}',
    '{"ts":"2026-06-28T08:05:00Z","sev":"INFO","service":"voip","msg":"SIP call completed: caller 192.168.1.10, duration 185s, quality MOS 4.2"}',
    '{"ts":"2026-06-28T08:06:00Z","sev":"DEBUG","service":"network","msg":"ICMP echo reply from 8.8.8.8, rtt_ms 14.2, ttl 118"}',
    '{"ts":"2026-06-28T08:07:00Z","sev":"INFO","service":"proxy","msg":"HTTP CONNECT to api.github.com:443 from 10.0.0.44, status 200"}',
    '{"ts":"2026-06-28T08:08:00Z","sev":"INFO","service":"email","msg":"SMTP session: 3 messages delivered from 10.0.0.55 to mail.example.com"}',
    '{"ts":"2026-06-28T08:09:00Z","sev":"INFO","service":"iot","msg":"smart thermostat 192.168.10.5 heartbeat received, temp 21C, firmware up to date"}',
    '{"ts":"2026-06-28T08:10:00Z","sev":"INFO","service":"routing","msg":"OSPF adjacency formed with 10.1.1.2 on interface eth2"}',
    '{"ts":"2026-06-28T08:11:00Z","sev":"INFO","service":"ntp","msg":"NTP time sync successful, offset +0.003s from pool.ntp.org"}',
    '{"ts":"2026-06-28T08:12:00Z","sev":"INFO","service":"radius","msg":"RADIUS authentication success for user subscriber@isp.net from NAS 10.0.0.1"}',
    '{"ts":"2026-06-28T08:13:00Z","sev":"INFO","service":"snmp","msg":"SNMP GET response for sysUpTime from router 10.0.0.254, value 1034200"}',
    '{"ts":"2026-06-28T08:14:00Z","sev":"INFO","service":"cdn","msg":"CDN cache hit ratio 94.2% over last 5 minutes, origin traffic nominal"}',
    '{"ts":"2026-06-28T08:15:00Z","sev":"INFO","service":"bandwidth","msg":"subscriber 192.168.20.1 usage: 8.2 Mbps downstream, 1.1 Mbps upstream — within plan"}',
    '{"ts":"2026-06-28T08:16:00Z","sev":"INFO","service":"network","msg":"scheduled maintenance window started on core-sw-02, expected 30 min"}',
    '{"ts":"2026-06-28T08:17:00Z","sev":"INFO","service":"dns","msg":"DNSSEC validation passed for example.com, chain of trust verified"}',
    '{"ts":"2026-06-28T08:18:00Z","sev":"INFO","service":"auth","msg":"admin user ops-team logged in via SSO from corporate VPN 10.100.0.5"}',
    '{"ts":"2026-06-28T08:19:00Z","sev":"INFO","service":"backup","msg":"nightly backup completed: 42 GB archived to cold storage, integrity check passed"}',
]

# ---------------------------------------------------------------------------
# Pure operational/performance logs — must NOT trigger threat alerts
# ---------------------------------------------------------------------------
SYNTHETIC_PERF = [
    '{"ts":"2026-06-28T09:00:00Z","sev":"WARN","service":"network","msg":"elevated latency on link xe-0/1/0: rtt_ms 280ms average over 5 min — degraded performance"}',
    '{"ts":"2026-06-28T09:01:00Z","sev":"WARN","service":"network","msg":"packet loss detected on ge-0/0/3: dropped_packets 8% — connection unstable, investigating"}',
    '{"ts":"2026-06-28T09:02:00Z","sev":"INFO","service":"network","msg":"jitter threshold exceeded on VoIP VLAN 20: jitter 42ms — SLA monitoring alert"}',
    '{"ts":"2026-06-28T09:03:00Z","sev":"WARN","service":"bandwidth","msg":"congestion event on upstream peer link: utilisation 98%, traffic shaping active"}',
    '{"ts":"2026-06-28T09:04:00Z","sev":"INFO","service":"dns","msg":"DNS resolution timeout for stale.example.invalid — NXDOMAIN response returned to client"}',
    '{"ts":"2026-06-28T09:05:00Z","sev":"INFO","service":"network","msg":"high latency alert cleared: rtt_ms returned to normal 12ms on xe-0/1/0"}',
]

# ---------------------------------------------------------------------------
# Edge cases — ambiguous logs that should NOT be flagged (borderline phrasing)
# ---------------------------------------------------------------------------
SYNTHETIC_EDGE_BENIGN = [
    # "failed" in a non-auth context
    '{"ts":"2026-06-28T10:00:00Z","sev":"WARN","service":"backup","msg":"backup job failed: disk write error on /mnt/backup — retry scheduled in 1 hour"}',
    # "unusual" without security context
    '{"ts":"2026-06-28T10:01:00Z","sev":"INFO","service":"network","msg":"unusual traffic pattern: customer streaming 4K video, 35 Mbps sustained — within fair-use policy"}',
    # "scan" in a maintenance context
    '{"ts":"2026-06-28T10:02:00Z","sev":"INFO","service":"infra","msg":"antivirus scheduled scan completed on fileserver-01 — 0 threats found"}',
    # "proxy" in a normal context
    '{"ts":"2026-06-28T10:03:00Z","sev":"INFO","service":"proxy","msg":"transparent proxy cache warmed up for popular domains — hit rate now 89%"}',
    # "encrypted" in TLS context (not ransomware)
    '{"ts":"2026-06-28T10:04:00Z","sev":"INFO","service":"tls","msg":"TLS 1.3 session established: traffic encrypted between client and origin server"}',
    # password in a reset success context (no = sign assignment)
    '{"ts":"2026-06-28T10:05:00Z","sev":"INFO","service":"auth","msg":"user self-service password reset completed successfully for subscriber@isp.net"}',
]


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _detect(log_str: str) -> bool:
    detector = ThreatDetector()
    features = extract_features(log_str)
    return bool(detector.detect([features]))


def _collect_results():
    results = {
        "tp": 0, "fp": 0, "tn": 0, "fn": 0,
        "missed": [], "false_alarms": [],
        "conf_scores": [],
    }

    for label, log in SYNTHETIC_ATTACKS:
        detector = ThreatDetector()
        features = extract_features(log)
        dets = detector.detect([features])
        if dets:
            results["tp"] += 1
            results["conf_scores"].append(dets[0]["confidence"])
        else:
            results["fn"] += 1
            results["missed"].append((label, log[:100]))

    for log in SYNTHETIC_BENIGN + SYNTHETIC_PERF + SYNTHETIC_EDGE_BENIGN:
        detected = _detect(log)
        if detected:
            results["fp"] += 1
            results["false_alarms"].append(log[:100])
        else:
            results["tn"] += 1

    return results


# ---------------------------------------------------------------------------
# Individual focused tests (fast, run in CI)
# ---------------------------------------------------------------------------

class TestSyntheticAttacks:
    def test_brute_force_novel_phrasing(self):
        logs = [l for lb, l in SYNTHETIC_ATTACKS if lb == "brute_force"]
        for log in logs:
            assert _detect(log), f"Missed brute-force: {log[:80]}"

    def test_ddos_novel_phrasing(self):
        logs = [l for lb, l in SYNTHETIC_ATTACKS if lb in ("ddos", "amp")]
        for log in logs:
            assert _detect(log), f"Missed DDoS/amp: {log[:80]}"

    def test_port_scan_novel_phrasing(self):
        logs = [l for lb, l in SYNTHETIC_ATTACKS if lb == "portscan"]
        for log in logs:
            assert _detect(log), f"Missed port scan: {log[:80]}"

    def test_dns_attacks_novel_phrasing(self):
        logs = [l for lb, l in SYNTHETIC_ATTACKS if lb in ("dns_tunnel", "dns_poison", "dns_nxdomain")]
        for log in logs:
            assert _detect(log), f"Missed DNS attack: {log[:80]}"

    def test_c2_botnet_novel_phrasing(self):
        logs = [l for lb, l in SYNTHETIC_ATTACKS if lb in ("c2", "tor", "miner")]
        for log in logs:
            assert _detect(log), f"Missed C2/botnet: {log[:80]}"

    def test_malware_novel_phrasing(self):
        logs = [l for lb, l in SYNTHETIC_ATTACKS if lb in ("malware", "ransomware", "fileless", "worm")]
        for log in logs:
            assert _detect(log), f"Missed malware: {log[:80]}"

    def test_exfiltration_novel_phrasing(self):
        logs = [l for lb, l in SYNTHETIC_ATTACKS if lb in ("exfil", "db_dump")]
        for log in logs:
            assert _detect(log), f"Missed exfiltration: {log[:80]}"

    def test_credential_access_novel_phrasing(self):
        logs = [l for lb, l in SYNTHETIC_ATTACKS if lb in ("cred_dump", "cred_expose", "phishing")]
        for log in logs:
            assert _detect(log), f"Missed credential access: {log[:80]}"

    def test_network_infra_novel_phrasing(self):
        logs = [l for lb, l in SYNTHETIC_ATTACKS if lb in ("bgp", "mitm", "router", "lateral")]
        for log in logs:
            assert _detect(log), f"Missed network infra attack: {log[:80]}"

    def test_isp_abuse_novel_phrasing(self):
        logs = [l for lb, l in SYNTHETIC_ATTACKS if lb in ("spam", "proxy", "dmca", "acct")]
        for log in logs:
            assert _detect(log), f"Missed ISP abuse: {log[:80]}"

    def test_voip_iot_novel_phrasing(self):
        logs = [l for lb, l in SYNTHETIC_ATTACKS if lb in ("voip", "tdos", "sip", "iot", "cctv", "meter")]
        for log in logs:
            assert _detect(log), f"Missed VoIP/IoT: {log[:80]}"


class TestSyntheticBenign:
    def test_normal_isp_ops_not_flagged(self):
        for log in SYNTHETIC_BENIGN:
            assert not _detect(log), f"False alarm on benign log: {log[:80]}"

    def test_performance_metrics_not_flagged(self):
        for log in SYNTHETIC_PERF:
            assert not _detect(log), f"False alarm on perf log: {log[:80]}"

    def test_edge_case_benign_not_flagged(self):
        for log in SYNTHETIC_EDGE_BENIGN:
            assert not _detect(log), f"False alarm on edge-case log: {log[:80]}"


class TestSyntheticOverall:
    def test_precision_above_threshold(self):
        """Precision must be >= 95% on this holdout set."""
        r = _collect_results()
        precision = r["tp"] / (r["tp"] + r["fp"]) if (r["tp"] + r["fp"]) else 0
        assert precision >= 0.95, f"Precision {precision:.1%} below 95% — FP: {r['false_alarms']}"

    def test_recall_above_threshold(self):
        """Recall must be >= 85% — catches most attacks even on novel phrasing."""
        r = _collect_results()
        recall = r["tp"] / (r["tp"] + r["fn"]) if (r["tp"] + r["fn"]) else 0
        assert recall >= 0.85, f"Recall {recall:.1%} below 85% — missed: {r['missed']}"

    def test_f1_above_threshold(self):
        r = _collect_results()
        precision = r["tp"] / (r["tp"] + r["fp"]) if (r["tp"] + r["fp"]) else 0
        recall = r["tp"] / (r["tp"] + r["fn"]) if (r["tp"] + r["fn"]) else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
        assert f1 >= 0.90, f"F1 {f1:.1%} below 90%"
