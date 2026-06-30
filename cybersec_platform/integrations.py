import logging
import random
from datetime import datetime, timedelta
from typing import Any, Dict, List

from .config import Config

logger = logging.getLogger(__name__)


class GrafanaClient:
    """Mock client for Grafana API."""
    def __init__(self, config: Config):
        self.base_url = config["grafana"]["base_url"]

    def fetch_dashboards(self) -> List[Dict[str, Any]]:
        logger.debug("Fetching dashboards from Grafana")
        return [{"id": 1, "title": "Main Cyber Dashboard"}]



def _random_ip():
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def _internal_ip():
    return f"192.168.{random.randint(1, 10)}.{random.randint(2, 200)}"

# ISP-specific attack templates focused on network-level threats
ATTACK_TEMPLATES = [
    # ── NETWORK SCANNING & RECONNAISSANCE ─────────────────────
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "WARN", "message": "Port scan detected: nmap SYN scan from {ip} - 1024 ports scanned in 2s"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "WARN", "message": "Network reconnaissance: masscan detected from {ip} targeting ISP subnet 10.0.0.0/8"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "HIGH", "message": "Service enumeration: {ip} probing multiple ports (21,22,23,80,443,3389) on customer network"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "WARN", "message": "DNS zone transfer attempt from {ip} - AXFR query blocked"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "WARN", "message": "SNMP community string brute force from {ip} against ISP infrastructure"}}',
    # ── DDoS ATTACKS ──────────────────────────────────────────
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "CRITICAL", "message": "DDoS: SYN flood from {ip} — 80,000 packets/second detected, connection limit reached"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "CRITICAL", "message": "DDoS: UDP amplification attack from {ip} — DNS reflection, 500x amplification factor"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "CRITICAL", "message": "DDoS: NTP monlist amplification from {ip} — 47x amplification detected"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "CRITICAL", "message": "DDoS: HTTP flood from botnet {ip} — 10,000 requests/second to customer web server"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "HIGH", "message": "Volumetric attack: ICMP flood from {ip} saturating ISP backbone link"}}',
    # ── DNS ATTACKS ───────────────────────────────────────────
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "HIGH", "message": "DNS tunneling: unusually long DNS query from {ip} — base64 encoded payload in subdomain"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "CRITICAL", "message": "DNS cache poisoning attempt from {ip} — spoofed DNS response detected"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "HIGH", "message": "DNS water torture attack from {ip} — random subdomain flooding"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "WARN", "message": "DNS rebinding attack detected from {ip} — malicious DNS server response"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "HIGH", "message": "DNS DDoS: NXDOMAIN flood from {ip} — 50,000 queries/second to non-existent domains"}}',
    # ── BOTNET & C2 TRAFFIC ───────────────────────────────────
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "CRITICAL", "message": "C2 beacon detected: reverse shell callback to {ip}:4444 — backdoor installed"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "CRITICAL", "message": "Botnet activity: Mirai botnet C2 communication from {ip} — IoT device compromise"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "HIGH", "message": "P2P botnet traffic detected from {ip} — Emotet C2 communication pattern"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "CRITICAL", "message": "Cryptominer detected: xmrig process connecting to stratum+tcp://pool.minexmr.com:4444"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "HIGH", "message": "Tor exit node traffic detected from {ip} — anonymizer in use for C2 communications"}}',
    # ── MALWARE DISTRIBUTION ─────────────────────────────────
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "CRITICAL", "message": "Malware distribution: {ip} serving Emotet payload via HTTP download"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "CRITICAL", "message": "Ransomware encryption detected in /home/user/docs — files renamed to .encrypted"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "HIGH", "message": "Fileless malware: powershell -EncodedCommand aQBlAHgAIA... executed in memory"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "HIGH", "message": "LOLBin abuse: certutil -decode dropping payload to C:\\\\Windows\\\\Temp\\\\malware.exe"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "CRITICAL", "message": "Worm propagation: SMB exploit EternalBlue from {ip} — WannaCry-like activity"}}',
    # ── DATA EXFILTRATION ─────────────────────────────────────
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "CRITICAL", "message": "Data exfiltration detected: 2.4GB outbound transfer to {ip} on port 443"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "CRITICAL", "message": "Database dump detected: mysqldump executed by app user — 50,000 rows exported"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "HIGH", "message": "Large file transfer: 10GB upload from {ip} to cloud storage — potential exfiltration"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "HIGH", "message": "Covert channel: ICMP tunneling detected from {ip} — data exfiltration via ping packets"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "CRITICAL", "message": "Steganography: suspicious image uploads from {ip} — hidden data detected"}}',
    # ── PHISHING & CREDENTIAL THEFT ───────────────────────────
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "HIGH", "message": "Phishing kit detected: {ip} hosting credential harvesting page mimicking bank login"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "HIGH", "message": "Credential dumping detected: lsass.exe memory access by unknown process from {ip}"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "WARN", "message": "Password spraying detected: 50 accounts failed login from {ip} in 30 seconds"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "HIGH", "message": "Brute-force authentication: SSH login attempts from {ip} — 1000 failed attempts in 5 minutes"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "CRITICAL", "message": "Credential exposure in logs: password=P@ssw0rd123 for user svcadmin"}}',
    # ── NETWORK INFRASTRUCTURE ATTACKS ───────────────────────
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "HIGH", "message": "ARP poisoning detected: ARP spoof from {ip} on internal subnet 192.168.1.0/24"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "CRITICAL", "message": "BGP hijacking attempt: suspicious route announcement from {ip} — prefix hijack detected"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "HIGH", "message": "Man-in-the-Middle (MitM): SSL strip attempt from {ip} — certificate mismatch"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "HIGH", "message": "Lateral movement: pass-the-hash from {ip} to 192.168.1.20 via SMB"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "CRITICAL", "message": "Router compromise: unauthorized configuration change on ISP edge router from {ip}"}}',
    # ── ISP-SPECIFIC ABUSE ────────────────────────────────────
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "HIGH", "message": "Spam campaign: {ip} sending 10,000 emails in 1 hour — spam botnet detected"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "WARN", "message": "Port forwarding abuse: {ip} exposing internal services via UPnP"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "HIGH", "message": "Proxy abuse: open proxy detected on {ip} — being used for malicious traffic"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "WARN", "message": "Copyright infringement: torrent traffic from {ip} — DMCA violation detected"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "HIGH", "message": "Account sharing: multiple simultaneous logins from different IPs for same customer account"}}',
    # ── VOIP & TELEPHONY ATTACKS ─────────────────────────────
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "CRITICAL", "message": "VoIP fraud: SIP trunk abuse from {ip} — international toll fraud detected"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "HIGH", "message": "TDoS attack: Telephony Denial of Service from {ip} — 1000 calls/minute to customer PBX"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "WARN", "message": "SIP registration attack: brute-force SIP credentials from {ip}"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "HIGH", "message": "Eavesdropping: SIP INVITE with malformed headers from {ip} — call interception attempt"}}',
    # ── IOT & SMART HOME ATTACKS ──────────────────────────────
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "HIGH", "message": "IoT botnet: Mirai infection on customer device {ip} — default credentials exploited"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "WARN", "message": "Smart home abuse: unauthorized access to customer IoT hub from {ip}"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "HIGH", "message": "CCTV camera compromise: {ip} accessing customer camera feed without authorization"}}',
    lambda ip, dt: f'{{"timestamp": "{dt.isoformat()}Z", "level": "WARN", "message": "Smart meter tampering: unusual power consumption pattern from {ip} — potential fraud"}}',
]

# Normal benign ISP log templates
BENIGN_TEMPLATES = [
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"INFO\", \"service\": \"dhcp\", \"message\": \"DHCP lease assigned to {ip}\", \"lease_time\": 86400}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"INFO\", \"service\": \"dns\", \"message\": \"DNS query resolved\", \"query\": \"example.com\", \"response_ip\": \"93.184.216.34\"}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"INFO\", \"service\": \"routing\", \"message\": \"BGP route update received\", \"prefix\": \"192.0.2.0/24\", \"as_path\": \"64512 64513\"}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"INFO\", \"service\": \"firewall\", \"message\": \"Connection allowed\", \"src_ip\": \"{ip}\", \"dst_port\": 443, \"protocol\": \"TCP\"}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"INFO\", \"service\": \"bandwidth\", \"message\": \"Bandwidth usage normal\", \"customer_id\": {random.randint(1000,9999)}, \"usage_mbps\": {random.uniform(10,100)}}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"INFO\", \"service\": \"voip\", \"message\": \"SIP call established\", \"caller\": \"{ip}\", \"duration\": {random.randint(60,3600)}}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"DEBUG\", \"service\": \"network\", \"message\": \"ICMP ping response\", \"src_ip\": \"{ip}\", \"rtt_ms\": {random.uniform(1,50)}}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"INFO\", \"service\": \"proxy\", \"message\": \"HTTP proxy request\", \"client_ip\": \"{ip}\", \"target\": \"example.com\", \"status\": 200}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"INFO\", \"service\": \"email\", \"message\": \"SMTP connection established\", \"client_ip\": \"{ip}\", \"emails_sent\": {random.randint(1,10)}}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"INFO\", \"service\": \"iot\", \"message\": \"IoT device heartbeat\", \"device_ip\": \"{ip}\", \"device_type\": \"smart_thermostat\"}}',
]

# ISP network performance monitoring templates (non-security)
NETWORK_PERFORMANCE_TEMPLATES = [
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"INFO\", \"service\": \"network\", \"message\": \"High latency detected from {ip}, rtt_ms: {random.uniform(200,500)} - degraded performance\", \"src_ip\": \"{ip}\", \"rtt_ms\": {random.uniform(200,500)}}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"INFO\", \"service\": \"network\", \"message\": \"Packet loss detected from {ip}, dropped_packets: {random.randint(10,50)} - connection unstable\", \"src_ip\": \"{ip}\", \"dropped_packets\": {random.randint(10,50)}}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"INFO\", \"service\": \"dns\", \"message\": \"DNS resolution timeout for query - NXDOMAIN\", \"query\": \"example.invalid\"}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"INFO\", \"service\": \"bandwidth\", \"message\": \"Bandwidth spike detected from {ip}, usage_mbps: {random.uniform(300,500)} - high throughput\", \"src_ip\": \"{ip}\", \"usage_mbps\": {random.uniform(300,500)}}}',
]

# ISP security threat templates (require explicit evidence)
SECURITY_THREAT_TEMPLATES = [
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"WARN\", \"service\": \"network\", \"message\": \"Bittorrent handshake detected from {ip} on port 6881 - tracker connection established\", \"src_ip\": \"{ip}\", \"protocol\": \"BITTORRENT\", \"port\": 6881}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"WARN\", \"service\": \"network\", \"message\": \"DMCA takedown notice received for copyright infringement confirmed from {ip}\", \"src_ip\": \"{ip}\", \"violation_type\": \"copyright_infringement\"}}',
]

# Critical infrastructure outage templates (sustained failure only)
CRITICAL_OUTAGE_TEMPLATES = [
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"CRITICAL\", \"service\": \"infrastructure\", \"message\": \"Sustained outage: multi-node failure detected across 3 data centers, service unavailable confirmed\", \"affected_nodes\": 3, \"status\": \"critical\"}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"CRITICAL\", \"service\": \"infrastructure\", \"message\": \"Complete service failure: critical infrastructure down, confirmed unavailability for 15 minutes\", \"duration_minutes\": 15, \"status\": \"down\"}}',
]


class LokiClient:
    """Mock client for Loki logs — generates rich, realistic multi-source log data."""
    def __init__(self, config: Config):
        self.base_url = config["loki"]["base_url"]

    def query_logs(self, query: str, limit: int = 100) -> List[str]:
        logger.debug("Querying Loki logs: %s", query)
        logs = []
        now = datetime.utcnow()
        for _ in range(limit):
            dt = now - timedelta(seconds=random.randint(0, 60))
            logs.append(self._generate_mock_log(dt))
        return logs

    def _generate_mock_log(self, dt: datetime) -> str:
        ip = _random_ip()
        rand = random.random()
        
        # 12% attacks
        if rand < 0.12:
            template = random.choice(ATTACK_TEMPLATES)
            return template(ip, dt)
        # 5% network performance
        elif rand < 0.17:
            template = random.choice(NETWORK_PERFORMANCE_TEMPLATES)
            return template(ip, dt)
        # 2% security threats
        elif rand < 0.19:
            template = random.choice(SECURITY_THREAT_TEMPLATES)
            return template(ip, dt)
        # 1% critical outages
        elif rand < 0.20:
            template = random.choice(CRITICAL_OUTAGE_TEMPLATES)
            return template(ip, dt)
        # Remaining are benign
        template = random.choice(BENIGN_TEMPLATES)
        return template(ip, dt)


class PrometheusClient:
    """Mock client for Prometheus metrics with realistic spikes and anomalies."""
    def __init__(self, config: Config):
        self.base_url = config["prometheus"]["base_url"]

    def query_metrics(self, query: str) -> Dict[str, float]:
        logger.debug("Querying Prometheus metrics: %s", query)
        # ~8% chance of a resource spike (DDoS, cryptominer, etc.)
        is_spike = random.random() < 0.08
        # ~3% chance of a network exfiltration anomaly
        is_exfil = random.random() < 0.03

        return {
            "cpu_usage": random.uniform(88.0, 100.0) if is_spike else random.uniform(10.0, 55.0),
            "memory_usage": random.uniform(92.0, 99.5) if is_spike else random.uniform(30.0, 72.0),
            "network_tx": random.uniform(50000.0, 200000.0) if is_exfil else random.uniform(100.0, 6000.0),
            "network_rx": random.uniform(50000.0, 200000.0) if is_spike else random.uniform(100.0, 6000.0),
            "active_connections": random.randint(5000, 50000) if is_spike else random.randint(10, 300),
            "http_error_rate": random.uniform(0.5, 1.0) if is_spike else random.uniform(0.0, 0.05),
            "failed_login_rate": random.uniform(0.3, 1.0) if is_spike else random.uniform(0.0, 0.02),
            "dns_query_rate": random.uniform(1000.0, 5000.0) if is_exfil else random.uniform(10.0, 200.0),
        }
