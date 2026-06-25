import logging
import re
from typing import Any, Dict, List

from .models import AnomalyDetector, ThreatClassifier

logger = logging.getLogger(__name__)

# ============================================================
# COMPREHENSIVE ATTACK SIGNATURE LIBRARY
# Covers all attack categories observable via Grafana/Loki/Prometheus
# Mapped to MITRE ATT&CK framework
# ============================================================
INDICATOR_PATTERNS = [

    # ── WEB APPLICATION ATTACKS ─────────────────────────────
    {
        "name": "SQL Injection",
        "pattern": re.compile(
            r"\b(union\s+select|select\s+.*?\s+from|insert\s+into|drop\s+table|"
            r"alter\s+table|truncate\s+table|exec\s*\(|xp_cmdshell|"
            r"or\s+1\s*=\s*1|and\s+1\s*=\s*1|--|#\s|/\*.*?\*/|"
            r"benchmark\s*\(|sleep\s*\(|waitfor\s+delay)\b", re.IGNORECASE),
        "severity": "high", "type": "web_attack", "mitre": "T1190",
        "category": "Web Application Attack"
    },
    {
        "name": "Cross-Site Scripting (XSS)",
        "pattern": re.compile(
            r"(<script[\s>]|%3Cscript|javascript:|vbscript:|data:text/html|"
            r"onerror\s*=|onload\s*=|onmouseover\s*=|onclick\s*=|onfocus\s*=|"
            r"document\.cookie|document\.write|eval\s*\(|innerHTML\s*=|"
            r"fromCharCode|String\.fromCharCode)", re.IGNORECASE),
        "severity": "high", "type": "web_attack", "mitre": "T1059.007",
        "category": "Web Application Attack"
    },
    {
        "name": "Directory Traversal / Path Traversal",
        "pattern": re.compile(
            r"(\.\./\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c|%252e%252e|"
            r"\.\./etc/passwd|/etc/shadow|/etc/hosts|/proc/self|"
            r"c:\\windows\\system32|c:\\boot\.ini)", re.IGNORECASE),
        "severity": "high", "type": "web_attack", "mitre": "T1083",
        "category": "Web Application Attack"
    },
    {
        "name": "Command Injection / Remote Code Execution",
        "pattern": re.compile(
            r"([\|;&`]|\$\(|\$\{).*?(cat\s+/etc/passwd|nc\s+-e|bash\s+-i|"
            r"python\s+-c|php\s+-r|curl\s+http|wget\s+http|chmod\s+\+x|"
            r"/bin/sh|/bin/bash|cmd\.exe|powershell\.exe|"
            r"net\s+user|net\s+localgroup)", re.IGNORECASE),
        "severity": "critical", "type": "rce", "mitre": "T1059",
        "category": "Remote Code Execution"
    },
    {
        "name": "Server-Side Request Forgery (SSRF)",
        "pattern": re.compile(
            r"(url=https?://|url=http://localhost|url=http://127\.|"
            r"url=http://169\.254\.169\.254|url=file://|"
            r"http://metadata\.google|http://instance-data)", re.IGNORECASE),
        "severity": "high", "type": "ssrf", "mitre": "T1190",
        "category": "Web Application Attack"
    },
    {
        "name": "XML External Entity (XXE) Injection",
        "pattern": re.compile(
            r"(<!ENTITY|SYSTEM\s+['\"]file://|SYSTEM\s+['\"]http://|"
            r"<!DOCTYPE\s.*?SYSTEM|%dtd;|&xxe;|ENTITY\s+xxe)", re.IGNORECASE),
        "severity": "high", "type": "xxe", "mitre": "T1190",
        "category": "Web Application Attack"
    },
    {
        "name": "Server-Side Template Injection (SSTI)",
        "pattern": re.compile(
            r"(\{\{.*?7\s*\*\s*7.*?\}\}|\$\{7\s*\*\s*7\}|"
            r"<#assign|#\{7\s*\*\s*7\}|\{\%.*?(import|exec|os).*?\%\})",
            re.IGNORECASE),
        "severity": "critical", "type": "ssti", "mitre": "T1190",
        "category": "Web Application Attack"
    },
    {
        "name": "Insecure Deserialization",
        "pattern": re.compile(
            r"(java\.rmi\.|ObjectInputStream|rO0AB|aced0005|"
            r"php:\/\/filter|unserialize\s*\(|pickle\.loads|"
            r"yaml\.load\s*\(.*Loader=None)", re.IGNORECASE),
        "severity": "critical", "type": "deserialization", "mitre": "T1211",
        "category": "Web Application Attack"
    },
    {
        "name": "HTTP Request Smuggling",
        "pattern": re.compile(
            r"(Transfer-Encoding:\s*chunked.*Content-Length:|"
            r"Content-Length:\s*\d+.*Transfer-Encoding:\s*chunked|"
            r"0\r\n\r\nGET\s+/|chunked,identity|obf-chunked)", re.IGNORECASE),
        "severity": "high", "type": "request_smuggling", "mitre": "T1190",
        "category": "Web Application Attack"
    },

    # ── AUTHENTICATION & CREDENTIAL ATTACKS ─────────────────
    {
        "name": "Brute-Force Authentication",
        "pattern": re.compile(
            r"\b(failed\s+password|invalid\s+(user|password|login)|"
            r"authentication\s+failure|login\s+failed|"
            r"max\s+auth\s+attempts|too\s+many\s+failed|"
            r"credential\s+validation\s+failed)\b", re.IGNORECASE),
        "severity": "medium", "type": "brute_force", "mitre": "T1110",
        "category": "Authentication Attack"
    },
    {
        "name": "Password Spraying",
        "pattern": re.compile(
            r"(multiple\s+accounts.*failed|accounts\s+locked|"
            r"lockout\s+threshold|distributed\s+login\s+failure|"
            r"spray\s+attack|user\s+enumeration)", re.IGNORECASE),
        "severity": "high", "type": "password_spray", "mitre": "T1110.003",
        "category": "Authentication Attack"
    },
    {
        "name": "Credential Dumping",
        "pattern": re.compile(
            r"(lsass\.exe.*dump|procdump.*lsass|mimikatz|sekurlsa|"
            r"wce\.exe|ntdsutil|sam.*hive|/etc/shadow\s+read|"
            r"hashdump|pwdump)", re.IGNORECASE),
        "severity": "critical", "type": "credential_dumping", "mitre": "T1003",
        "category": "Credential Access"
    },
    {
        "name": "Credential Exposure in Logs",
        "pattern": re.compile(
            r"\b(password\s*=\s*\S+|passwd\s*=\s*\S+|api[-_]?key\s*=\s*\S+|"
            r"secret[-_]?token\s*=\s*\S+|aws_access_key|"
            r"private[-_]?key|authorization:\s+bearer\s+\S+)\b",
            re.IGNORECASE),
        "severity": "high", "type": "credential_exposure", "mitre": "T1552",
        "category": "Credential Access"
    },
    {
        "name": "OAuth / JWT Token Theft",
        "pattern": re.compile(
            r"(invalid\s+token|expired\s+token|token\s+reuse|"
            r"jwt\s+decode\s+error|bearer\s+token\s+misuse|"
            r"forged\s+token|stolen\s+jwt)", re.IGNORECASE),
        "severity": "high", "type": "token_theft", "mitre": "T1528",
        "category": "Credential Access"
    },

    # ── PRIVILEGE ESCALATION ─────────────────────────────────
    {
        "name": "Privilege Escalation (sudo/root)",
        "pattern": re.compile(
            r"\b(sudo:\s+\S+\s*:.*USER=root|pkexec|su\s+-\s+root|"
            r"runAs\s+administrator|setuid.*root|chmod\s+4755|"
            r"NOPASSWD.*ALL|\/etc\/sudoers\s+modified)\b", re.IGNORECASE),
        "severity": "critical", "type": "privilege_escalation", "mitre": "T1068",
        "category": "Privilege Escalation"
    },
    {
        "name": "Container Escape / Docker Breakout",
        "pattern": re.compile(
            r"(docker\.sock|/proc/1/root|runc.*escape|"
            r"container.*privilege|cgroup\s+release|"
            r"nsenter.*pid\s+1|cap_sys_admin.*container)", re.IGNORECASE),
        "severity": "critical", "type": "container_escape", "mitre": "T1611",
        "category": "Privilege Escalation"
    },
    {
        "name": "Kernel Exploit Attempt",
        "pattern": re.compile(
            r"(dirty\s*cow|exploit.*kernel|local\s+privilege.*escalation|"
            r"ptrace\s+inject|perf_event_open\s+exploit|"
            r"CVE-202[0-9]-\d+.*kernel)", re.IGNORECASE),
        "severity": "critical", "type": "kernel_exploit", "mitre": "T1068",
        "category": "Privilege Escalation"
    },

    # ── NETWORK ATTACKS ──────────────────────────────────────
    {
        "name": "Port Scanning / Reconnaissance",
        "pattern": re.compile(
            r"(nmap|masscan|zmap|SYN\s+scan|port\s+sweep|"
            r"\d+\s+port(s)?\s+scanned|OS\s+detection|service\s+detection|"
            r"Nessus|OpenVAS|nikto)", re.IGNORECASE),
        "severity": "medium", "type": "reconnaissance", "mitre": "T1046",
        "category": "Reconnaissance"
    },
    {
        "name": "DDoS / Volumetric Attack",
        "pattern": re.compile(
            r"(syn\s+flood|udp\s+flood|http\s+flood|amplification\s+attack|"
            r"ddos\s+detected|botnet\s+traffic|high\s+pps|packet\s+storm|"
            r"connection\s+limit\s+reached|rate\s+limit\s+exceeded)", re.IGNORECASE),
        "severity": "high", "type": "ddos", "mitre": "T1498",
        "category": "Network Attack"
    },
    {
        "name": "Man-in-the-Middle (MitM)",
        "pattern": re.compile(
            r"(arp\s+poison|arp\s+spoof|ssl\s+strip|ssl\s+intercept|"
            r"certificate\s+mismatch|invalid\s+certificate|"
            r"tls\s+downgrade|heartbleed|beast\s+attack)", re.IGNORECASE),
        "severity": "high", "type": "mitm", "mitre": "T1557",
        "category": "Network Attack"
    },
    {
        "name": "DNS Tunneling / Exfiltration",
        "pattern": re.compile(
            r"(dns\s+tunnel|unusually\s+long\s+dns|base64.*\.dns\.|"
            r"high\s+dns\s+query\s+rate|dns\s+exfil|"
            r"iodine|dnscat|DNSxD)", re.IGNORECASE),
        "severity": "high", "type": "dns_tunneling", "mitre": "T1048.003",
        "category": "Exfiltration"
    },
    {
        "name": "Lateral Movement / Pass-the-Hash",
        "pattern": re.compile(
            r"(pass.the.hash|pass.the.ticket|wmi\s+exec|psexec|"
            r"winrm\s+lateral|smbexec|atexec|dcomexec|"
            r"remote\s+registry.*modified|scheduled\s+task.*remote)",
            re.IGNORECASE),
        "severity": "critical", "type": "lateral_movement", "mitre": "T1550.002",
        "category": "Lateral Movement"
    },

    # ── MALWARE & EXECUTION ──────────────────────────────────
    {
        "name": "Ransomware Activity",
        "pattern": re.compile(
            r"(ransomware|\.encrypted|\.locked|\.enc$|\.crypto$|"
            r"your\s+files\s+are\s+encrypted|ransom\s+note|"
            r"bitcoin.*decrypt|pay.*recover.*files)", re.IGNORECASE),
        "severity": "critical", "type": "ransomware", "mitre": "T1486",
        "category": "Malware"
    },
    {
        "name": "Cryptominer / Coin Miner",
        "pattern": re.compile(
            r"(xmrig|stratum\+tcp|cryptonight|monero\s+miner|"
            r"coinhive|mining\s+pool|cpu\s+mining\s+detected|"
            r"cgminer|nicehash|ethminer)", re.IGNORECASE),
        "severity": "high", "type": "cryptominer", "mitre": "T1496",
        "category": "Malware"
    },
    {
        "name": "Malware Download / C2 Beacon",
        "pattern": re.compile(
            r"(\bdownloaded\s+.*\.(exe|dll|bin|scr|sh|elf|bat|ps1|vbs)\b|"
            r"c2\s+(beacon|callback)|command.*and.*control|"
            r"reverse\s+shell|backdoor\s+(installed|detected)|"
            r"trojan|rootkit|spyware)", re.IGNORECASE),
        "severity": "critical", "type": "malware_download", "mitre": "T1105",
        "category": "Malware"
    },
    {
        "name": "Fileless Malware / LOLBins",
        "pattern": re.compile(
            r"(powershell\s+-enc|-EncodedCommand|regsvr32.*scrobj|"
            r"mshta.*javascript|certutil.*-decode|"
            r"wscript.*eval|cmstp\s+-ns|rundll32.*shell32)", re.IGNORECASE),
        "severity": "critical", "type": "fileless_malware", "mitre": "T1059.001",
        "category": "Malware"
    },
    {
        "name": "Persistence Mechanism",
        "pattern": re.compile(
            r"(crontab\s+-e|/etc/cron\.|at\s+command|schtasks\s+/create|"
            r"HKLM.*Run.*added|startup\s+folder\s+modified|"
            r"systemd\s+service\s+created|rc\.local\s+modified|"
            r"bashrc\s+modified|profile\s+modified)", re.IGNORECASE),
        "severity": "high", "type": "persistence", "mitre": "T1053",
        "category": "Persistence"
    },

    # ── DATA EXFILTRATION ────────────────────────────────────
    {
        "name": "Data Exfiltration",
        "pattern": re.compile(
            r"(large\s+data\s+transfer\s+detected|unusually\s+large\s+upload|"
            r"sensitive\s+data.*sent|exfiltration\s+detected|"
            r"outbound.*\d{3,}\s*MB|data\s+leak|"
            r"bulk\s+download|megabytes.*external)", re.IGNORECASE),
        "severity": "critical", "type": "data_exfiltration", "mitre": "T1041",
        "category": "Exfiltration"
    },
    {
        "name": "Database Exfiltration / Dump",
        "pattern": re.compile(
            r"(mysqldump|pg_dump|mongodump|SELECT\s+\*\s+FROM\s+\w+\s+INTO\s+OUTFILE|"
            r"database.*dump\s+detected|LOAD\s+DATA\s+INFILE|"
            r"db\s+credentials\s+exposed)", re.IGNORECASE),
        "severity": "critical", "type": "db_exfiltration", "mitre": "T1005",
        "category": "Exfiltration"
    },

    # ── CLOUD / INFRASTRUCTURE ATTACKS ──────────────────────
    {
        "name": "Cloud Metadata Service Abuse (IMDS)",
        "pattern": re.compile(
            r"(169\.254\.169\.254|metadata\.google\.internal|"
            r"http://instance-data|http://169\.254|"
            r"IMDSv1\s+request|instance\s+metadata\s+access)", re.IGNORECASE),
        "severity": "critical", "type": "cloud_metadata_abuse", "mitre": "T1552.005",
        "category": "Cloud Attack"
    },
    {
        "name": "Kubernetes API Server Abuse",
        "pattern": re.compile(
            r"(kubectl\s+exec|kube-apiserver.*unauthorized|"
            r"ClusterRoleBinding.*created|ServiceAccount.*privilege|"
            r"kube\s+dashboard\s+exposed|etcd.*unauthenticated|"
            r"pod.*hostNetwork.*true)", re.IGNORECASE),
        "severity": "critical", "type": "k8s_api_abuse", "mitre": "T1610",
        "category": "Cloud Attack"
    },
    {
        "name": "IAM / Permissions Abuse",
        "pattern": re.compile(
            r"(iam.*policy.*attached|assume\s+role|sts\s+GetSessionToken|"
            r"unauthorized.*s3|unauthorized.*ec2|unauthorized.*iam|"
            r"privilege\s+escalation.*iam|admin\s+role.*assumed)",
            re.IGNORECASE),
        "severity": "high", "type": "iam_abuse", "mitre": "T1078.004",
        "category": "Cloud Attack"
    },
    {
        "name": "S3 Bucket / Cloud Storage Exposure",
        "pattern": re.compile(
            r"(s3.*public\s+access|bucket\s+policy.*public|"
            r"acl.*public-read|cloud\s+storage.*exposed|"
            r"blob.*public|gcs.*allUsers)", re.IGNORECASE),
        "severity": "high", "type": "cloud_storage_exposure", "mitre": "T1530",
        "category": "Cloud Attack"
    },

    # ── ENDPOINT / SYSTEM ATTACKS ────────────────────────────
    {
        "name": "Anomalous Process Execution",
        "pattern": re.compile(
            r"(unusual\s+process|unexpected\s+binary|"
            r"parent\s+process\s+mismatch|process\s+hollowing|"
            r"process\s+injection|CreateRemoteThread|"
            r"WriteProcessMemory|VirtualAllocEx)", re.IGNORECASE),
        "severity": "high", "type": "process_injection", "mitre": "T1055",
        "category": "Defense Evasion"
    },
    {
        "name": "Log Tampering / Anti-Forensics",
        "pattern": re.compile(
            r"(wevtutil\s+cl|ClearEvent|log\s+(cleared|wiped|deleted)|"
            r"/var/log.*removed|auditd\s+stopped|"
            r"shred\s+-u|secure-delete|history\s+-c)", re.IGNORECASE),
        "severity": "critical", "type": "log_tampering", "mitre": "T1070",
        "category": "Defense Evasion"
    },
    {
        "name": "Firewall / Security Control Disabled",
        "pattern": re.compile(
            r"(iptables\s+-F|ufw\s+disable|firewall\s+disabled|"
            r"Windows\s+Firewall\s+turned\s+off|netsh\s+advfirewall\s+set.*off|"
            r"setenforce\s+0|apparmor\s+disabled)", re.IGNORECASE),
        "severity": "critical", "type": "security_disabled", "mitre": "T1562",
        "category": "Defense Evasion"
    },

    # ── PROTOCOL / INFRASTRUCTURE-SPECIFIC ──────────────────
    {
        "name": "SSH Key / Authorized Keys Tampering",
        "pattern": re.compile(
            r"(authorized_keys\s+modified|\.ssh.*write|"
            r"ssh-keygen.*injected|sshd_config.*modified|"
            r"new\s+ssh\s+key\s+added|ssh\s+host\s+key\s+changed)",
            re.IGNORECASE),
        "severity": "high", "type": "ssh_tampering", "mitre": "T1098.004",
        "category": "Persistence"
    },
    {
        "name": "VPN / Tunneling Abuse",
        "pattern": re.compile(
            r"(vpn.*anomaly|openvpn.*suspicious|wireguard.*unauthorized|"
            r"split\s+tunnel\s+bypass|vpn\s+credential.*invalid|"
            r"unusual\s+vpn\s+geolocation)", re.IGNORECASE),
        "severity": "medium", "type": "vpn_abuse", "mitre": "T1133",
        "category": "Initial Access"
    },
    {
        "name": "Tor / Anonymous Proxy Detected",
        "pattern": re.compile(
            r"(tor\s+exit\s+node|onion\s+routing|proxy\s+chain|"
            r"anonymizer\s+detected|darknet\s+traffic|"
            r"i2p\s+traffic|tor\s+browser)", re.IGNORECASE),
        "severity": "medium", "type": "tor_proxy", "mitre": "T1090.003",
        "category": "Command and Control"
    },
    {
        "name": "Log4Shell / Known CVE Exploitation",
        "pattern": re.compile(
            r"(jndi:(ldap|rmi|dns|nis|iiop|corba|nds|http)://|"
            r"\$\{jndi:|log4shell|CVE-2021-44228|"
            r"CVE-2022-\d+.*exploit|CVE-2023-\d+.*exploit)",
            re.IGNORECASE),
        "severity": "critical", "type": "known_cve_exploit", "mitre": "T1190",
        "category": "Initial Access"
    },
    {
        "name": "Supply Chain / Third-Party Compromise",
        "pattern": re.compile(
            r"(supply\s+chain\s+attack|dependency\s+confusion|"
            r"typosquat\s+package|malicious\s+npm|malicious\s+pypi|"
            r"compromised\s+dependency|solarwinds|npm\s+audit.*critical)",
            re.IGNORECASE),
        "severity": "critical", "type": "supply_chain", "mitre": "T1195",
        "category": "Initial Access"
    },
    {
        "name": "API Abuse / Scraping",
        "pattern": re.compile(
            r"(rate\s+limit\s+exceeded|api\s+abuse\s+detected|"
            r"scraping\s+detected|bot\s+traffic|unusual\s+api\s+pattern|"
            r"\d{3,}\s+requests.*per\s+second|automated\s+scan)",
            re.IGNORECASE),
        "severity": "medium", "type": "api_abuse", "mitre": "T1190",
        "category": "Discovery"
    },
    {
        "name": "Zero-Day / Unknown Exploit Indicator",
        "pattern": re.compile(
            r"(zero.day|0.day|unknown\s+exploit|novel\s+attack\s+pattern|"
            r"unclassified\s+threat|new\s+malware\s+variant|"
            r"anomalous\s+payload|shellcode\s+detected)", re.IGNORECASE),
        "severity": "critical", "type": "zero_day", "mitre": "T1203",
        "category": "Initial Access"
    }
]


class ThreatDetector:
    """Unifies rule-based heuristics and ML models for comprehensive threat detection."""

    def __init__(self):
        self.anomaly_detector = AnomalyDetector()
        self.classifier = ThreatClassifier()

    def detect(self, features_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run detection engine across a batch of extracted features."""
        results = []

        # 1. Prepare numerical feature vectors for ML models
        X_numeric = []
        for row in features_list:
            X_numeric.append([
                row.get("message_length", 0),
                row.get("status_code", 0),
                row.get("bytes_sent", 0),
                row.get("cpu", 0.0),
                row.get("memory", 0.0),
                row.get("network_tx", 0.0),
                row.get("network_rx", 0.0)
            ])

        # 2. Run ML Models (will default to safe values if untrained)
        anomalies = self.anomaly_detector.predict(X_numeric)
        classifications = self.classifier.predict(X_numeric)
        confidences = self.classifier.predict_proba(X_numeric)

        # 3. Combine with Rule-based heuristics
        for i, row in enumerate(features_list):
            msg = row.get("raw_message", "")

            # Rule engine — check all signatures
            detected_signatures = []
            highest_severity = "low"
            mitre_tactics = set()

            for pattern in INDICATOR_PATTERNS:
                if pattern["pattern"].search(msg):
                    detected_signatures.append(pattern["name"])
                    mitre_tactics.add(pattern.get("mitre", ""))
                    sev = pattern["severity"]
                    if sev == "critical":
                        highest_severity = "critical"
                    elif sev == "high" and highest_severity not in ["critical"]:
                        highest_severity = "high"
                    elif sev == "medium" and highest_severity in ["low", "info"]:
                        highest_severity = "medium"

            is_threat = len(detected_signatures) > 0 or anomalies[i] == 1 or classifications[i] != "benign"

            if is_threat:
                confidence = 1.0 if detected_signatures else max(confidences[i], 0.6)
                results.append({
                    "timestamp": row.get("timestamp"),
                    "source_ip": row.get("source_ip"),
                    "threat_type": detected_signatures[0] if detected_signatures else classifications[i],
                    "category": INDICATOR_PATTERNS[
                        next((j for j, p in enumerate(INDICATOR_PATTERNS)
                              if detected_signatures and p["name"] == detected_signatures[0]),
                             0)
                    ].get("category", "Unknown") if detected_signatures else "ML Detected",
                    "severity": highest_severity if detected_signatures else "medium",
                    "confidence": round(confidence, 2),
                    "is_anomaly": bool(anomalies[i]),
                    "signatures": detected_signatures,
                    "mitre_tactics": list(mitre_tactics),
                    "raw_message": msg
                })

        return results
