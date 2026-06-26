import logging
import re
from typing import Any, Dict, List

from .models import AnomalyDetector, ThreatClassifier

logger = logging.getLogger(__name__)


INDICATOR_PATTERNS = [

    
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
        import hashlib
        results = []
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
        anomalies = self.anomaly_detector.predict(X_numeric)
        anomaly_scores = self.anomaly_detector.anomaly_scores(X_numeric)
        classifications = self.classifier.predict(X_numeric)
        confidences = self.classifier.predict_proba(X_numeric)
        for i, row in enumerate(features_list):
            msg = row.get("raw_message", "")
            matched_rules = []
            for pattern in INDICATOR_PATTERNS:
                if pattern["pattern"].search(msg):
                    matched_rules.append(pattern)

            if matched_rules:
                for pat_idx, pattern in enumerate(matched_rules):
                    lookup = pattern["name"]
                    details = THREAT_DETAILS.get(lookup, {})
                    cve_id = "CVE-2021-44228" if "log4shell" in lookup.lower() else ("CVE-2021-41773" if "traversal" in lookup.lower() else ("CVE-2021-23017" if "nginx" in lookup.lower() else "N/A"))
                    explanation = details.get("explanation", f"Local signature match for security rule '{pattern['name']}'.")
                    impact = details.get("impact", "Potential security exposure of service resources.")
                    mitigation = details.get("mitigation", "Review access logs, block sender IP, and check system configurations.")
                    sev = pattern["severity"]
                    base = {"critical": 0.92, "high": 0.84, "medium": 0.73, "low": 0.62}.get(sev, 0.70)

                    
                    anom = anomaly_scores[i]      
                    clf_conf = confidences[i]     
                    seed = hashlib.md5(f"{msg}:{pattern['name']}:{pat_idx}".encode()).hexdigest()
                    jitter = (int(seed[:8], 16) % 1500) / 10000.0 - 0.075   
                    raw_conf = 0.70 * base + 0.15 * anom + 0.15 * clf_conf + jitter
                    confidence = round(min(0.97, max(0.58, raw_conf)), 3)

                    results.append({
                        "timestamp": row.get("timestamp"),
                        "source_ip": row.get("source_ip"),
                        "threat_type": pattern["name"],
                        "category": pattern.get("category", "Unknown"),
                        "severity": pattern["severity"],
                        "confidence": confidence,
                        "is_anomaly": bool(anomalies[i]),
                        "signatures": [pattern["name"]],
                        "mitre_tactics": [pattern.get("mitre", "")],
                        "raw_message": msg,
                        "cve_id": cve_id,
                        "explanation": explanation,
                        "impact": impact,
                        "mitigation": mitigation
                    })
            else:
               
                is_ml_threat = anomalies[i] == 1 or classifications[i] != "benign"
                if is_ml_threat:
                   
                    ml_conf = confidences[i]
                    anom_boost = anomaly_scores[i] * 0.15
                    confidence = round(min(0.95, max(0.45, ml_conf + anom_boost)), 3)
                    threat_type = classifications[i] if classifications[i] != "benign" else "Anomaly"
                    results.append({
                        "timestamp": row.get("timestamp"),
                        "source_ip": row.get("source_ip"),
                        "threat_type": threat_type,
                        "category": "ML Detected",
                        "severity": "high" if anomalies[i] == 1 else "medium",
                        "confidence": confidence,
                        "is_anomaly": bool(anomalies[i]),
                        "signatures": [],
                        "mitre_tactics": ["T1005" if anomalies[i] == 1 else "T1059"],
                        "raw_message": msg,
                        "cve_id": "N/A",
                        "explanation": f"Machine learning anomaly detector flagged unusual activity matching '{threat_type}'.",
                        "impact": "Potential compromise of system resources or unauthorized access.",
                        "mitigation": "Examine resource metrics, check running processes, and trace process networks."
                    })

        return results

    def local_analyze_alert(self, threat_type: str, severity: str, raw_message: str) -> str:
        """Local analysis helper that generates a professional security analysis of a threat."""
        lookup = threat_type.strip()
        details = THREAT_DETAILS.get(lookup)
        
        if not details:
            category = "Unknown"
            for pattern in INDICATOR_PATTERNS:
                if pattern["name"].lower() == lookup.lower():
                    category = pattern.get("category", "Unknown")
                    break
            details = CATEGORY_DETAILS.get(category, {
                "explanation": f"Security anomaly categorized as '{threat_type}' was detected.",
                "impact": "Potential security exposure or service degradation.",
                "mitigation": "Examine relevant application logs, restrict access to the affected asset, and scan for vulnerability patches."
            })

        return f"{details['explanation']} Potential Impact: {details['impact']} Recommended Mitigation: {details['mitigation']}"

    def local_analyze_log(self, log_text: str) -> Dict[str, Any]:
        """Local analysis helper that calculates threat probability and returns a reason for a manual log scan."""
        lines = [line.strip() for line in log_text.splitlines() if line.strip()]
        if not lines:
            lines = [log_text]
            
        from .feature_engineering import extract_features
        features_list = [extract_features(line) for line in lines]
        detections = self.detect(features_list)
        
        if detections:
           
            highest_conf_det = max(detections, key=lambda d: d["confidence"])
            prob = int(highest_conf_det["confidence"] * 100)
            
            unique_threats = list(set(d["threat_type"] for d in detections))
            if len(unique_threats) == 1:
                reason = f"Security threat '{unique_threats[0]}' detected in logs."
            else:
                reason = f"Multiple security threats detected: {', '.join(unique_threats)}."
            return {"probability": prob, "reason": reason}
            
        
        X_numeric = []
        for features in features_list:
            X_numeric.append([
                features.get("message_length", 0),
                features.get("status_code", 0),
                features.get("bytes_sent", 0),
                features.get("cpu", 0.0),
                features.get("memory", 0.0),
                features.get("network_tx", 0.0),
                features.get("network_rx", 0.0)
            ])
            
        anomalies = self.anomaly_detector.predict(X_numeric)
        if any(a == 1 for a in anomalies):
            return {
                "probability": 70,
                "reason": "Anomalous patterns flagged in request metadata (unusual sizes or resource utilization spikes)."
            }
            
        return {
            "probability": 15,
            "reason": "No anomalous activity or known security threat signatures detected."
        }



THREAT_DETAILS = {
    "SQL Injection": {
        "explanation": "Detected SQL injection signatures attempting to manipulate database queries.",
        "impact": "Potential exposure of sensitive database content, authentication bypass, or complete database modification.",
        "mitigation": "Use prepared statements/parameterized queries and apply strict input sanitization on all parameters."
    },
    "Cross-Site Scripting (XSS)": {
        "explanation": "Malicious javascript injection detected in query fields or request headers.",
        "impact": "Execution of arbitrary client-side scripts, session hijacking, or credential theft of users.",
        "mitigation": "Implement proper context-aware output encoding and configure a strict Content Security Policy (CSP)."
    },
    "Directory / Path Traversal": {
        "explanation": "Attempt to access files outside the web root directory via traversal sequences.",
        "impact": "Disclosure of sensitive system files such as /etc/passwd or configuration files.",
        "mitigation": "Sanitize file path inputs, use path normalization checks, and run services with low-privilege accounts."
    },
    "Command Injection / RCE": {
        "explanation": "Arbitrary system shell command execution signature matched in query arguments.",
        "impact": "Complete system compromise, shell execution, or server takeover by an attacker.",
        "mitigation": "Avoid passing user input directly to system command shells; use safe APIs and disable execution privileges."
    },
    "SSRF": {
        "explanation": "Server-Side Request Forgery attempt to query internal network metadata or endpoints.",
        "impact": "Access to restricted internal endpoints, cloud metadata API exploitation, or internal port scanning.",
        "mitigation": "Restrict outgoing HTTP requests from the server to whitelisted domains; disable unused protocol handlers."
    },
    "XXE Injection": {
        "explanation": "XML External Entity reference detected in XML input body.",
        "impact": "Server-side request forgery, local file disclosure, or denial of service.",
        "mitigation": "Disable external entity resolution (DTD) in your XML parser configuration."
    },
    "SSTI": {
        "explanation": "Server-Side Template Injection expression detected in web request parameters.",
        "impact": "Execution of arbitrary code on the web server within the template engine context.",
        "mitigation": "Avoid dynamic template generation from user inputs; sanitize inputs and sandbox the template environment."
    },
    "Insecure Deserialization": {
        "explanation": "Insecure object deserialization signature matched in request body.",
        "impact": "Remote code execution, privilege escalation, or arbitrary file access.",
        "mitigation": "Avoid deserializing untrusted user inputs; use safe serialization formats like JSON or Protocol Buffers."
    },
    "HTTP Request Smuggling": {
        "explanation": "Mismatched Content-Length and Transfer-Encoding headers indicating request smuggling.",
        "impact": "Bypassing security controls, cache poisoning, or session hijacking of other users.",
        "mitigation": "Ensure frontend and backend servers use consistent HTTP parsing rules; disable HTTP/1.1 pipelining."
    },
    "Brute-Force Authentication": {
        "explanation": "Multiple failed authentication attempts detected from the same source IP.",
        "impact": "Unauthorized account access and credential compromise.",
        "mitigation": "Implement rate limiting, account lockout policies, and enforce multi-factor authentication (MFA)."
    },
    "Password Spraying": {
        "explanation": "Multiple login failures across different accounts from a single source IP.",
        "impact": "Widespread credential compromise across weak accounts.",
        "mitigation": "Monitor login patterns, enforce strong unique passwords, and alert on multi-account login failures."
    },
    "Credential Dumping": {
        "explanation": "lsass.exe memory access or password dumping utility execution detected.",
        "impact": "Compromise of Windows domain or local administrator credentials.",
        "mitigation": "Enable LSA protection, restrict administrative privileges, and deploy Endpoint Detection and Response (EDR)."
    },
    "Credential Exposure in Logs": {
        "explanation": "Plaintext passwords or secrets detected in web server or application logs.",
        "impact": "Exposure of credentials to log administrators or unauthorized actors with log access.",
        "mitigation": "Configure log scrubbers to redact sensitive fields (like 'password', 'token') before writing to logs."
    },
    "OAuth / JWT Token Theft": {
        "explanation": "OAuth or JWT token reuse/misuse signature detected.",
        "impact": "Session hijacking and unauthorized API access acting as the victim user.",
        "mitigation": "Implement token validation, enforce short lifetimes for access tokens, and use secure HTTPOnly cookies."
    },
    "Privilege Escalation (sudo)": {
        "explanation": "Unauthorized sudo execution or privilege escalation attempt detected.",
        "impact": "Low-privilege user gaining administrative root access on the host system.",
        "mitigation": "Configure secure sudoers rules, audit command executions, and keep system packages updated."
    },
    "Container Escape": {
        "explanation": "Access to host resources or container escape signatures detected.",
        "impact": "Attacker breakout from container to host system, compromising host infrastructure.",
        "mitigation": "Do not mount docker.sock in containers, run containers as non-root, and use secure container runtimes."
    },
    "Kernel Exploit Attempt": {
        "explanation": "Execution of system calls or exploit payloads targeting known kernel vulnerabilities.",
        "impact": "Complete system takeover with root/kernel-level privileges.",
        "mitigation": "Keep the operating system kernel patched and restrict access to dangerous system calls."
    },
    "Port Scanning / Recon": {
        "explanation": "High volume of network probes or port scans detected from an external IP.",
        "impact": "Discovery of open network services and potential vulnerabilities by adversaries.",
        "mitigation": "Configure firewalls to block scanning IPs and disable unused services."
    },
    "DDoS / Volumetric Attack": {
        "explanation": "Volumetric traffic spike or SYN flood pattern detected.",
        "impact": "Denial of service making the application unavailable to legitimate users.",
        "mitigation": "Deploy volumetric DDoS protection (e.g. Cloudflare) and configure rate limiters at firewall level."
    },
    "Man-in-the-Middle (MitM)": {
        "explanation": "ARP spoofing or SSL stripping signatures detected on the local subnet.",
        "impact": "Eavesdropping, traffic interception, or theft of sensitive credentials in transit.",
        "mitigation": "Enforce HTTPS everywhere, enable HSTS, and implement dynamic ARP inspection (DAI) on switches."
    },
    "DNS Tunneling / Exfiltration": {
        "explanation": "Unusually long or base64-encoded DNS subdomains indicating DNS tunneling.",
        "impact": "Bypass of firewall rules for data exfiltration or Command and Control (C2) communications.",
        "mitigation": "Configure DNS firewalls to detect and block anomalous query rates or patterns; inspect DNS payload sizes."
    },
    "Lateral Movement / PtH": {
        "explanation": "Pass-the-hash or remote SMB administrative connections detected.",
        "impact": "Attacker movement from one compromised system to another within the internal network.",
        "mitigation": "Disable legacy SMB protocols, restrict administrative shares, and monitor lateral authentication traffic."
    },
    "Ransomware Activity": {
        "explanation": "Rapid file modification or mass encryption signatures detected.",
        "impact": "Complete loss of files and operational disruption due to encryption of critical assets.",
        "mitigation": "Configure file integrity monitoring, enforce strict write permissions, and implement automated backups."
    },
    "Cryptominer / Coin Miner": {
        "explanation": "xmrig process execution or connection to stratum mining pools detected.",
        "impact": "Severe CPU/resource exhaustion and increased infrastructure costs.",
        "mitigation": "Block egress connections to mining pools and monitor running processes for unauthorized miners."
    },
    "Malware Download / C2 Beacon": {
        "explanation": "Reverse shell callbacks or download of suspicious payloads detected.",
        "impact": "Establishment of Command and Control (C2) channels and subsequent server exploitation.",
        "mitigation": "Implement strict egress firewall rules, deploy network-based intrusion detection, and block C2 domains."
    },
    "Fileless Malware / LOLBins": {
        "explanation": "Abuse of built-in system tools (like powershell -EncodedCommand, certutil) to download or run payloads.",
        "impact": "Evasion of traditional antivirus detection and execution of arbitrary malicious scripts in memory.",
        "mitigation": "Enable PowerShell transcription logging, constrain PowerShell language modes, and restrict LOLBin execution."
    },
    "Persistence Mechanism": {
        "explanation": "Creation of unauthorized systemd services, cron jobs, or registry keys.",
        "impact": "Attacker maintains access to the system even after restarts or service cleanups.",
        "mitigation": "Audit startup services and cron directories regularly; implement host integrity verification."
    },
    "Data Exfiltration": {
        "explanation": "High-volume data transfer to external IPs or cloud storages.",
        "impact": "Theft of corporate intellectual property, personal user data, or database backups.",
        "mitigation": "Enforce strict egress data limits and monitor for massive file transfers to external endpoints."
    },
    "Database Exfiltration / Dump": {
        "explanation": "Execution of database dump utility or bulk data query commands.",
        "impact": "Exfiltration of the entire application database.",
        "mitigation": "Restrict database backup command permissions and log all bulk data query requests."
    },
    "Cloud Metadata Abuse (IMDS)": {
        "explanation": "Unauthorized containment calls to cloud metadata service IP 169.254.169.254.",
        "impact": "Theft of temporary cloud IAM credentials resulting in cloud resource takeover.",
        "mitigation": "Configure IMDSv2 with session tokens and restrict container network egress to the metadata IP."
    },
    "Kubernetes API Server Abuse": {
        "explanation": "Unauthorized API calls or exec requests to the K8s API server.",
        "impact": "Cluster compromise, privilege escalation, or cluster-wide takeover.",
        "mitigation": "Enable RBAC, restrict API server access to specific namespaces, and audit Kubernetes API access logs."
    },
    "IAM / Permissions Abuse": {
        "explanation": "STS GetSessionToken or unauthorized policy modification attempts.",
        "impact": "Privilege escalation inside cloud accounts, exposing critical cloud services.",
        "mitigation": "Enforce least-privilege IAM policies and audit STS generation requests."
    },
    "S3 / Cloud Storage Exposure": {
        "explanation": "Modification of storage bucket policy to allow public access.",
        "impact": "Public exposure of sensitive objects or internal backups hosted in cloud storage.",
        "mitigation": "Enforce 'Block Public Access' at the cloud account level and audit storage bucket policies."
    },
    "Anomalous Process Execution": {
        "explanation": "Process injection or creation of unexpected parent-child process chains.",
        "impact": "Defense evasion and execution of malicious code inside legitimate system processes.",
        "mitigation": "Deploy endpoint security agents to block process injections and monitor process parentage."
    },
    "Log Tampering / Anti-Forensics": {
        "explanation": "Clearing of security event logs or disabling of logging services.",
        "impact": "Erasure of attacker footprints, hindering incident response and forensics investigations.",
        "mitigation": "Forward logs in real-time to a secure, write-once-read-many (WORM) centralized log management server."
    },
    "Firewall / Security Disabled": {
        "explanation": "Flushing of iptables rules or disabling of system firewalls.",
        "impact": "Exposure of internal network services to external network scanning and direct attacks.",
        "mitigation": "Lock down firewall administration privileges and alert on any security service state changes."
    },
    "SSH Key Tampering": {
        "explanation": "Modification of authorized_keys file by non-administrative users.",
        "impact": "Attacker registers their public key to maintain SSH access to the server.",
        "mitigation": "Implement file integrity monitoring on ~/.ssh directory and restrict write permissions to owner only."
    },
    "VPN / Tunneling Abuse": {
        "explanation": "Unauthorized creation of VPN tunnels or SSH forwards.",
        "impact": "Establishment of persistent backdoor bypass routes through firewalls.",
        "mitigation": "Monitor and restrict outgoing tunnel connections; restrict SSH tunneling features in sshd_config."
    },
    "Tor / Anonymous Proxy": {
        "explanation": "Connections to known Tor exit nodes or proxy networks.",
        "impact": "Anonymized Command and Control (C2) communications or untraceable system scans.",
        "mitigation": "Block egress and ingress connections to known Tor exit node IP lists."
    },
    "Log4Shell / Known CVE Exploit": {
        "explanation": "JNDI lookup patterns matching Log4Shell CVE-2021-44228 exploit attempt.",
        "impact": "Remote code execution with full server privileges.",
        "mitigation": "Upgrade Log4j packages to the latest patched version and sanitize HTTP headers."
    },
    "Supply Chain / Third-Party": {
        "explanation": "Dependency confusion or malicious package installation detected.",
        "impact": "Execution of compromised third-party packages resulting in backdoors or credential theft.",
        "mitigation": "Use private package registries, pin dependency hashes, and scan packages before builds."
    },
    "API Abuse / Scraping": {
        "explanation": "Unusual rate limit exceeded or automated scanning signatures detected.",
        "impact": "API exhaustion, service slowdowns, or automated scraping of application data.",
        "mitigation": "Implement strict rate limiters per client IP and deploy CAPTCHAs for bot protection."
    },
    "Zero-Day / Unknown Exploit": {
        "explanation": "Novel or unclassified anomalous patterns detected in logs.",
        "impact": "Foothold or exploitation via zero-day vulnerabilities.",
        "mitigation": "Keep all packages updated and deploy proactive machine-learning anomaly detection."
    }
}

CATEGORY_DETAILS = {
    "Web Application Attack": {
        "explanation": "Web-based exploit payload matched against signature library.",
        "impact": "Unauthorised database access, service manipulation, or information disclosure.",
        "mitigation": "Deploy Web Application Firewall (WAF) and sanitize all inputs."
    },
    "Remote Code Execution": {
        "explanation": "Remote command execution signature matched.",
        "impact": "Full system compromise and unauthorized host control.",
        "mitigation": "Apply patches immediately and restrict process privileges."
    },
    "Authentication Attack": {
        "explanation": "Unusual login failures or brute-force pattern detected.",
        "impact": "Unauthorised access to user or administrator accounts.",
        "mitigation": "Implement rate limiting, account lockout policies, and enforce multi-factor authentication (MFA)."
    },
    "Credential Access": {
        "explanation": "Credential dumping or exposure signature matched.",
        "impact": "Compromise of system or administrative credentials.",
        "mitigation": "Enforce strong password policies and restrict access to credentials storage."
    },
    "Privilege Escalation": {
        "explanation": "Attempted container escape, sudo escalation, or kernel exploit.",
        "impact": "Elevated user permissions up to root/administrator level.",
        "mitigation": "Patch kernel vulnerabilities and secure container configurations."
    },
    "Network Attack": {
        "explanation": "SYN flood, DDoS patterns, or port scanning detected.",
        "impact": "Denial of service or internal asset discovery by external actors.",
        "mitigation": "Enable rate limiting, block scanner IPs, and configure firewalls."
    },
    "Malware": {
        "explanation": "Ransomware encryption, coinminer connection, or C2 beacon signature matched.",
        "impact": "Data encryption, resource hijacking, or malicious remote control.",
        "mitigation": "Isolate affected hosts, terminate malicious processes, and restore from backups."
    },
    "Exfiltration": {
        "explanation": "High-volume outbound data transfer or database dumping detected.",
        "impact": "Loss of sensitive corporate data or customer records.",
        "mitigation": "Configure egress network filtering and monitor database dump commands."
    },
    "Cloud Attack": {
        "explanation": "IMDS metadata abuse or kubernetes API server misuse detected.",
        "impact": "Compromise of cloud IAM credentials or cluster takeover.",
        "mitigation": "Restrict access to cloud metadata services and enforce least-privilege IAM."
    },
    "Defense Evasion": {
        "explanation": "Attempted clearing of security logs or disabling firewall rules.",
        "impact": "Loss of audit trails or exposure of network services.",
        "mitigation": "Centralize logging to secure remote repositories and lock down firewall configs."
    },
    "Initial Access": {
        "explanation": "Log4Shell, known CVE, or zero-day exploit pattern detected.",
        "impact": "Initial foothold established in the enterprise network.",
        "mitigation": "Update vulnerable packages and implement vulnerability scanning."
    },
    "Discovery": {
        "explanation": "Automated API scraping or scanning activity detected.",
        "impact": "Mapping of system endpoints and data harvesting.",
        "mitigation": "Implement request rate-limiting and challenge automated bots."
    }
}
