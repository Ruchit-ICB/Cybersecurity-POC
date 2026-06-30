import logging
import re
import hashlib
from typing import Any, Dict, List
from datetime import datetime, timedelta, timezone

from .models import AnomalyDetector, ThreatClassifier

logger = logging.getLogger(__name__)

# Operational indicators (latency, packet loss, etc.) - should NOT be considered threats without other evidence
OPERATIONAL_PATTERNS = [
    re.compile(r"(latency_ms|packet_loss|jitter|congestion|degraded\s+performance|connection\s+unstable|rtt_ms|dropped_packets|high\s+latency|routing\s+changes|retransmissions|service\s+degradation|response_time_ms)", re.IGNORECASE),
]

# Define the direct indicators per threat type for correlation logic
DIRECT_INDICATORS = {
    # Exclusive signals: repeated failures against a SINGLE account / service
    # (no multi-account targeting, no IDS stuffing signature)
    "Brute-Force Authentication": [
        "failed password", "invalid login", "failed login", "login_failed", "failed ssh login",
        "ssh login attempts", "failed login attempt", "invalid password",
        "authentication failure", "max auth attempts", "too many failed",
        "credential validation failed",
        "Brute-force threshold exceeded", "Signature=SSH_Brute_Force"
    ],
    # Exclusive signals: confirmed IDS signature or explicit multi-account targeting from one IP
    "Credential Stuffing": [
        "signature=CREDENTIAL_STUFFING", "credential stuffing", "credential_stuffing",
    ],
    # Exclusive signals: multi-account lockout / spray language — but NOT when stuffing sig present
    "Password Spraying": [
        "multiple accounts failed", "accounts locked", "password spraying detected",
        "account_lockouts"
    ],
    "DDoS / Volumetric Attack": [
        "syn flood", "udp flood", "connection limit reached", "volumetric attack", "ddos detected",
        "saturating backbone", "http flood", "icmp flood", "packets/second"
    ],
    "Amplification Attack": [
        "DNS reflection", "NTP monlist", "amplification factor"
    ],
    "Port Scanning / Reconnaissance": [
        "nmap", "masscan", "port scanned", "AXFR", "SNMP brute force",
        "service enumeration", "probing multiple ports", "probing.*ports",
        "SNMP community string", "TCP_PORT_SCAN", "PORT_SCAN", "unique_ports", "inbound_connections"
    ],
    "Exploit Attempt": [
        # Active exploitation signals ONLY — passive CVE references belong in VulnerabilityAssessment
        "exploit attempt", "exploit confirmed", "exploit success",
        "signature=EXPLOIT", "exploitation detected",
        "privilege escalation", "pkexec", "dirtycow",
        "malicious payload", "command execution confirmed",
        "remote code execution", "rce confirmed", "rce detected",
        "shell spawned", "reverse shell", "payload delivered",
        "jndi:ldap://", "jndi:rmi://", "jndi:dns://",
        "abnormal process creation",
    ],
    "Network Reconnaissance": [
        "masscan.*subnet", "network recon", "targeting ISP subnet",
        "probing.*multiple.*ports", "service enumeration"
    ],
    "DNS Tunneling / Exfiltration": [
        "dns tunnel", "base64.*subdomain", "unusually long dns", "iodine", "dnscat",
        "base64 encoded payload in subdomain"
    ],
    "DNS Cache Poisoning": [
        "DNS cache poisoning", "spoofed DNS response", "DNS rebinding"
    ],
    "C2 Beacon / Command & Control": [
        "c2 beacon", "reverse shell", "backdoor installed", "Mirai botnet", "Emotet C2",
        "tor exit node"
    ],
    "Cryptominer / Coin Miner": [
        "xmrig", "stratum+tcp", "cryptonight", "monero miner",
        "nicehash", "cpu mining detected", "mining pool", "cgminer", "ethminer",
    ],
    "Malware Distribution": [
        "malware distribution", "serving payload", "Worm propagation", "EternalBlue", "WannaCry"
    ],
    "Ransomware Activity": [
        "ransomware", ".encrypted", ".locked", "your files are encrypted"
    ],
    "Fileless Malware / LOLBins": [
        "powershell -enc", "-EncodedCommand", "certutil -decode", "LOLBin abuse"
    ],
    "Data Exfiltration": [
        "exfiltration detected", "large data transfer", "outbound.*MB", "bulk download", "ICMP tunneling",
        "large file transfer", "GB upload", "potential exfiltration", "10GB upload", "steganography"
    ],
    "Database Exfiltration / Dump": [
        "mysqldump", "pg_dump", "mongodump", "database dump detected"
    ],
    "Credential Dumping": [
        "lsass.exe.*dump", "procdump.*lsass", "mimikatz", "hashdump", "pwdump",
        "lsass.exe memory access", "credential dumping detected"
    ],
    "Credential Exposure in Logs": [
        "password=", "passwd=", "api[-_]?key=", "api_key=", "secret[-_]?token=",
        "aws_access_key", "authorization: bearer",
    ],
    "BGP Hijacking": [
        "BGP hijacking", "suspicious route announcement", "prefix hijack"
    ],
    "Man-in-the-Middle (MitM)": [
        "arp poison", "arp spoof", "ssl strip", "certificate mismatch"
    ],
    "Router Compromise": [
        "router compromise", "unauthorized configuration change", "edge router"
    ],
    "Lateral Movement / Pass-the-Hash": [
        "pass-the-hash", "pass-the-ticket", "psexec", "smbexec"
    ],
    "Spam Campaign": [
        "spam campaign", "spam botnet", "sending.*emails.*hour"
    ],
    "Proxy Abuse": [
        "open proxy", "proxy abuse"
    ],
    "VoIP Fraud": [
        "VoIP fraud", "SIP trunk abuse", "international toll fraud"
    ],
    "TDoS Attack": [
        "TDoS", "Telephony Denial of Service", "calls.*minute.*PBX"
    ],
    "IoT Botnet": [
        "IoT botnet", "Mirai infection", "default credentials",
        "unauthorized access.*IoT hub", "IoT hub"
    ],
    "CCTV Camera Compromise": [
        "CCTV camera compromise", "accessing camera feed"
    ],
    "Phishing Kit": [
        "phishing kit", "credential harvesting", "mimicking bank login", "hosting credential harvesting page"
    ],
    "Port Forwarding Abuse": [
        "port forwarding abuse", "exposing internal services", "UPnP"
    ],
    "Copyright Infringement": [
        "copyright infringement", "DMCA violation", "torrent traffic", "bittorrent",
        "bittorrent handshake", "tracker connection"
    ],
    "Account Sharing": [
        "account sharing", "multiple simultaneous logins", "different IPs.*same.*account"
    ],
    "SIP Registration Attack": [
        "SIP registration attack", "brute-force SIP credentials"
    ],
    "Eavesdropping": [
        "eavesdropping", "SIP INVITE", "call interception"
    ],
    "Smart Home Abuse": [
        "smart home abuse", "unauthorized access.*IoT hub", "IoT hub"
    ],
    "Tor / Anonymous Proxy Detected": [
        "tor exit node", "onion routing", "anonymizer", "anonymizer in use", "darknet traffic"
    ],
    "Smart Meter Tampering": [
        "smart meter tampering", "unusual power consumption"
    ],
    "DNS Water Torture / NXDOMAIN Flood": [
        "DNS water torture", "random subdomain flooding", "NXDOMAIN flood", "NXDOMAIN"
    ],
}


INDICATOR_PATTERNS = [
    # ── NETWORK SCANNING & RECONNAISSANCE ─────────────────────
    {
        "name": "Port Scanning / Reconnaissance",
        "pattern": re.compile(
            r"(nmap|masscan|zmap|SYN\s+scan|port\s+sweep|"
            r"\d+\s+port(s)?\s+scanned|OS\s+detection|service\s+detection|"
            r"Nessus|OpenVAS|nikto|service\s+enumeration|"
            r"DNS\s+zone\s+transfer|AXFR|SNMP\s+brute\s+force|"
            r"SNMP\s+community\s+string\s+brute\s+force|"
            r"TCP_PORT_SCAN|PORT_SCAN|unique_ports=\d+|inbound_connections=\d+)", re.IGNORECASE),
        "severity": "medium", "type": "reconnaissance", "mitre": "T1046",
        "category": "Network Reconnaissance"
    },
    {
        "name": "Network Reconnaissance",
        "pattern": re.compile(
            r"(masscan.*subnet|network\s+recon|targeting\s+ISP\s+subnet|"
            r"probing.*multiple\s+ports|service\s+enumeration)", re.IGNORECASE),
        "severity": "high", "type": "network_recon", "mitre": "T1018",
        "category": "Network Reconnaissance"
    },

    # ── DDoS ATTACKS ──────────────────────────────────────────
    {
        "name": "DDoS / Volumetric Attack",
        "pattern": re.compile(
            r"(syn\s+flood|udp\s+flood|http[\s_]flood|amplification\s+attack|"
            r"ddos[\s_]detected|botnet\s+traffic|high\s+pps|packet\s+storm|"
            r"connection[\s_]limit[\s_]reached|rate[\s_]limit[\s_](exceeded|triggered)|"
            r"volumetric\s+attack|ICMP\s+flood|saturating\s+backbone|"
            r"HTTP_FLOOD_ATTACK|SYN_FLOOD|UDP_FLOOD|DDOS_ATTACK|"
            r"inbound_requests_per_sec=[5-9]\d{4,}|inbound_requests_per_sec=\d{6,}|"
            r"bandwidth_utilization=9[0-9]%|"
            r"signature=HTTP_FLOOD|signature=SYN_FLOOD|signature=UDP_FLOOD|"
            r"signature=DDOS|signature=VOLUMETRIC)", re.IGNORECASE),
        "severity": "critical", "type": "ddos", "mitre": "T1498",
        "category": "DDoS Attack"
    },
    {
        "name": "Amplification Attack",
        "pattern": re.compile(
            r"(DNS\s+reflection|NTP\s+monlist|amplification\s+factor|"
            r"UDP\s+amplification|reflection\s+attack)", re.IGNORECASE),
        "severity": "critical", "type": "amplification", "mitre": "T1498",
        "category": "DDoS Attack"
    },

    # ── DNS ATTACKS ───────────────────────────────────────────
    {
        "name": "DNS Tunneling / Exfiltration",
        "pattern": re.compile(
            r"(dns\s+tunnel|unusually\s+long\s+dns|base64.*\.dns\.|"
            r"high\s+dns\s+query\s+rate|dns\s+exfil|"
            r"iodine|dnscat|DNSxD)", re.IGNORECASE),
        "severity": "high", "type": "dns_tunneling", "mitre": "T1048.003",
        "category": "DNS Attack"
    },
    {
        "name": "DNS Cache Poisoning",
        "pattern": re.compile(
            r"(DNS\s+cache\s+poisoning|spoofed\s+DNS\s+response|"
            r"DNS\s+rebinding|malicious\s+DNS\s+server)", re.IGNORECASE),
        "severity": "critical", "type": "dns_poisoning", "mitre": "T1055",
        "category": "DNS Attack"
    },
    {
        "name": "DNS Water Torture / NXDOMAIN Flood",
        "pattern": re.compile(
            r"(DNS\s+water\s+torture|random\s+subdomain\s+flooding|"
            r"NXDOMAIN\s+flood|high\s+query\s+rate.*non-existent)", re.IGNORECASE),
        "severity": "high", "type": "dns_flood", "mitre": "T1498",
        "category": "DNS Attack"
    },

    # ── BOTNET & C2 TRAFFIC ───────────────────────────────────
    {
        "name": "C2 Beacon / Command & Control",
        "pattern": re.compile(
            r"(c2\s+(beacon|callback)|command.*and.*control|"
            r"reverse\s+shell|backdoor\s+(installed|detected)|"
            r"botnet\s+activity|Mirai\s+botnet|Emotet\s+C2)", re.IGNORECASE),
        "severity": "critical", "type": "c2_beacon", "mitre": "T1102",
        "category": "Botnet Activity"
    },
    {
        "name": "Tor / Anonymous Proxy Detected",
        "pattern": re.compile(
            r"(tor\s+exit\s+node|onion\s+routing|proxy\s+chain|"
            r"anonymizer\s+detected|darknet\s+traffic|"
            r"i2p\s+traffic|tor\s+browser)", re.IGNORECASE),
        "severity": "high", "type": "tor_proxy", "mitre": "T1090.003",
        "category": "Botnet Activity"
    },
    {
        "name": "Cryptominer / Coin Miner",
        "pattern": re.compile(
            r"(xmrig|stratum\+tcp|cryptonight|monero\s+miner|"
            r"coinhive|mining\s+pool|cpu\s+mining\s+detected|"
            r"cgminer|nicehash|ethminer)", re.IGNORECASE),
        "severity": "critical", "type": "cryptominer", "mitre": "T1496",
        "category": "Botnet Activity"
    },

    # ── MALWARE DISTRIBUTION ─────────────────────────────────
    {
        "name": "Malware Distribution",
        "pattern": re.compile(
            r"(malware\s+distribution|serving\s+payload|Emotet\s+payload|"
            r"Worm\s+propagation|EternalBlue|WannaCry)", re.IGNORECASE),
        "severity": "critical", "type": "malware_dist", "mitre": "T1105",
        "category": "Malware"
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
        "name": "Fileless Malware / LOLBins",
        "pattern": re.compile(
            r"(powershell\s+-enc|-EncodedCommand|regsvr32.*scrobj|"
            r"mshta.*javascript|certutil.*-decode|"
            r"wscript.*eval|cmstp\s+-ns|rundll32.*shell32|LOLBin\s+abuse)", re.IGNORECASE),
        "severity": "high", "type": "fileless_malware", "mitre": "T1059.001",
        "category": "Malware"
    },

    # ── DATA EXFILTRATION ─────────────────────────────────────
    {
        "name": "Data Exfiltration",
        "pattern": re.compile(
            r"(large\s+data\s+transfer\s+detected|unusually\s+large\s+upload|"
            r"sensitive\s+data.*sent|exfiltration\s+detected|"
            r"outbound.*\d{3,}\s*MB|data\s+leak|"
            r"bulk\s+download|megabytes.*external|"
            r"covert\s+channel|ICMP\s+tunneling|steganography|"
            r"large\s+file\s+transfer|GB\s+upload.*cloud\s+storage|potential\s+exfiltration)", re.IGNORECASE),
        "severity": "critical", "type": "data_exfiltration", "mitre": "T1041",
        "category": "Data Exfiltration"
    },
    {
        "name": "Database Exfiltration / Dump",
        "pattern": re.compile(
            r"(mysqldump|pg_dump|mongodump|SELECT\s+\*\s+FROM\s+\w+\s+INTO\s+OUTFILE|"
            r"database.*dump\s+detected|LOAD\s+DATA\s+INFILE|"
            r"db\s+credentials\s+exposed)", re.IGNORECASE),
        "severity": "critical", "type": "db_exfiltration", "mitre": "T1005",
        "category": "Data Exfiltration"
    },

    # ── PHISHING & CREDENTIAL THEFT ───────────────────────────
    {
        "name": "Phishing Kit",
        "pattern": re.compile(
            r"(phishing\s+kit|credential\s+harvesting|mimicking\s+bank\s+login|"
            r"fake\s+login\s+page)", re.IGNORECASE),
        "severity": "high", "type": "phishing", "mitre": "T1566",
        "category": "Phishing & Credential Theft"
    },
    {
        "name": "Credential Dumping",
        "pattern": re.compile(
            r"(lsass\.exe.*dump|procdump.*lsass|mimikatz|sekurlsa|"
            r"wce\.exe|ntdsutil|sam.*hive|/etc/shadow\s+read|"
            r"hashdump|pwdump|credential\s+dumping\s+detected|"
            r"lsass\.exe\s+memory\s+access)", re.IGNORECASE),
        "severity": "critical", "type": "credential_dumping", "mitre": "T1003",
        "category": "Phishing & Credential Theft"
    },
    {
        # Fires ONLY on raw repeated-failure signals with NO multi-account targeting context.
        # Disambiguation in detect() will suppress this when Credential Stuffing or
        # Password Spraying is confirmed from the same source IP.
        "name": "Brute-Force Authentication",
        "pattern": re.compile(
            r"\b(failed\s+password|invalid\s+(user|password|login)|"
            r"authentication\s+failure|login[_\s]failed|failed[_\s]login|"
            r"max\s+auth\s+attempts|too\s+many\s+failed|"
            r"credential\s+validation\s+failed|SSH\s+login\s+attempts|Failed\s+SSH\s+login|"
            r"Failed\s+login\s+attempt|Brute-force\s+threshold\s+exceeded|"
            r"Signature=SSH_Brute_Force)", re.IGNORECASE),
        "severity": "high", "type": "brute_force", "mitre": "T1110",
        "category": "Phishing & Credential Theft"
    },
    {
        # Fires ONLY on an explicit IDS signature or confirmed multi-account-targeting indicator.
        # Most specific auth classification — suppresses Brute-Force and Password Spraying
        # when present from the same source IP.
        "name": "Credential Stuffing",
        "pattern": re.compile(
            r"(signature=CREDENTIAL_STUFFING|credential[_\s]stuffing|"
            r"multiple_accounts_targeted=\d+)",
            re.IGNORECASE),
        "severity": "high", "type": "credential_stuffing", "mitre": "T1110.004",
        "category": "Phishing & Credential Theft"
    },
    {
        # Fires on multi-account lockout / spray language.
        # Suppresses Brute-Force when confirmed; suppressed itself by Credential Stuffing.
        "name": "Password Spraying",
        "pattern": re.compile(
            r"(multiple\s+accounts.*failed|accounts\s+locked|"
            r"lockout\s+threshold|distributed\s+login\s+failure|"
            r"spray\s+attack|user\s+enumeration|"
            r"password\s+spraying\s+detected|accounts\s+failed\s+login|"
            r"account_lockouts=[1-9])", re.IGNORECASE),
        "severity": "high", "type": "password_spray", "mitre": "T1110.003",
        "category": "Phishing & Credential Theft"
    },
    {
        "name": "Credential Exposure in Logs",
        "pattern": re.compile(
            r"\b(password\s*=\s*\S+|passwd\s*=\s*\S+|api[-_]?key\s*=\s*\S+|"
            r"secret[-_]?token\s*=\s*\S+|aws_access_key|"
            r"private[-_]?key|authorization:\s+bearer\s+\S+)\b",
            re.IGNORECASE),
        "severity": "critical", "type": "credential_exposure", "mitre": "T1552",
        "category": "Phishing & Credential Theft"
    },

    # ── NETWORK INFRASTRUCTURE ATTACKS ───────────────────────
    {
        "name": "BGP Hijacking",
        "pattern": re.compile(
            r"(BGP\s+hijacking|suspicious\s+route\s+announcement|"
            r"prefix\s+hijack|route\s+leak|unauthorized\s+BGP)", re.IGNORECASE),
        "severity": "critical", "type": "bgp_hijack", "mitre": "T1565",
        "category": "Network Infrastructure"
    },
    {
        "name": "Man-in-the-Middle (MitM)",
        "pattern": re.compile(
            r"(arp\s+poison|arp\s+spoof|ssl\s+strip|ssl\s+intercept|"
            r"certificate\s+mismatch|invalid\s+certificate|"
            r"tls\s+downgrade|heartbleed|beast\s+attack)", re.IGNORECASE),
        "severity": "high", "type": "mitm", "mitre": "T1557",
        "category": "Network Infrastructure"
    },
    {
        "name": "Router Compromise",
        "pattern": re.compile(
            r"(router\s+compromise|unauthorized\s+configuration\s+change|"
            r"edge\s+router|router\s+configuration)", re.IGNORECASE),
        "severity": "critical", "type": "router_compromise", "mitre": "T1562",
        "category": "Network Infrastructure"
    },
    {
        "name": "Lateral Movement / Pass-the-Hash",
        "pattern": re.compile(
            r"(pass.the.hash|pass.the.ticket|wmi\s+exec|psexec|"
            r"winrm\s+lateral|smbexec|atexec|dcomexec|"
            r"remote\s+registry.*modified|scheduled\s+task.*remote)",
            re.IGNORECASE),
        "severity": "critical", "type": "lateral_movement", "mitre": "T1550.002",
        "category": "Network Infrastructure"
    },

    # ── ISP-SPECIFIC ABUSE ────────────────────────────────────
    {
        "name": "Spam Campaign",
        "pattern": re.compile(
            r"(spam\s+campaign|spam\s+botnet|sending.*emails.*hour|"
            r"email\s+abuse|bulk\s+email)", re.IGNORECASE),
        "severity": "high", "type": "spam_abuse", "mitre": "T1566",
        "category": "ISP Abuse"
    },
    {
        "name": "Port Forwarding Abuse",
        "pattern": re.compile(
            r"(port\s+forwarding\s+abuse|exposing\s+internal\s+services|UPnP)", re.IGNORECASE),
        "severity": "medium", "type": "port_forwarding_abuse", "mitre": "T1090",
        "category": "ISP Abuse"
    },
    {
        "name": "Proxy Abuse",
        "pattern": re.compile(
            r"(open\s+proxy|proxy\s+abuse|malicious\s+traffic)", re.IGNORECASE),
        "severity": "high", "type": "proxy_abuse", "mitre": "T1090",
        "category": "ISP Abuse"
    },
    {
        "name": "Copyright Infringement",
        "pattern": re.compile(
            r"(copyright\s+infringement|torrent\s+traffic|DMCA\s+violation|"
            r"P2P\s+file\s+sharing|bittorrent\s+handshake|bittorrent)", re.IGNORECASE),
        "severity": "medium", "type": "copyright_infringement", "mitre": "T1048",
        "category": "ISP Abuse"
    },
    {
        "name": "Account Sharing",
        "pattern": re.compile(
            r"(account\s+sharing|multiple\s+simultaneous\s+logins|"
            r"different\s+IPs.*same\s+account)", re.IGNORECASE),
        "severity": "medium", "type": "account_sharing", "mitre": "T1078",
        "category": "ISP Abuse"
    },

    # ── VOIP & TELEPHONY ATTACKS ─────────────────────────────
    {
        "name": "VoIP Fraud",
        "pattern": re.compile(
            r"(VoIP\s+fraud|SIP\s+trunk\s+abuse|international\s+toll\s+fraud|"
            r"SIP\s+abuse|toll\s+fraud)", re.IGNORECASE),
        "severity": "critical", "type": "voip_fraud", "mitre": "T1204",
        "category": "VoIP & Telephony"
    },
    {
        "name": "TDoS Attack",
        "pattern": re.compile(
            r"(TDoS|Telephony\s+Denial\s+of\s+Service|calls.*minute.*PBX|"
            r"SIP\s+flood)", re.IGNORECASE),
        "severity": "critical", "type": "tdos", "mitre": "T1498",
        "category": "VoIP & Telephony"
    },
    {
        "name": "SIP Registration Attack",
        "pattern": re.compile(
            r"(SIP\s+registration\s+attack|brute-force\s+SIP\s+credentials)", re.IGNORECASE),
        "severity": "high", "type": "sip_attack", "mitre": "T1110",
        "category": "VoIP & Telephony"
    },
    {
        "name": "Eavesdropping",
        "pattern": re.compile(
            r"(eavesdropping|SIP\s+INVITE|malformed\s+headers|"
            r"call\s+interception)", re.IGNORECASE),
        "severity": "high", "type": "eavesdropping", "mitre": "T1123",
        "category": "VoIP & Telephony"
    },

    # ── IOT & SMART HOME ATTACKS ──────────────────────────────
    {
        "name": "IoT Botnet",
        "pattern": re.compile(
            r"(IoT\s+botnet|Mirai\s+infection|default\s+credentials|"
            r"IoT\s+device\s+compromise)", re.IGNORECASE),
        "severity": "high", "type": "iot_botnet", "mitre": "T1190",
        "category": "IoT & Smart Home"
    },
    {
        "name": "Smart Home Abuse",
        "pattern": re.compile(
            r"(smart\s+home\s+abuse|unauthorized\s+access.*IoT\s+hub|"
            r"IoT\s+hub)", re.IGNORECASE),
        "severity": "medium", "type": "smart_home_abuse", "mitre": "T1190",
        "category": "IoT & Smart Home"
    },
    {
        "name": "CCTV Camera Compromise",
        "pattern": re.compile(
            r"(CCTV\s+camera\s+compromise|accessing\s+camera\s+feed|"
            r"without\s+authorization)", re.IGNORECASE),
        "severity": "high", "type": "cctv_compromise", "mitre": "T1190",
        "category": "IoT & Smart Home"
    },
    {
        "name": "Smart Meter Tampering",
        "pattern": re.compile(
            r"(smart\s+meter\s+tampering|unusual\s+power\s+consumption|"
            r"potential\s+fraud)", re.IGNORECASE),
        "severity": "medium", "type": "meter_tampering", "mitre": "T1528",
        "category": "IoT & Smart Home"
    },

    # ── GENERAL NETWORK THREATS ─────────────────────────────
    {
        "name": "Firewall / Security Control Disabled",
        "pattern": re.compile(
            r"(iptables\s+-F|ufw\s+disable|firewall\s+disabled|"
            r"Windows\s+Firewall\s+turned\s+off|netsh\s+advfirewall\s+set.*off|"
            r"setenforce\s+0|apparmor\s+disabled)", re.IGNORECASE),
        "severity": "critical", "type": "security_disabled", "mitre": "T1562",
        "category": "Defense Evasion"
    },
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
        "name": "API Abuse / Scraping",
        "pattern": re.compile(
            r"(rate\s+limit\s+exceeded|api\s+abuse\s+detected|"
            r"scraping\s+detected|bot\s+traffic|unusual\s+api\s+pattern|"
            r"\d{3,}\s+requests.*per\s+second|automated\s+scan)",
            re.IGNORECASE),
        "severity": "medium", "type": "api_abuse", "mitre": "T1190",
        "category": "Network Abuse"
    },
    {
        # Fires ONLY on confirmed active exploitation evidence.
        # Passive signals (cve=CVE-XXXX, VULN_SCAN, unpatched, version strings) are
        # intentionally excluded here — those belong exclusively in VulnerabilityAssessment.
        # Active evidence required: IDS exploit sig, payload delivery, RCE confirmation,
        # privilege escalation, shell spawn, or command execution.
        "name": "Exploit Attempt",
        "pattern": re.compile(
            r"(exploit\s+(attempt|confirmed|success|detected)|"
            r"exploitation\s+(detected|confirmed)|"
            r"signature=EXPLOIT|"
            r"malicious\s+payload|payload\s+delivered|payload\s+received|"
            r"remote\s+code\s+execution|rce\s+(confirmed|detected)|"
            r"command\s+execution\s+confirmed|"
            r"shell\s+spawned|reverse\s+shell|"
            r"privilege\s+escalation|pkexec\s+privilege|dirtycow|"
            r"abnormal\s+process\s+creation|"
            r"jndi:(ldap|rmi|dns)://)",
            re.IGNORECASE),
        "severity": "high", "type": "exploit_attempt", "mitre": "T1190",
        "category": "Initial Access"
    },
]

COMPLIANCE_THREATS = {
    "Copyright Infringement",
    "Smart Meter Tampering",
    "Account Sharing",
}

REQUIRES_DIRECT_EVIDENCE = {
    "C2 Beacon / Command & Control",
}

# ── Auth-attack priority chain ────────────────────────────────────────────────
# Most-specific wins and suppresses lower-priority types for the same source IP.
AUTH_ATTACK_PRIORITY = [
    "Credential Stuffing",         # explicit IDS sig / multi-account targeting — most specific
    "Password Spraying",           # multi-account lockout / spray language
    "Brute-Force Authentication",  # raw failed-login fallback — least specific
]

# ── Cross-category specificity rules ─────────────────────────────────────────
# Each entry is (winner, suppressed_loser).
# When *winner* is detected from the same source IP, *suppressed_loser* is dropped.
#
# Design rationale per pair:
#   Network Recon > Port Scan/Recon
#       Network Recon matches "masscan.*subnet / targeting ISP subnet / probing multiple ports",
#       which is a superset of generic port scan evidence. When both fire on the same message,
#       the subnet-level reconnaissance label is more actionable for ISP analysts.
#
#   Amplification Attack > DDoS / Volumetric Attack
#       Amplification is a specific *type* of DDoS. Reporting both is redundant — the specific
#       mechanism (reflection/amplification) is more useful for mitigation.
#
#   Database Exfiltration / Dump > Data Exfiltration
#       A database dump is the *cause*; "large data transfer" is the *consequence*.
#       Prefer the root-cause classification.
#
#   DNS Tunneling / Exfiltration > Data Exfiltration
#       DNS tunneling is the *method* of exfiltration. Suppress the generic label so analysts
#       see the specific exfil channel rather than just "large transfer".
#
#   C2 Beacon / Command & Control > Tor / Anonymous Proxy Detected
#       Tor exit node usage is *how* C2 traffic is anonymised, not an independent threat.
#       When C2 is confirmed, the Tor observation is implied and redundant.
#
#   C2 Beacon / Command & Control > IoT Botnet
#       IoT Botnet describes the *infection source*; C2 describes the *active behaviour*.
#       When C2 callback traffic is directly confirmed, that is the primary finding.
#
#   Tor / Anonymous Proxy Detected > Proxy Abuse
#       Tor is a specific anonymiser. Generic "Proxy Abuse" is a weaker classification
#       of the same evidence when a Tor exit node is explicitly identified.
#
#   SIP Registration Attack > Brute-Force Authentication
#       SIP Registration Attack is the VoIP-specific classification; Brute-Force is the
#       generic authentication failure category. The specific classification wins.
#
CATEGORY_PRIORITY_RULES: List[tuple] = [
    ("Network Reconnaissance",           "Port Scanning / Reconnaissance"),
    ("Amplification Attack",             "DDoS / Volumetric Attack"),
    ("Database Exfiltration / Dump",     "Data Exfiltration"),
    ("DNS Tunneling / Exfiltration",     "Data Exfiltration"),
    ("C2 Beacon / Command & Control",    "Tor / Anonymous Proxy Detected"),
    ("C2 Beacon / Command & Control",    "IoT Botnet"),
    ("Tor / Anonymous Proxy Detected",   "Proxy Abuse"),
    ("SIP Registration Attack",          "Brute-Force Authentication"),
]

DOMAINS = {
    "NETWORK_PERFORMANCE": {
        "labels": [
            "High Latency / Degraded Performance",
            "Packet Loss / Connection Issues",
            "DNS Resolution Delay",
            "Bandwidth Spike",
        ],
        "description": "Network performance metrics — not security threats.",
    },
    "SECURITY_THREATS": {
        "labels": [p["name"] for p in INDICATOR_PATTERNS],
        "description": "Confirmed or suspicious security threats with evidence.",
    },
    "SERVICE_HEALTH": {
        "labels": [
            "Service Outage",
            "Infrastructure Failure",
            "Routing Path Change",
        ],
        "description": "Service availability conditions — not security threats.",
    },
    "COMPLIANCE": {
        "labels": [
            "Copyright Infringement",
            "Smart Meter Tampering",
            "Account Sharing",
        ],
        "description": "Policy and compliance violations.",
    },
}

_MALICIOUS_CONTEXT = re.compile(
    r"(ddos|attack|flood|scan|malware|c2|beacon|exfiltration|breach|intrusion|"
    r"exploit|brute|ransomware|botnet|hijack|spoof|tunnel|dump|phish|spam|"
    r"compromise|credential|exfil|ransom|shell|proxy\s+abuse|toll\s+fraud)",
    re.IGNORECASE,
)


def get_domain_label(domain: str, threat_type: str) -> str:
    """Return the display label for a detection within its domain."""
    labels = DOMAINS.get(domain, {}).get("labels", [])
    if threat_type in labels:
        return threat_type
    if domain == "NETWORK_PERFORMANCE":
        if re.search(r"packet\s*loss|dropped_packets", threat_type, re.IGNORECASE):
            return "Packet Loss / Connection Issues"
        if re.search(r"dns|nxdomain", threat_type, re.IGNORECASE):
            return "DNS Resolution Delay"
        if re.search(r"bandwidth|throughput", threat_type, re.IGNORECASE):
            return "Bandwidth Spike"
        return "High Latency / Degraded Performance"
    return threat_type


class ThreatDetector:
    """High-precision ISP/SIEM threat analysis engine with strict evidence requirements."""

    def __init__(self):
        self.anomaly_detector = AnomalyDetector()
        self.classifier = ThreatClassifier()
        self.dedup_window_seconds = 60
        self._monitor_escalation_tracker: Dict[tuple, List[datetime]] = {}

    def _determine_threat_status(self, confidence: float) -> str:
        """Map confidence to threat status: NONE | MONITOR | SUSPICIOUS | CONFIRMED."""
        if confidence < 0.40:
            return "NONE"
        if confidence < 0.70:
            return "MONITOR"
        if confidence < 0.85:
            return "SUSPICIOUS"
        return "CONFIRMED"

    def _compute_status(self, confidence: float, severity: str, domain: str) -> str:
        """Map confidence to UI status badge."""
        if confidence < 0.70:
            return "MONITOR_ONLY"
        if domain in ("NETWORK_PERFORMANCE", "SERVICE_HEALTH"):
            return "CRITICAL" if severity in ("high", "critical") else "DEGRADED"
        if confidence < 0.85:
            return "SUSPICIOUS"
        return "CRITICAL" if severity in ("high", "critical") else "SUSPICIOUS"

    def _resolve_domain(self, threat_name: str) -> str:
        if threat_name in COMPLIANCE_THREATS:
            return "COMPLIANCE"
        return "SECURITY_THREATS"

    def _classification_type(self, domain: str) -> str:
        if domain == "COMPLIANCE":
            return "Classification"
        if domain in ("NETWORK_PERFORMANCE", "SERVICE_HEALTH"):
            return "Condition"
        return "Threat"

    def _has_security_context(self, msg: str) -> bool:
        return bool(_MALICIOUS_CONTEXT.search(msg))

    def _is_operational_only(self, msg: str, matched: List[Dict[str, Any]]) -> bool:
        """True when log is a performance metric with no security indicator."""
        has_operational = any(p.search(msg) for p in OPERATIONAL_PATTERNS)
        if not has_operational:
            return False
        if matched and self._has_security_context(msg):
            return False
        if matched:
            return False
        return True

    # Passive vulnerability-disclosure signals that belong in VulnerabilityAssessment,
    # not in the threat pipeline.
    _PASSIVE_VULN_PATTERN = re.compile(
        r"(cve=CVE-\d{4}-\d+|CVE-\d{4}-\d+|VULN_SCAN|vuln_scan|"
        r"\bunpatched\b|vulnerable\s+(component|version|service)|"
        r"version\s+string|server=\S+/\d+\.\d+)",
        re.IGNORECASE,
    )

    # Active exploitation signals that *do* promote a log to the threat pipeline.
    _ACTIVE_EXPLOIT_PATTERN = re.compile(
        r"(exploit\s+(attempt|confirmed|success|detected)|"
        r"exploitation\s+(detected|confirmed)|"
        r"signature=EXPLOIT|"
        r"malicious\s+payload|payload\s+(delivered|received)|"
        r"remote\s+code\s+execution|rce\s+(confirmed|detected)|"
        r"command\s+execution\s+confirmed|"
        r"shell\s+spawned|reverse\s+shell|"
        r"privilege\s+escalation|pkexec|dirtycow|"
        r"abnormal\s+process\s+creation|"
        r"jndi:(ldap|rmi|dns)://)",
        re.IGNORECASE,
    )

    def _is_passive_vuln_only(self, msg: str, matched: List[Dict[str, Any]]) -> bool:
        """
        Return True when a log line contains only passive CVE/scanner signals with no
        active exploitation evidence.  Such lines are handled by VulnerabilityAssessment
        and must NOT produce threat-pipeline detections (no MITRE mapping, no alert card).

        A line is passive-only when ALL of the following hold:
          1. It matches a passive vulnerability pattern (CVE ref, VULN_SCAN, version string).
          2. It does NOT match any active exploitation pattern.
          3. Every matched INDICATOR_PATTERN rule that fired on it is the Exploit Attempt
             rule — meaning no independently-confirmed other threat type is also present.
        """
        if not self._PASSIVE_VULN_PATTERN.search(msg):
            return False  # no passive signal at all
        if self._ACTIVE_EXPLOIT_PATTERN.search(msg):
            return False  # active exploitation evidence present — allow through
        # If any matched rule is something *other* than Exploit Attempt, let it through
        # so that e.g. a port-scan line that also mentions a CVE still fires Port Scan.
        non_exploit_matches = [p for p in matched if p["name"] != "Exploit Attempt"]
        if non_exploit_matches:
            return False
        return True

    def _has_direct_indicator(self, threat_name: str, msg: str) -> bool:
        indicators = DIRECT_INDICATORS.get(threat_name, [])
        msg_lower = msg.lower()
        for indicator in indicators:
            if indicator.lower() in msg_lower:
                return True
        return False

    def _classify_operational(self, msg: str) -> Dict[str, Any]:
        if re.search(
            r"(latency|rtt_ms|packet_loss|jitter|dropped_packets|congestion|"
            r"degraded\s+performance|bandwidth\s+spike|high\s+throughput|nxdomain)",
            msg,
            re.IGNORECASE,
        ):
            return {
                "threat_type": "High Latency / Degraded Performance",
                "domain": "NETWORK_PERFORMANCE",
                "severity": "low",
                "explanation": (
                    "Network performance condition detected. This indicates network "
                    "degradation, not a security threat."
                ),
                "impact": "Elevated latency, packet loss, or jitter affecting service quality.",
                "mitigation": "Check link utilization, trace routing hops, and monitor for congestion.",
            }
        return {
            "threat_type": "Service Health Degraded",
            "domain": "SERVICE_HEALTH",
            "severity": "low",
            "explanation": (
                "Service health condition detected. This indicates service availability "
                "problems, not a security threat."
            ),
            "impact": "Elevated response times, timeouts, or routing path changes.",
            "mitigation": "Check DNS server health, verify BGP status, and inspect router logs.",
        }

    def _parse_timestamp(self, row: Dict[str, Any]) -> datetime:
        ts = row.get("timestamp")
        if isinstance(ts, datetime):
            return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        if isinstance(ts, str) and ts:
            try:
                parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        return datetime.now(timezone.utc)

    def _collect_evidence(self, threat_name: str, msg: str, has_direct: bool, corroborating_count: int) -> List[str]:
        evidence = []
        if has_direct:
            for indicator in DIRECT_INDICATORS.get(threat_name, []):
                if indicator.lower() in msg.lower():
                    evidence.append(f"Direct indicator: '{indicator}'")
                    break
            if not evidence:
                evidence.append(f"Direct signature match for '{threat_name}'")
        if corroborating_count >= 2:
            evidence.append(f"{corroborating_count} corroborating log entries from same source")
        if not evidence:
            evidence.append(f"Pattern match for '{threat_name}'")
        return evidence

    def _build_detection(
        self,
        *,
        row: Dict[str, Any],
        pattern: Dict[str, Any],
        source_ip: str,
        confidence: float,
        has_direct: bool,
        corroborating_count: int,
        index: int,
    ) -> Dict[str, Any]:
        msg = row.get("raw_message", "")
        lookup = pattern["name"]
        details = THREAT_DETAILS.get(lookup, {})
        domain = self._resolve_domain(lookup)
        classification_type = self._classification_type(domain)
        sev = pattern["severity"]
        mitre = pattern.get("mitre", "NOT APPLICABLE")
        mitre_tactics = [mitre] if domain == "SECURITY_THREATS" else ["NOT APPLICABLE"]

        explanation = details.get(
            "explanation",
            f"Security signature match for '{lookup}'.",
        )
        impact = details.get("impact", "Potential security exposure or service degradation.")
        mitigation = details.get(
            "mitigation",
            "Review access logs, block sender IP, and check system configurations.",
        )

        threat_status = self._determine_threat_status(confidence)
        label = get_domain_label(domain, lookup)
        status = self._compute_status(confidence, sev, domain)

        cve_match = re.search(r"cve=(CVE-\d{4}-\d+)", msg, re.IGNORECASE)
        cve_id = cve_match.group(1).upper() if cve_match else "N/A"

        return {
            "threat_type": lookup,
            "source_ip": source_ip,
            "domain": domain,
            "classification_type": classification_type,
            "threat_status": threat_status,
            "severity": sev,
            "confidence": confidence,
            "label": label,
            "status": status,
            "category": pattern.get("category", "Unknown"),
            "mitre_attack": mitre if domain == "SECURITY_THREATS" else "NOT APPLICABLE",
            "mitre_tactics": mitre_tactics,
            "evidence": self._collect_evidence(lookup, msg, has_direct, corroborating_count),
            "explanation": explanation,
            "impact": impact,
            "mitigation": mitigation,
            "raw_message": msg,
            "timestamp": self._parse_timestamp(row).isoformat(),
            "cve_id": cve_id,
            "line_index": index,
        }

    def _compute_confidence(
        self,
        *,
        base: float,
        anom: float,
        clf_conf: float,
        jitter: float,
        has_direct: bool,
        is_confirmed: bool,
        corroborating_count: int,
    ) -> float:
        if is_confirmed:
            raw_conf = 0.70 * base + 0.15 * anom + 0.15 * clf_conf + jitter
            if has_direct:
                raw_conf += 0.15
            floor = 0.65 if (corroborating_count >= 2 and not has_direct) else 0.70
            raw_conf = max(raw_conf, floor)
            return round(min(0.99, raw_conf), 3)
        raw_conf = 0.50 * base + 0.25 * anom + 0.25 * clf_conf + jitter
        return round(min(0.55, max(0.30, raw_conf)), 3)

    def detect(self, features_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not features_list:
            return []

        resolved_ips = []
        for idx, row in enumerate(features_list):
            ip = row.get("source_ip", "unknown")
            if ip == "unknown":
                back_ip = "unknown"
                for j in range(idx - 1, -1, -1):
                    other_ip = features_list[j].get("source_ip", "unknown")
                    if other_ip != "unknown":
                        back_ip = other_ip
                        break
                fwd_ip = "unknown"
                for j in range(idx + 1, len(features_list)):
                    other_ip = features_list[j].get("source_ip", "unknown")
                    if other_ip != "unknown":
                        fwd_ip = other_ip
                        break
                ip = back_ip if back_ip != "unknown" else fwd_ip
            resolved_ips.append(ip)

        X_numeric = [
            [
                row.get("message_length", 0),
                row.get("status_code", 0),
                row.get("bytes_sent", 0),
                row.get("cpu", 0.0),
                row.get("memory", 0.0),
                row.get("network_tx", 0.0),
                row.get("network_rx", 0.0),
            ]
            for row in features_list
        ]
        anomaly_scores = self.anomaly_detector.anomaly_scores(X_numeric)
        confidences = self.classifier.predict_proba(X_numeric)

        row_matched_rules = []
        for row in features_list:
            msg = row.get("raw_message", "")
            matched = [p for p in INDICATOR_PATTERNS if p["pattern"].search(msg)]
            row_matched_rules.append(matched)

        threat_occurrences: Dict[tuple, List[int]] = {}
        for i, row in enumerate(features_list):
            msg = row.get("raw_message", "")
            if self._is_operational_only(msg, row_matched_rules[i]):
                continue
            if self._is_passive_vuln_only(msg, row_matched_rules[i]):
                continue
            for pattern in row_matched_rules[i]:
                key = (resolved_ips[i], pattern["name"])
                threat_occurrences.setdefault(key, []).append(i)

        seen_keys: Dict[tuple, tuple] = {}
        base_map = {"critical": 0.94, "high": 0.86, "medium": 0.75, "low": 0.60}

        for (source_ip, threat_name), indices in threat_occurrences.items():
            has_direct = any(
                self._has_direct_indicator(threat_name, features_list[idx].get("raw_message", ""))
                for idx in indices
            )
            corroborating_count = len(indices)
            # ISP signature regex match is direct evidence unless strict C2 rules apply
            is_confirmed = has_direct or corroborating_count >= 2

            for i in indices:
                pattern = next((p for p in row_matched_rules[i] if p["name"] == threat_name), None)
                if not pattern:
                    continue

                msg = features_list[i].get("raw_message", "")
                row_has_direct = self._has_direct_indicator(threat_name, msg)
                if pattern["name"] in REQUIRES_DIRECT_EVIDENCE and not row_has_direct:
                    continue

                confirmed = is_confirmed or pattern["name"] not in REQUIRES_DIRECT_EVIDENCE
                sev = pattern["severity"]
                base = base_map.get(sev, 0.75)
                seed = hashlib.md5(f"{msg}:{pattern['name']}:{i}".encode()).hexdigest()
                jitter = (int(seed[:8], 16) % 1000) / 10000.0 - 0.05

                confidence = self._compute_confidence(
                    base=base,
                    anom=anomaly_scores[i],
                    clf_conf=confidences[i],
                    jitter=jitter,
                    has_direct=has_direct or row_has_direct,
                    is_confirmed=confirmed,
                    corroborating_count=corroborating_count,
                )

                threat_status = self._determine_threat_status(confidence)
                domain = self._resolve_domain(threat_name)

                if domain == "SECURITY_THREATS" and threat_status not in ("SUSPICIOUS", "CONFIRMED"):
                    if not confirmed:
                        continue

                detection = self._build_detection(
                    row=features_list[i],
                    pattern=pattern,
                    source_ip=source_ip,
                    confidence=confidence,
                    has_direct=has_direct or row_has_direct,
                    corroborating_count=corroborating_count,
                    index=i,
                )

                dedup_key = (source_ip, threat_name)
                det_time = self._parse_timestamp(features_list[i])
                if dedup_key in seen_keys:
                    last_time, last_detection = seen_keys[dedup_key]
                    if abs((det_time - last_time).total_seconds()) <= self.dedup_window_seconds:
                        if detection["confidence"] > last_detection["confidence"]:
                            seen_keys[dedup_key] = (det_time, detection)
                        continue
                seen_keys[dedup_key] = (det_time, detection)

        raw_detections = [det for (_, det) in seen_keys.values()]
        return self._disambiguate_detections(raw_detections)

    def _disambiguate_detections(
        self, detections: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Apply all specificity rules to avoid duplicate / mutually-exclusive detections.

        Step 1 – Auth attacks: keep only the most specific per source IP.
        Step 2 – Cross-category rules: for each (winner, loser) pair in
                 CATEGORY_PRIORITY_RULES, if winner is present for a given IP
                 then loser is suppressed for that same IP.
        """
        # ── Step 1: auth disambiguation (existing logic) ──────────────────
        result = self._disambiguate_auth_attacks(detections)

        # ── Step 2: cross-category specificity rules ──────────────────────
        # Build a set of (ip, threat_type) for fast lookup
        present: set = {(d["source_ip"], d["threat_type"]) for d in result}

        suppressed: set = set()
        for winner, loser in CATEGORY_PRIORITY_RULES:
            for det in result:
                ip = det["source_ip"]
                if det["threat_type"] == winner and (ip, loser) in present:
                    suppressed.add((ip, loser))

        if suppressed:
            result = [
                d for d in result
                if (d["source_ip"], d["threat_type"]) not in suppressed
            ]

        return result

    def _disambiguate_auth_attacks(
        self, detections: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        For each source IP, keep only the most specific auth-attack classification.

        Priority (highest to lowest):
          1. Credential Stuffing   — explicit IDS signature or multi-account targeting
          2. Password Spraying     — multi-account lockout / spray language
          3. Brute-Force Auth      — raw failed-login fallback

        When a higher-priority type is present for a given source IP, all
        lower-priority auth types from that same IP are suppressed.
        Non-auth detections are always passed through unchanged.
        """
        auth_set = set(AUTH_ATTACK_PRIORITY)

        # Group auth detections by source IP
        auth_by_ip: Dict[str, List[Dict[str, Any]]] = {}
        non_auth: List[Dict[str, Any]] = []

        for det in detections:
            if det["threat_type"] in auth_set:
                ip = det.get("source_ip", "unknown")
                auth_by_ip.setdefault(ip, []).append(det)
            else:
                non_auth.append(det)

        kept_auth: List[Dict[str, Any]] = []
        for ip, auth_detections in auth_by_ip.items():
            present_types = {d["threat_type"] for d in auth_detections}

            # Find the highest-priority type that was actually detected
            winning_type = None
            for candidate in AUTH_ATTACK_PRIORITY:
                if candidate in present_types:
                    winning_type = candidate
                    break

            if winning_type is None:
                # No known auth type found — keep all (shouldn't happen)
                kept_auth.extend(auth_detections)
                continue

            # Keep only detections of the winning type for this IP
            for det in auth_detections:
                if det["threat_type"] == winning_type:
                    kept_auth.append(det)
                # Lower-priority auth types are silently suppressed

        return non_auth + kept_auth

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
        """High-precision log analysis per ISP/SIEM specification with backward compatibility."""
        lines = [line.strip() for line in log_text.splitlines() if line.strip()]
        if not lines:
            lines = [log_text]
            
        from .feature_engineering import extract_features
        features_list = [extract_features(line) for line in lines]
        detections = self.detect(features_list)
        security_threats = [
            d for d in detections
            if (
                d.get("threat_status") in ("SUSPICIOUS", "CONFIRMED")
                and d.get("domain") == "SECURITY_THREATS"
            )
            or (
                d.get("classification_type") in ("Threat", "Classification")
                and d.get("domain") in ("SECURITY_THREATS", "COMPLIANCE")
            )
        ]

        if security_threats:
            highest_conf_det = max(security_threats, key=lambda d: d["confidence"])
            prob = int(round(
                sum(t["confidence"] for t in security_threats) / len(security_threats) * 100
            ))
            unique_threats = list(dict.fromkeys(d["threat_type"] for d in security_threats))
            reason = (
                f"Multiple security threats detected: {', '.join(unique_threats)}."
                if len(unique_threats) > 1
                else f"Security threat '{unique_threats[0]}' detected in logs."
            )
            status = "threat"
            return {
                "domain": highest_conf_det["domain"],
                "threat_status": highest_conf_det["threat_status"],
                "severity": highest_conf_det["severity"],
                "confidence": highest_conf_det["confidence"],
                "mitre_attack": highest_conf_det["mitre_attack"],
                "mitre_tactics": highest_conf_det["mitre_tactics"],
                "evidence": highest_conf_det["evidence"],
                "explanation": highest_conf_det["explanation"],
                "impact": highest_conf_det["impact"],
                "mitigation": highest_conf_det["mitigation"],
                "raw_message": highest_conf_det["raw_message"],
                "all_detections": detections,
                # Old output keys for compatibility with frontend
                "probability": prob,
                "status": status,
                "reason": reason
            }
        
        return {
            "domain": "SECURITY_THREATS",
            "threat_status": "NONE",
            "severity": "LOW",
            "confidence": 0.0,
            "mitre_attack": [],
            "mitre_tactics": [],
            "evidence": [],
            "explanation": "No threats detected. Log entries match normal ISP activity patterns.",
            "mitigation": "N/A",
            "raw_message": log_text,
            "all_detections": [],
            # Old output keys for compatibility with frontend
            "probability": 0,
            "status": "clean",
            "reason": "No threats detected. Log entries match normal ISP activity patterns."
        }



THREAT_DETAILS = {
    # ── BRUTE-FORCE / CREDENTIAL ─────────────────────────────
    "Brute-Force Authentication": {
        "explanation": "Repeated failed login attempts detected from a single source IP against SSH, RADIUS, or web portals, indicating an automated credential guessing campaign.",
        "impact": "Unauthorized account access, customer credential compromise, and potential lateral movement within the ISP infrastructure.",
        "mitigation": "Implement rate limiting and IP-based lockout on authentication endpoints. Deploy fail2ban or similar tools. Enforce MFA for all administrative and customer portals."
    },
    "Credential Stuffing": {
        "explanation": "Automated login attempts across multiple distinct accounts from a single source IP detected, consistent with credential stuffing using previously breached username/password pairs. IDS signature CREDENTIAL_STUFFING confirmed with high confidence.",
        "impact": "Mass account takeover of customer credentials, enabling fraudulent service usage, data theft, and further lateral movement.",
        "mitigation": "Block the offending source IP immediately. Force password resets for targeted accounts. Enable MFA. Check breached credential databases (HaveIBeenPwned) for affected accounts. Review rate-limiting policies on authentication endpoints."
    },
    "Password Spraying": {
        "explanation": "Low-volume login failures spread across many customer accounts from a single source, consistent with a password-spraying campaign to avoid lockout thresholds.",
        "impact": "Compromise of multiple customer accounts with weak or common passwords, enabling account takeovers and fraudulent service usage.",
        "mitigation": "Monitor for cross-account login anomalies, enforce strong password requirements, and alert on distributed login failure patterns."
    },
    "SIP Registration Attack": {
        "explanation": "Brute-force attempts detected against SIP registration endpoints, targeting VoIP credential compromise.",
        "impact": "Unauthorized VoIP service access enabling toll fraud and eavesdropping on customer communications.",
        "mitigation": "Restrict SIP registration to known customer IP ranges, implement SIP-aware intrusion prevention, and enforce strong SIP credentials."
    },
    # ── DDoS / VOLUMETRIC ────────────────────────────────────
    "DDoS / Volumetric Attack": {
        "explanation": "Volumetric flood traffic (SYN, UDP, HTTP, or ICMP) directed at ISP infrastructure or downstream customers, consistent with a coordinated denial-of-service attack.",
        "impact": "Service unavailability for targeted customers, backbone saturation affecting all ISP subscribers, and potential SLA violations.",
        "mitigation": "Activate upstream scrubbing via DDoS mitigation provider. Apply BGP blackholing for victim prefix. Implement rate limiting at peering points."
    },
    "Amplification Attack": {
        "explanation": "Open resolvers or NTP servers on the ISP network are being abused to reflect and amplify UDP traffic toward a victim, multiplying attack bandwidth.",
        "impact": "Significant backbone congestion and collateral damage to customers sharing infrastructure with the victim.",
        "mitigation": "Close open DNS resolvers and disable NTP monlist. Implement BCP38 ingress filtering. Rate-limit UDP responses from publicly exposed services."
    },
    # ── PORT SCAN / RECON ────────────────────────────────────
    "Port Scanning / Reconnaissance": {
        "explanation": "Systematic probe of multiple ports across ISP-managed IP ranges, indicating network mapping or vulnerability discovery by an external actor.",
        "impact": "Detailed knowledge of open services and network topology obtained by adversaries, enabling targeted follow-on attacks.",
        "mitigation": "Deploy network IDS to detect scan patterns. Block scanning IPs at edge routers. Limit SNMP community string exposure."
    },
    "Network Reconnaissance": {
        "explanation": "Broad subnet scanning or service enumeration across ISP customer address space detected, consistent with pre-attack reconnaissance.",
        "impact": "Identification of vulnerable customer endpoints and ISP infrastructure nodes for targeted exploitation.",
        "mitigation": "Apply rate limiting on ICMP and TCP SYN responses. Use honeypots to detect and fingerprint reconnaissance activity."
    },
    # ── DNS ATTACKS ──────────────────────────────────────────
    "DNS Tunneling / Exfiltration": {
        "explanation": "Base64-encoded payloads or abnormally long subdomains detected in DNS queries, indicating data exfiltration or C2 communication via DNS tunneling.",
        "impact": "Bypass of firewall egress controls for covert data theft or persistent C2 channel maintenance through ISP recursive resolvers.",
        "mitigation": "Deploy DNS firewall with payload inspection. Block unusually long query names. Monitor query rates per client and alert on anomalous DNS patterns."
    },
    "DNS Cache Poisoning": {
        "explanation": "Spoofed DNS responses or cache poisoning attempt detected targeting ISP recursive resolvers, potentially redirecting customer traffic.",
        "impact": "Customer traffic redirected to malicious servers, enabling credential phishing, malware delivery, and man-in-the-middle attacks at scale.",
        "mitigation": "Enable DNSSEC validation on all recursive resolvers. Randomize DNS source ports. Upgrade to DNS-over-TLS/HTTPS for stub resolver traffic."
    },
    "DNS Water Torture / NXDOMAIN Flood": {
        "explanation": "High-rate flood of queries for randomly generated non-existent subdomains targeting ISP authoritative or recursive DNS infrastructure.",
        "impact": "DNS server resource exhaustion, increased response latency, and denial of DNS service for all ISP customers.",
        "mitigation": "Enable DNS Response Rate Limiting (RRL). Deploy anycast DNS infrastructure. Filter NXDOMAIN floods at upstream peering points."
    },
    # ── BOTNET & C2 ──────────────────────────────────────────
    "C2 Beacon / Command & Control": {
        "explanation": "Reverse shell callback or C2 beacon traffic detected originating from a customer device to an external command-and-control server.",
        "impact": "Compromised customer device actively controlled by threat actor, potentially used for further attacks or data exfiltration through ISP network.",
        "mitigation": "Block known C2 infrastructure using threat intelligence feeds. Notify affected customer and recommend device remediation. Implement egress filtering for suspicious callback ports."
    },
    "Tor / Anonymous Proxy Detected": {
        "explanation": "Traffic routed through Tor exit nodes or anonymous proxy chains detected, often used to obscure C2 communications or illicit activity.",
        "impact": "Untraceable malicious activity originating from ISP customer network, complicating incident response and potential legal liability.",
        "mitigation": "Block known Tor exit node IP lists at edge. Alert customer with remediation guidance. Maintain up-to-date threat intelligence blocklists."
    },
    "Cryptominer / Coin Miner": {
        "explanation": "Cryptocurrency mining client (xmrig, stratum protocol) detected connecting to external mining pool from a customer device.",
        "impact": "Unauthorized consumption of ISP bandwidth and customer compute resources; device likely part of a larger botnet infection.",
        "mitigation": "Block mining pool connection patterns at edge (stratum+tcp port 4444). Alert customer of device compromise. Enforce AUP clauses on prohibited mining activity."
    },
    # ── MALWARE DISTRIBUTION ─────────────────────────────────
    "Malware Distribution": {
        "explanation": "Customer-hosted server distributing malware payloads (Emotet, worms, ransomware droppers) detected over HTTP/HTTPS.",
        "impact": "ISP network used as malware distribution infrastructure, damaging reputation and triggering abuse complaints.",
        "mitigation": "Immediately null-route offending customer IP. Notify customer and require remediation before restoration. Submit indicators to abuse databases."
    },
    "Ransomware Activity": {
        "explanation": "Mass file encryption activity or ransomware-specific file extension patterns detected on a customer device connected to the ISP network.",
        "impact": "Customer data loss and potential spread to networked devices; may impact ISP-hosted services if originating from a managed server.",
        "mitigation": "Alert customer immediately and recommend network isolation of infected device. Block SMB lateral movement at edge. Preserve logs for forensic analysis."
    },
    "Fileless Malware / LOLBins": {
        "explanation": "Abuse of built-in system tools (PowerShell -EncodedCommand, certutil -decode) for in-memory payload execution detected on a network-connected device.",
        "impact": "Evasion of traditional antivirus, enabling persistent access and further compromise through living-off-the-land techniques.",
        "mitigation": "Enable PowerShell Script Block Logging. Restrict certutil and mshta via application control policies. Deploy EDR on managed endpoints."
    },
    # ── DATA EXFILTRATION ────────────────────────────────────
    "Data Exfiltration": {
        "explanation": "Unusually large outbound data transfer to an external IP detected, inconsistent with normal customer traffic baseline, indicating potential data theft.",
        "impact": "Loss of sensitive customer data, intellectual property, or database contents through the ISP network, creating compliance and legal exposure.",
        "mitigation": "Enforce egress bandwidth anomaly alerting. Block destination IP pending investigation. Notify customer with transfer volume details and request justification."
    },
    "Database Exfiltration / Dump": {
        "explanation": "Database dump utility execution (mysqldump, pg_dump) or bulk data export query detected on a customer-hosted database server.",
        "impact": "Complete exfiltration of customer database contents, including PII, financial records, or proprietary business data.",
        "mitigation": "Restrict database backup commands to authorised administrator accounts. Implement database activity monitoring. Audit all bulk data query patterns."
    },
    # ── PHISHING & CREDENTIAL ACCESS ─────────────────────────
    "Phishing Kit": {
        "explanation": "Customer-hosted server running a phishing kit targeting credential harvesting from third-party service users, mimicking legitimate login pages.",
        "impact": "ISP network used as phishing infrastructure, triggering takedown requests, abuse complaints, and potential service suspension.",
        "mitigation": "Immediately null-route the hosting IP. Submit phishing URL to Google Safe Browsing and PhishTank. Notify customer and require content removal."
    },
    "Credential Dumping": {
        "explanation": "Memory access to Windows LSASS process or credential extraction tool execution detected on a networked device.",
        "impact": "Compromise of all cached Windows domain credentials, enabling lateral movement and privilege escalation across the network.",
        "mitigation": "Enable LSA protection (RunAsPPL). Deploy EDR to block LSASS access. Recommend customer isolate device and rotate all domain credentials."
    },
    "Credential Exposure in Logs": {
        "explanation": "Plaintext password, API key, or secret token found in network-accessible log files or captured in transit.",
        "impact": "Immediate exposure of credentials to anyone with log access, enabling unauthorised service access or account takeover.",
        "mitigation": "Redact sensitive fields in application logging before writing to disk. Use secrets management vaults. Rotate all exposed credentials immediately."
    },
    # ── NETWORK INFRASTRUCTURE ───────────────────────────────
    "BGP Hijacking": {
        "explanation": "Suspicious BGP route announcement detected that hijacks an IP prefix not legitimately owned by the announcing AS.",
        "impact": "Customer traffic redirected through adversary-controlled infrastructure, enabling interception or blackholing of ISP customer communications.",
        "mitigation": "Implement RPKI for route origin validation. Apply IRR-based prefix filtering. Alert NOC for immediate investigation."
    },
    "Man-in-the-Middle (MitM)": {
        "explanation": "ARP spoofing or SSL stripping attack detected on a network segment, enabling interception of customer traffic.",
        "impact": "Eavesdropping on unencrypted communications, credential theft, and session hijacking for affected customers.",
        "mitigation": "Enable Dynamic ARP Inspection (DAI) on managed switches. Enforce HTTPS everywhere with HSTS preloading. Deploy 802.1X port authentication."
    },
    "Router Compromise": {
        "explanation": "Unauthorized configuration change detected on an ISP edge or customer-premises router, indicating compromise or insider threat.",
        "impact": "Traffic redirection, routing loop introduction, or complete loss of routing service for affected customer segments.",
        "mitigation": "Immediately review and revert unauthorized changes. Rotate all router management credentials. Enforce out-of-band management access only."
    },
    "Lateral Movement / Pass-the-Hash": {
        "explanation": "Pass-the-hash or WMI-based lateral movement detected between network hosts, indicating an attacker pivoting through the infrastructure.",
        "impact": "Expansion of attacker foothold from one compromised device to multiple systems within the same network segment.",
        "mitigation": "Disable NTLMv1 across all devices. Restrict administrative shares. Deploy network segmentation to limit east-west lateral movement paths."
    },
    # ── ISP ABUSE ────────────────────────────────────────────
    "Spam Campaign": {
        "explanation": "High-volume unsolicited email transmission detected from a customer IP, consistent with a spam botnet infection or deliberate abuse.",
        "impact": "ISP IP ranges blacklisted by major email providers, affecting all customers' email deliverability and ISP reputation.",
        "mitigation": "Rate-limit outbound SMTP for residential customers. Notify customer and block SMTP until remediated. Submit IPs for delisting post-cleanup."
    },
    "Port Forwarding Abuse": {
        "explanation": "Customer device using UPnP to expose internal services to the public internet without authorization.",
        "impact": "Exposure of internal services to external attackers, potentially enabling exploitation of unpatched services behind the ISP NAT.",
        "mitigation": "Disable UPnP on customer-premises equipment. Audit and revoke unauthorized port forwarding rules. Notify customer of the exposure."
    },
    "Proxy Abuse": {
        "explanation": "Open proxy service detected on a customer IP being exploited for anonymous malicious traffic routing.",
        "impact": "ISP bandwidth consumed by third-party malicious actors; ISP IP ranges associated with abuse activity in threat intelligence databases.",
        "mitigation": "Block ports commonly associated with open proxy services. Notify customer to close open proxy. Apply AUP enforcement."
    },
    "Copyright Infringement": {
        "explanation": "BitTorrent traffic or DMCA takedown notice associated with copyright-infringing file sharing detected from a customer IP.",
        "impact": "Legal liability for the ISP if not acted upon; repeated violations may require mandatory account suspension under copyright law.",
        "mitigation": "Issue DMCA notice to customer per legal obligations. Track repeat offenders. Throttle P2P traffic per AUP policy for persistent violators."
    },
    "Account Sharing": {
        "explanation": "Multiple simultaneous authenticated sessions from geographically disparate IPs detected on the same customer account.",
        "impact": "Revenue loss from unauthorized account sharing and potential credential compromise if account was sold or leaked.",
        "mitigation": "Enforce single-session policies or concurrent connection limits. Alert customer of suspicious simultaneous access. Require password reset."
    },
    # ── VOIP & TELEPHONY ─────────────────────────────────────
    "VoIP Fraud": {
        "explanation": "SIP trunk abuse detected with high-volume outbound calls to premium-rate international destinations, consistent with toll fraud.",
        "impact": "Significant financial loss to customer and ISP from fraudulent international calls billed at peak rates; SIP trunk suspension required.",
        "mitigation": "Implement real-time call anomaly detection. Set per-customer concurrent call limits. Block calls to high-fraud destination prefixes. Alert customer immediately."
    },
    "TDoS Attack": {
        "explanation": "Telephony Denial of Service detected with excessive inbound call volume targeting a customer PBX, exhausting call capacity.",
        "impact": "Legitimate inbound calls blocked, customer phone system unavailable, and potential emergency services disruption.",
        "mitigation": "Implement SIP rate limiting and call admission control. Block originating SIP traffic at the ISP SBC. Engage upstream carrier for source blocking."
    },
    "Eavesdropping": {
        "explanation": "Malformed SIP INVITE packets or unexpected mid-call recording signatures detected, indicating a VoIP call interception attempt.",
        "impact": "Unauthorized recording of customer voice communications, violating privacy regulations (GDPR, CCPA) and wiretapping laws.",
        "mitigation": "Enforce SIP TLS and SRTP encryption for all VoIP sessions. Audit SBC access logs. Deploy SIP anomaly detection at the ISP voice infrastructure."
    },
    # ── IoT & SMART HOME ─────────────────────────────────────
    "IoT Botnet": {
        "explanation": "Customer IoT device infected with Mirai or similar botnet malware, exploiting default credentials to join a C2-controlled botnet.",
        "impact": "Customer device used as a DDoS amplifier or attack origin, contributing to attacks against third parties through the ISP network.",
        "mitigation": "Notify customer of device compromise. Block outbound C2 traffic for known botnet infrastructure. Recommend device firmware update or factory reset."
    },
    "Smart Home Abuse": {
        "explanation": "Unauthorized access to a customer IoT hub or smart home controller detected from an external source.",
        "impact": "Compromise of customer physical security systems (locks, cameras, alarms) and potential privacy violations.",
        "mitigation": "Alert customer immediately. Block inbound traffic to customer IoT hub ports. Recommend customer change hub credentials and enable 2FA."
    },
    "CCTV Camera Compromise": {
        "explanation": "Unauthorized access to a customer CCTV camera feed detected, likely via default credentials or known firmware vulnerability.",
        "impact": "Real-time surveillance of customer premises by unauthorized parties; significant privacy violation.",
        "mitigation": "Notify customer of camera compromise. Block inbound RTSP/HTTP traffic to camera IPs. Recommend firmware update and credential change."
    },
    "Smart Meter Tampering": {
        "explanation": "Anomalous power consumption data or unexpected meter communication patterns detected, consistent with meter tampering or energy theft.",
        "impact": "Revenue loss from energy theft; potential safety hazard from unauthorized meter modifications.",
        "mitigation": "Flag account for physical inspection. Alert utility billing team. Monitor for repeated anomalies and escalate to regulatory authorities if confirmed."
    },
    # ── DEFENSE EVASION / PERSISTENCE ────────────────────────
    "Firewall / Security Control Disabled": {
        "explanation": "Firewall flush or security service disable command detected on a network-connected device.",
        "impact": "All inbound and outbound network restrictions removed, exposing the device and connected network to direct attack.",
        "mitigation": "Re-enable firewall immediately. Investigate how the command was executed. Review administrative access logs for unauthorized activity."
    },
    "SSH Key / Authorized Keys Tampering": {
        "explanation": "Modification of SSH authorized_keys file detected, potentially adding an attacker's public key for persistent backdoor access.",
        "impact": "Persistent SSH access for the attacker even after password changes, enabling long-term presence on the compromised system.",
        "mitigation": "Review and purge unauthorized SSH keys. Implement file integrity monitoring on ~/.ssh. Restrict key-based authentication to approved keys only."
    },
    "API Abuse / Scraping": {
        "explanation": "Automated high-rate API requests or scraping activity detected exceeding normal usage thresholds.",
        "impact": "API backend resource exhaustion, rate limit triggering, and potential harvesting of customer or service data.",
        "mitigation": "Enforce per-IP and per-account API rate limits. Deploy CAPTCHA or bot detection for unauthenticated endpoints. Block scraping user-agent signatures."
    },
    # Legacy fallback entries kept for backward compatibility
    "SQL Injection": {
        "explanation": "SQL injection signature matched (non-ISP context). This entry is preserved for backward compatibility.",
        "impact": "Potential exposure of database content or authentication bypass.",
        "mitigation": "Use parameterized queries and apply strict input sanitization."
    },
    "Exploit Attempt": {
        "explanation": "Active exploitation of a known vulnerability confirmed by direct evidence: IDS exploit signature, malicious payload delivery, JNDI/RCE callback, shell spawn, privilege escalation, or command execution. Passive CVE references and scanner findings are classified separately as vulnerability findings and do not trigger this alert.",
        "impact": "Potential system compromise, remote code execution, or service takeover by an active adversary.",
        "mitigation": "Isolate the affected host immediately. Capture memory and network forensics. Apply emergency patches and rotate all credentials accessible from the compromised endpoint."
    },
}

_LEGACY_THREAT_DETAILS_REMOVED = True  # Old web-app entries replaced with ISP-specific content above

# ── CATEGORY DETAILS (ISP-focused) ──────────────────────────────────────────
CATEGORY_DETAILS = {
    "Network Reconnaissance": {
        "explanation": "Network scanning or service enumeration activity detected against ISP-managed IP space.",
        "impact": "Adversary-obtained knowledge of open services and network topology, enabling targeted follow-on attacks.",
        "mitigation": "Deploy IDS to detect scan patterns. Block scanning IPs at edge routers. Limit service exposure."
    },
    "DDoS Attack": {
        "explanation": "Volumetric or protocol-based denial-of-service attack targeting ISP infrastructure or customers.",
        "impact": "Service unavailability, backbone saturation, and SLA violations affecting all ISP subscribers.",
        "mitigation": "Activate DDoS scrubbing. Apply BGP blackholing. Implement rate limiting at peering points."
    },
    "DNS Attack": {
        "explanation": "Attack targeting ISP DNS infrastructure via tunneling, cache poisoning, or amplification.",
        "impact": "DNS service disruption, customer traffic redirection, or covert data exfiltration via DNS.",
        "mitigation": "Enable DNSSEC, DNS rate limiting (RRL), and anomalous query pattern detection."
    },
    "Botnet Activity": {
        "explanation": "C2 beacon, botnet communication, or cryptomining traffic detected from a customer device.",
        "impact": "Customer device used as attack origin; ISP network associated with malicious botnet infrastructure.",
        "mitigation": "Block C2 infrastructure. Notify customer. Apply threat intel blocklists at edge."
    },
    "Malware": {
        "explanation": "Malware distribution, ransomware, or fileless malware activity detected on ISP-connected device.",
        "impact": "Data encryption, device compromise, or ISP network used as malware distribution point.",
        "mitigation": "Null-route offending IP. Alert customer. Require device remediation before restoration."
    },
    "Data Exfiltration": {
        "explanation": "Large-volume outbound data transfer or database dump inconsistent with normal traffic baseline.",
        "impact": "Loss of sensitive customer data or proprietary business records through the ISP network.",
        "mitigation": "Enforce egress anomaly alerting. Block destination. Notify customer for investigation."
    },
    "Phishing & Credential Theft": {
        "explanation": "Phishing kit hosting, credential dumping, or credential exposure detected on or through ISP network.",
        "impact": "Customer credential compromise, enabling account takeover and fraudulent service usage.",
        "mitigation": "Take down phishing infrastructure. Rotate compromised credentials. Enable MFA."
    },
    "Network Infrastructure": {
        "explanation": "BGP hijacking, ARP spoofing, MitM, or router compromise targeting ISP routing infrastructure.",
        "impact": "Traffic interception, routing manipulation, or complete loss of routing for customer segments.",
        "mitigation": "Implement RPKI, DAI, and out-of-band management. Alert NOC immediately."
    },
    "ISP Abuse": {
        "explanation": "Spam campaigns, proxy abuse, copyright infringement, or account sharing detected from customer IP.",
        "impact": "ISP IP reputation damage, legal liability, and AUP violations.",
        "mitigation": "Enforce AUP. Notify customer. Apply traffic controls per policy."
    },
    "VoIP & Telephony": {
        "explanation": "VoIP fraud, TDoS, or SIP attack targeting customer or ISP telephony infrastructure.",
        "impact": "Fraudulent call charges, customer phone unavailability, and potential emergency service disruption.",
        "mitigation": "Implement SIP rate limiting and call admission control. Block fraudulent destination prefixes."
    },
    "IoT & Smart Home": {
        "explanation": "IoT botnet infection, unauthorized camera access, or smart meter tampering detected.",
        "impact": "Customer device compromise, privacy violations, and ISP network used for botnet DDoS.",
        "mitigation": "Notify customer. Block C2 traffic. Recommend device firmware updates and credential changes."
    },
    "Defense Evasion": {
        "explanation": "Firewall disable or SSH key tampering detected on a network-connected device.",
        "impact": "All network protections removed, enabling persistent attacker access.",
        "mitigation": "Re-enable controls immediately. Investigate unauthorized command execution. Review admin access logs."
    },
    "Network Abuse": {
        "explanation": "API abuse, scraping, or unauthorized automated network activity detected.",
        "impact": "Service resource exhaustion, data harvesting, or network policy violations.",
        "mitigation": "Apply rate limits and bot detection. Block abusive sources. Enforce AUP."
    },
    "Persistence": {
        "explanation": "SSH key modification or backdoor installation detected, enabling persistent attacker access.",
        "impact": "Long-term unauthorized access maintained even after initial remediation attempts.",
        "mitigation": "Audit and purge unauthorized access credentials. Enable file integrity monitoring."
    },
}

