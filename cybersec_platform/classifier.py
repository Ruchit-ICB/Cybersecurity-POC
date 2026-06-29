"""Lightweight Naive Bayes log classifier and rule-based indicator detection.

This module provides the core analysis engine used by both the web frontend
and the CLI.  It intentionally avoids heavy dependencies (no scikit-learn)
so the CLI can work without installing the full ML stack.
"""

import math
import re
from collections import Counter
from typing import Any, Dict, List, Tuple

# ---------------------------------------------------------------------------
# Rule-based indicator patterns
# ---------------------------------------------------------------------------

INDICATOR_PATTERNS = [
    {
        "name": "DDoS Attack",
        "pattern": re.compile(
            r"\b(syn flood|udp flood|http flood|ddos detected|amplification attack|volumetric attack)\b",
            re.IGNORECASE,
        ),
        "severity": "critical",
        "type": "threat",
    },
    {
        "name": "DNS Attack",
        "pattern": re.compile(
            r"\b(dns tunnel|dns cache poisoning|dns water torture|nxdomain flood|dns exfil)\b",
            re.IGNORECASE,
        ),
        "severity": "high",
        "type": "threat",
    },
    {
        "name": "Botnet Activity",
        "pattern": re.compile(
            r"\b(c2 beacon|botnet activity|mirai botnet|reverse shell|backdoor|tor exit node)\b",
            re.IGNORECASE,
        ),
        "severity": "critical",
        "type": "threat",
    },
    {
        "name": "Malware Distribution",
        "pattern": re.compile(
            r"\b(malware distribution|ransomware|worm propagation|eternalblue|wannacry|fileless malware)\b",
            re.IGNORECASE,
        ),
        "severity": "critical",
        "type": "threat",
    },
    {
        "name": "Data Exfiltration",
        "pattern": re.compile(
            r"\b(data exfiltration|large file transfer|covert channel|steganography|icmp tunneling)\b",
            re.IGNORECASE,
        ),
        "severity": "critical",
        "type": "threat",
    },
    {
        "name": "Phishing Attack",
        "pattern": re.compile(
            r"\b(phishing kit|credential harvesting|password spraying|credential dumping)\b",
            re.IGNORECASE,
        ),
        "severity": "high",
        "type": "threat",
    },
    {
        "name": "Network Infrastructure Attack",
        "pattern": re.compile(
            r"\b(bgp hijacking|arp poison|arp spoof|router compromise|mitm)\b",
            re.IGNORECASE,
        ),
        "severity": "critical",
        "type": "threat",
    },
    {
        "name": "ISP Abuse",
        "pattern": re.compile(
            r"\b(spam campaign|proxy abuse|copyright infringement|account sharing|port forwarding abuse)\b",
            re.IGNORECASE,
        ),
        "severity": "medium",
        "type": "threat",
    },
    {
        "name": "VoIP Attack",
        "pattern": re.compile(
            r"\b(voip fraud|tdos attack|sip registration attack|eavesdropping)\b",
            re.IGNORECASE,
        ),
        "severity": "critical",
        "type": "threat",
    },
    {
        "name": "IoT Attack",
        "pattern": re.compile(
            r"\b(iot botnet|smart home abuse|cctv camera compromise|smart meter tampering)\b",
            re.IGNORECASE,
        ),
        "severity": "high",
        "type": "threat",
    },
    {
        "name": "Port Scanning",
        "pattern": re.compile(
            r"\b(nmap|masscan|port scan|syn scan|service enumeration|snmp brute force)\b",
            re.IGNORECASE,
        ),
        "severity": "medium",
        "type": "threat",
    },
]

LOG_LINE_REGEX = re.compile(
    r"^(?P<timestamp>\S+)\s+(?P<level>\S+)\s+(?P<source>\S+)\s+-\s+(?P<message>.*)$"
)


# ---------------------------------------------------------------------------
# Naive Bayes classifier
# ---------------------------------------------------------------------------


class SimpleLogClassifier:
    """A lightweight Naive Bayes classifier for log-line classification."""

    def __init__(self) -> None:
        self.labels: List[str] = ["benign", "vulnerability", "threat"]
        self.vocab: set = set()
        self.word_counts: Dict[str, Counter] = {
            label: Counter() for label in self.labels
        }
        self.class_counts: Counter = Counter()
        self.total_words: Dict[str, int] = {label: 0 for label in self.labels}
        self.total_examples: int = 0
        self._train()

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        tokens = re.findall(r"[a-zA-Z0-9_]+", text.lower())
        return [t for t in tokens if len(t) > 1]

    # -- training ------------------------------------------------------------

    def _train(self) -> None:
        training_examples = [
            ("DHCP lease assigned to customer", "benign"),
            ("DNS query resolved successfully", "benign"),
            ("BGP route update received", "benign"),
            ("Connection allowed by firewall", "benign"),
            ("Bandwidth usage normal", "benign"),
            ("SIP call established", "benign"),
            ("ICMP ping response", "benign"),
            ("HTTP proxy request completed", "benign"),
            ("SMTP connection established", "benign"),
            ("IoT device heartbeat", "benign"),
            ("DDoS SYN flood detected", "threat"),
            ("DNS tunneling detected", "threat"),
            ("C2 beacon callback", "threat"),
            ("Mirai botnet activity", "threat"),
            ("Ransomware encryption detected", "threat"),
            ("Data exfiltration detected", "threat"),
            ("Phishing kit detected", "threat"),
            ("BGP hijacking attempt", "threat"),
            ("Spam campaign detected", "threat"),
            ("VoIP fraud detected", "threat"),
            ("IoT botnet infection", "threat"),
            ("Port scan detected", "threat"),
        ]

        for text, label in training_examples:
            self.class_counts[label] += 1
            tokens = self._tokenize(text)
            self.total_words[label] += len(tokens)
            for token in tokens:
                self.vocab.add(token)
                self.word_counts[label][token] += 1

        self.total_examples = sum(self.class_counts.values())

    # -- inference -----------------------------------------------------------

    def predict(self, text: str) -> Tuple[str, float]:
        tokens = self._tokenize(text)
        if not tokens:
            return "benign", 0.0

        label_scores: Dict[str, float] = {}
        vocab_size = max(len(self.vocab), 1)

        for label in self.labels:
            prior = (self.class_counts[label] + 1) / (
                self.total_examples + len(self.labels)
            )
            log_score = math.log(prior)
            for token in tokens:
                token_count = self.word_counts[label].get(token, 0)
                token_prob = (token_count + 1) / (
                    self.total_words[label] + vocab_size
                )
                log_score += math.log(token_prob)
            label_scores[label] = log_score

        best_label = max(label_scores, key=label_scores.get)  # type: ignore[arg-type]
        confidence = self._softmax_confidence(label_scores, best_label)
        return best_label, confidence

    def _softmax_confidence(
        self, scores: Dict[str, float], best_label: str
    ) -> float:
        # Subtract max for numerical stability (prevents exp overflow).
        max_score = max(scores.values())
        exp_scores = [math.exp(v - max_score) for v in scores.values()]
        total = sum(exp_scores)
        if total <= 0:
            return 0.0
        return exp_scores[self.labels.index(best_label)] / total


# ---------------------------------------------------------------------------
# Log parsing & analysis helpers
# ---------------------------------------------------------------------------


def parse_log_line(line: str) -> Dict[str, Any]:
    """Parse a single log line into its components."""
    match = LOG_LINE_REGEX.match(line.strip())
    if not match:
        return {
            "raw": line.strip(),
            "timestamp": None,
            "level": None,
            "source": None,
            "message": line.strip(),
        }
    return {
        "raw": line.strip(),
        "timestamp": match.group("timestamp"),
        "level": match.group("level"),
        "source": match.group("source"),
        "message": match.group("message"),
    }


def detect_indicators(parsed_line: Dict[str, Any]) -> List[Dict[str, str]]:
    """Run rule-based indicator patterns against a parsed log line."""
    findings: List[Dict[str, str]] = []
    for pattern in INDICATOR_PATTERNS:
        if pattern["pattern"].search(parsed_line.get("message", "")):
            findings.append(
                {
                    "indicator": pattern["name"],
                    "severity": pattern["severity"],
                    "type": pattern["type"],
                }
            )
    return findings


def analyze_log_text(
    log_text: str, model: SimpleLogClassifier
) -> List[Dict[str, Any]]:
    """Analyse raw log text and return per-line findings."""
    findings: List[Dict[str, Any]] = []
    for line_number, raw_line in enumerate(
        log_text.strip().splitlines(), start=1
    ):
        if not raw_line.strip():
            continue
        parsed = parse_log_line(raw_line)
        ml_label, confidence = model.predict(parsed["message"])
        patterns = detect_indicators(parsed)
        findings.append(
            {
                "line_number": line_number,
                "timestamp": parsed["timestamp"],
                "level": parsed["level"],
                "source": parsed["source"],
                "message": parsed["message"],
                "ml_label": ml_label,
                "confidence": round(confidence, 2),
                "indicators": patterns,
            }
        )
    return findings


def summarize_findings(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Produce aggregate counts from a list of findings."""
    summary: Dict[str, int] = {
        "total_lines": len(findings),
        "ml_threat_count": 0,
        "ml_vulnerability_count": 0,
        "ml_benign_count": 0,
        "indicator_count": 0,
        "threat_indicator_count": 0,
        "vulnerability_indicator_count": 0,
    }
    for item in findings:
        key = f"ml_{item['ml_label']}_count"
        summary[key] = summary.get(key, 0) + 1
        if item["indicators"]:
            summary["indicator_count"] += len(item["indicators"])
            for indicator in item["indicators"]:
                if indicator["type"] == "threat":
                    summary["threat_indicator_count"] += 1
                elif indicator["type"] == "vulnerability":
                    summary["vulnerability_indicator_count"] += 1
    return summary


def create_sample_log_text() -> str:
    """Return a sample ISP log block for demo purposes."""
    return "\n".join(
        [
            '2026-06-24T11:14:22Z INFO dhcp - DHCP lease assigned to 192.168.1.100',
            '2026-06-24T11:15:00Z INFO dns - DNS query resolved for example.com',
            '2026-06-24T11:16:05Z INFO routing - BGP route update received for 192.0.2.0/24',
            '2026-06-24T11:17:42Z CRITICAL network - DDoS: SYN flood from 10.0.0.50 — 80,000 packets/second detected',
            '2026-06-24T11:18:14Z HIGH dns - DNS tunneling: unusually long DNS query from 10.0.0.75',
            '2026-06-24T11:19:33Z CRITICAL botnet - C2 beacon detected: reverse shell callback to 10.0.0.100',
            '2026-06-24T11:20:15Z CRITICAL malware - Ransomware encryption detected in customer network',
            '2026-06-24T11:21:00Z CRITICAL exfil - Data exfiltration detected: 2.4GB outbound transfer to 10.0.0.200',
            '2026-06-24T11:22:30Z HIGH phishing - Phishing kit detected: 10.0.0.150 hosting credential harvesting page',
            '2026-06-24T11:23:45Z CRITICAL bgp - BGP hijacking attempt: suspicious route announcement from 10.0.0.175',
            '2026-06-24T11:24:10Z HIGH voip - VoIP fraud: SIP trunk abuse from 10.0.0.225',
            '2026-06-24T11:25:00Z HIGH iot - IoT botnet: Mirai infection on customer device 10.0.0.250',
        ]
    )
