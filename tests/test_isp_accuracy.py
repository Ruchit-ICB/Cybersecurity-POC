"""ISP log threat detection accuracy tests."""

import random
from datetime import datetime, timedelta, timezone

import pytest

from cybersec_platform.feature_engineering import extract_features
from cybersec_platform.integrations import ATTACK_TEMPLATES, BENIGN_TEMPLATES
from cybersec_platform.parsing import normalize_log_entry
from cybersec_platform.threat_detection import ThreatDetector


def _generate_test_logs(num_attacks=100, num_benign=100, seed=42):
    """Generate ISP logs with known ground truth."""
    rng = random.Random(seed)
    logs = []
    now = datetime.now(timezone.utc)

    for _ in range(num_attacks):
        dt = now - timedelta(seconds=rng.randint(0, 3600))
        template = rng.choice(ATTACK_TEMPLATES)
        ip = f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        logs.append({"log": template(ip, dt), "is_attack": True})

    for _ in range(num_benign):
        dt = now - timedelta(seconds=rng.randint(0, 3600))
        template = rng.choice(BENIGN_TEMPLATES)
        ip = f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        logs.append({"log": template(ip, dt), "is_attack": False})

    rng.shuffle(logs)
    return logs


def _evaluate_logs(test_logs):
    detector = ThreatDetector()
    tp = fp = tn = fn = 0

    for log_data in test_logs:
        parsed = normalize_log_entry(log_data["log"])
        features = extract_features(parsed)
        detected = bool(detector.detect([features]))
        is_attack = log_data["is_attack"]

        if detected and is_attack:
            tp += 1
        elif detected and not is_attack:
            fp += 1
        elif not detected and not is_attack:
            tn += 1
        else:
            fn += 1

    total = len(test_logs)
    accuracy = (tp + tn) / total if total else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / sum(1 for log in test_logs if log["is_attack"]) if test_logs else 0
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
    }


def test_isp_threat_detection_accuracy():
    """All ISP attack templates should be detected; benign logs should pass."""
    results = _evaluate_logs(_generate_test_logs())

    assert results["true_positives"] == 100
    assert results["false_positives"] == 0
    assert results["true_negatives"] == 100
    assert results["false_negatives"] == 0
    assert results["accuracy"] == pytest.approx(1.0)
    assert results["precision"] == pytest.approx(1.0)
    assert results["recall"] == pytest.approx(1.0)


def test_isp_classifier_detects_sample_threats():
    """Lightweight classifier should flag known ISP threat lines in sample logs."""
    from cybersec_platform.classifier import (
        SimpleLogClassifier,
        analyze_log_text,
        create_sample_log_text,
        summarize_findings,
    )

    findings = analyze_log_text(create_sample_log_text(), SimpleLogClassifier())
    summary = summarize_findings(findings)

    assert summary["total_lines"] == 12
    assert summary["ml_benign_count"] == 3
    assert summary["ml_threat_count"] == 9
    assert summary["threat_indicator_count"] >= 8


def test_benign_logs_report_zero_threat_probability():
    """Clean ISP logs should report NONE threat status, 0 confidence."""
    detector = ThreatDetector()
    now = datetime.now(timezone.utc)

    for template in BENIGN_TEMPLATES:
        log = template("192.168.1.1", now)
        analysis = detector.local_analyze_log(log)
        assert analysis["threat_status"] == "NONE"
        assert analysis["confidence"] == 0.0


def test_attack_logs_report_high_threat_probability():
    """Detected ISP attacks should report SUSPICIOUS or CONFIRMED status."""        
    detector = ThreatDetector()
    now = datetime.now(timezone.utc)

    for template in ATTACK_TEMPLATES:
        log = template("10.0.0.1", now)
        analysis = detector.local_analyze_log(log)
        assert analysis["threat_status"] in ["SUSPICIOUS", "CONFIRMED"]
        assert analysis["confidence"] >= 0.70


def test_failed_ssh_login_is_detected():
    """Common manual-scan placeholder logs should be detected as threat."""
    detector = ThreatDetector()
    log = (
        '{"timestamp": "2026-06-24T12:00:00Z", "level": "WARN", '
        '"message": "Failed SSH login from 192.168.1.50"}'
    )
    analysis = detector.local_analyze_log(log)
    assert analysis["threat_status"] in ["SUSPICIOUS", "CONFIRMED"]
    assert analysis["confidence"] >= 0.70
