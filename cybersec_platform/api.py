"""REST API blueprint for the enterprise cybersecurity analytics platform."""

from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta

from .database import SessionLocal, Alert, SystemHealth, LogEntry, Vulnerability
from .config import Config
from .ingestion import LogIngestor
from .feature_engineering import aggregate_window, extract_features
from .predictive_analytics import PredictiveAnalytics
from .sonar_analyzer import SonarAnalyzer
from .vulnerability_assessment import VulnerabilityAssessment

api = Blueprint("api", __name__, url_prefix="/api")

_config = Config()
_ingestor = LogIngestor(_config)
_ingestor.start()

@api.route("/start-ingestion", methods=["POST"])
def start_ingestion():
    
    _ingestor.start()
    return jsonify({"status": "Ingestion started"})

@api.route("/stop-ingestion", methods=["POST"])
def stop_ingestion():
    """Stop the background data ingestion loop."""
    _ingestor.stop()
    return jsonify({"status": "Ingestion stopped"})

def _persist_vulnerability_findings(db, findings):
    """Persist any new CVE findings to the vulnerability database table."""
    updated = False
    for finding in findings:
        cve_id = finding.get("cve_id")
        if not cve_id:
            continue

        existing = db.query(Vulnerability).filter_by(cve_id=cve_id).first()
        if existing:
            if (
                existing.description != finding.get("description") or
                existing.cvss_score != finding.get("cvss_score") or
                existing.severity != finding.get("severity") or
                existing.mitigation != finding.get("mitigation")
            ):
                existing.description = finding.get("description")
                existing.cvss_score = finding.get("cvss_score", existing.cvss_score)
                existing.severity = finding.get("severity", existing.severity)
                existing.mitigation = finding.get("mitigation", existing.mitigation)
                updated = True
        else:
            db.add(Vulnerability(
                cve_id=cve_id,
                description=finding.get("description", ""),
                cvss_score=finding.get("cvss_score", 0.0),
                severity=finding.get("severity", "Unknown"),
                mitigation=finding.get("mitigation", "N/A")
            ))
            updated = True

    if updated:
        db.commit()


def _build_vulnerability_summary(db):
    vulnerabilities = db.query(Vulnerability).order_by(Vulnerability.cvss_score.desc()).all()
    findings = [{
        "cve_id": v.cve_id,
        "title": v.description,
        "description": v.description,
        "severity": v.severity,
        "mitigation": v.mitigation,
        "cvss_score": v.cvss_score
    } for v in vulnerabilities]

    overall_risk_score = min(100.0, sum(v.cvss_score * 3.0 for v in vulnerabilities))
    risk_level = (
        "Critical" if overall_risk_score > 80 else
        "High" if overall_risk_score > 60 else
        "Medium" if overall_risk_score > 30 else
        "Low"
    )

    return {
        "findings": findings,
        "overall_risk_score": round(overall_risk_score, 1),
        "risk_level": risk_level
    }


@api.route("/dashboard", methods=["GET"])
def get_dashboard_data():
    """Fetch live data from the database to populate the frontend dashboard."""
    db = SessionLocal()
    try:
        now = datetime.utcnow()

        # Get time range from query parameter (default to 60 minutes)
        time_range_minutes = request.args.get('time_range', 60, type=int)
        time_range_start = now - timedelta(minutes=time_range_minutes)

        # Get all recent alerts for filtering
        recent_alerts_query = db.query(Alert).order_by(Alert.timestamp.desc()).limit(50).all()
        
        # Separate security threats from conditions
        security_alerts = []
        condition_alerts = []
        seen_alerts = set()  # For deduplication
        
        for a in recent_alerts_query:
            # Create unique key for deduplication
            alert_key = (a.alert_type, a.source_ip, a.severity)
            
            # Skip if already seen (deduplication)
            if alert_key in seen_alerts:
                continue
            seen_alerts.add(alert_key)
            
            # Check if this is a security threat (threat_status is SUSPICIOUS or CONFIRMED)
            # For backward compatibility, if threat_status is not set, check MITRE tactic
            threat_status = getattr(a, 'threat_status', None)
            mitre_tactic = a.mitre_tactic
            
            is_security_threat = False
            if threat_status in ['SUSPICIOUS', 'CONFIRMED']:
                is_security_threat = True
            elif threat_status is None and mitre_tactic and mitre_tactic != 'NOT APPLICABLE':
                is_security_threat = True
            elif threat_status is None and mitre_tactic is None:
                # Legacy: assume it's a threat if it has a MITRE tactic or high severity
                is_security_threat = a.severity in ['high', 'critical']
            
            alert_data = {
                "id": a.id,
                "timestamp": a.timestamp.isoformat() + "Z",
                "type": a.alert_type,
                "severity": a.severity,
                "description": a.description,
                "source_ip": a.source_ip,
                "mitre": a.mitre_tactic,
                "ai_summary": getattr(a, "ai_summary", None),
                "domain": getattr(a, 'domain', 'SECURITY_THREATS'),
                "classification_type": getattr(a, 'classification_type', 'Threat'),
                "threat_status": getattr(a, 'threat_status', 'CONFIRMED' if is_security_threat else 'NONE')
            }
            
            if is_security_threat:
                security_alerts.append(alert_data)
            else:
                condition_alerts.append(alert_data)
        
        # Limit to 15 security threats for live threats display
        live_threats = security_alerts[:15]

        recent_health = db.query(SystemHealth).order_by(SystemHealth.timestamp.desc()).limit(1).first()
        system_health = {
            "cpu_usage": recent_health.cpu_usage if recent_health else 0,
            "memory_usage": recent_health.memory_usage if recent_health else 0,
            "active_connections": recent_health.active_connections if recent_health else 0
        }

        # Build attack timeline - only include security threats
        alerts_in_range = db.query(Alert).filter(Alert.timestamp >= time_range_start).all()
        timeline_dict = {}
        for a in alerts_in_range:
            # Filter to only security threats
            threat_status = getattr(a, 'threat_status', None)
            mitre_tactic = a.mitre_tactic
            
            is_security_threat = False
            if threat_status in ['SUSPICIOUS', 'CONFIRMED']:
                is_security_threat = True
            elif threat_status is None and mitre_tactic and mitre_tactic != 'NOT APPLICABLE':
                is_security_threat = True
            elif threat_status is None and mitre_tactic is None:
                is_security_threat = a.severity in ['high', 'critical']
            
            if not is_security_threat:
                continue
            
            minute_key = a.timestamp.strftime("%Y-%m-%dT%H:%M:00Z")
            if minute_key not in timeline_dict:
                timeline_dict[minute_key] = {"count": 0, "threats": []}
            timeline_dict[minute_key]["count"] += 1
            timeline_dict[minute_key]["threats"].append({
                "type": a.alert_type,
                "severity": a.severity,
                "source_ip": a.source_ip,
                "mitre": a.mitre_tactic
            })

        attack_timeline = [{"time": k, "count": v["count"], "threats": v["threats"]} for k, v in sorted(timeline_dict.items())]
        
        
        recent_logs = db.query(LogEntry).filter(LogEntry.timestamp >= time_range_start).all()
        features = [extract_features(l.message) for l in recent_logs]
        assessment = VulnerabilityAssessment().assess(features)
        _persist_vulnerability_findings(db, assessment["findings"])
        vulnerability_summary = assessment
        predictive = PredictiveAnalytics().predict_risk()
        
        # Calculate aggregate threat probability only from security threats
        if security_alerts:
            total_confidence = sum(a.get('confidence', 0) for a in security_alerts if a.get('confidence'))
            avg_threat_probability = (total_confidence / len(security_alerts)) * 100 if security_alerts else 0
        else:
            avg_threat_probability = 0
        
        return jsonify({
            "live_threats": live_threats,
            "conditions": condition_alerts[:10],  # Include conditions separately
            "system_health": system_health,
            "attack_timeline": attack_timeline,
            "vulnerability_summary": vulnerability_summary,
            "predictive_risk": predictive,
            "aggregate_threat_probability": round(avg_threat_probability, 1),
            "security_threat_count": len(security_alerts),
            "condition_count": len(condition_alerts)
        })
    finally:
        db.close()

@api.route("/scan", methods=["POST"])
def manual_scan():
    """Manual log scan endpoint for debugging."""
    from .threat_detection import ThreatDetector
    import logging
    
    logger = logging.getLogger(__name__)
    
    log_text = request.json.get("log_text", "") if request.is_json else ""
    if not log_text:
        return jsonify({"error": "No log_text provided"}), 400

    lines = [line.strip() for line in log_text.splitlines() if line.strip()] or [log_text.strip()]
    from .parsing import normalize_log_entry
    features = [extract_features(normalize_log_entry(line)) for line in lines]

    import sys
    print(f"[SCAN] {len(lines)} lines parsed, first fmt={features[0].get('format') if features else '?'}", flush=True, file=sys.stderr)
    
    detector = ThreatDetector()
    all_detections = detector.detect(features)
    assessment = VulnerabilityAssessment().assess(features)
    ml_analysis = detector.local_analyze_log(log_text)

    # Separate security threats from conditions and deduplicate
    security_threats = []
    conditions = []
    seen_threats = set()
    seen_conditions = set()
    
    for detection in all_detections:
        threat_status = detection.get('threat_status', 'NONE')
        domain = detection.get('domain', 'SECURITY_THREATS')
        classification_type = detection.get('classification_type', 'Threat')
        
        # Create deduplication key
        dedup_key = (
            detection.get('threat_type', ''),
            detection.get('source_ip', ''),
            detection.get('severity', ''),
            threat_status
        )
        
        # Check if this is a threat or compliance violation (not a condition)
        is_threat_or_compliance = (
            (threat_status in ['SUSPICIOUS', 'CONFIRMED'] and domain == 'SECURITY_THREATS') or
            (classification_type in ['Threat', 'Classification'] and domain in ['SECURITY_THREATS', 'COMPLIANCE'])
        )
        
        if is_threat_or_compliance:
            # This is a genuine security threat or compliance violation
            if dedup_key not in seen_threats:
                seen_threats.add(dedup_key)
                security_threats.append(detection)
        elif classification_type == 'Condition' or threat_status == 'NONE':
            # This is a condition, not a security threat
            if dedup_key not in seen_conditions:
                seen_conditions.add(dedup_key)
                conditions.append(detection)
    
    # Calculate aggregate threat probability from security threats only
    if security_threats:
        total_confidence = sum(t.get('confidence', 0) for t in security_threats)
        avg_threat_probability = int(round((total_confidence / len(security_threats)) * 100))
        
        # Generate threat summary
        unique_threats = list(dict.fromkeys(t['threat_type'] for t in security_threats))
        if len(unique_threats) == 1:
            threat_summary = f"Security threat '{unique_threats[0]}' detected in logs."
        else:
            threat_summary = f"Multiple security threats detected: {', '.join(unique_threats)}."
    else:
        avg_threat_probability = 0
        threat_summary = "No threats detected. Log entries match normal ISP activity patterns."
    
    # Update ml_analysis to reflect only security threats
    ml_analysis['probability'] = avg_threat_probability
    ml_analysis['reason'] = threat_summary
    ml_analysis['status'] = 'threat' if security_threats else 'clean'
    ml_analysis['security_threat_count'] = len(security_threats)
    ml_analysis['condition_count'] = len(conditions)

    db = SessionLocal()
    try:
        # Record the manual scanned log entry in the database
        entry = LogEntry(message=log_text, source="manual", level="INFO")
        db.add(entry)
        _persist_vulnerability_findings(db, assessment["findings"])
    finally:
        db.close()
    
    return jsonify({
        "detections": security_threats,
        "conditions": conditions,
        "assessment": assessment,
        "aggregate": aggregate_window(features),
        "llama_analysis": ml_analysis,
        "ml_analysis": ml_analysis,
        "security_threat_count": len(security_threats),
        "condition_count": len(conditions),
        "debug": {
            "lines_parsed": len(lines),
            "first_fmt": features[0].get("format") if features else None,
            "all_detections_raw": len(all_detections)
        }
    })

@api.route("/upload-code", methods=["POST"])
def upload_code():
    """Accept a source code file upload and run Sonar-like analysis."""
    analyzer = SonarAnalyzer()
    if "code_file" not in request.files:
        return jsonify({"error": "No code_file uploaded."}), 400

    file = request.files["code_file"]
    filename = file.filename or "uploaded_code"
    try:
        content = file.read().decode("utf-8", errors="replace")
    except Exception as e:
        return jsonify({"error": f"Unable to read uploaded file: {e}"}), 400

    report = analyzer.analyze_code(filename, content)
    return jsonify(report)


@api.route("/export/vulnerabilities", methods=["GET"])
def export_vulnerabilities_csv():
    """Export persisted vulnerability findings to a CSV file."""
    import csv
    from io import StringIO
    from flask import Response

    db = SessionLocal()
    try:
        vulnerabilities = db.query(Vulnerability).order_by(Vulnerability.cvss_score.desc()).all()
        output = StringIO()
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(["CVE ID", "Description", "CVSS Score", "Severity", "Mitigation"])
        for v in vulnerabilities:
            writer.writerow([
                v.cve_id or "",
                v.description or "",
                f"{v.cvss_score:.1f}" if v.cvss_score is not None else "",
                v.severity or "",
                v.mitigation or ""
            ])

        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=vulnerabilities_export.csv"}
        )
    finally:
        db.close()

@api.route("/export/excel", methods=["GET"])
def export_excel():
    """Export all threat alerts to an Excel file."""
    from .database import SessionLocal, Alert
    import pandas as pd
    from io import BytesIO
    from flask import send_file

    db = SessionLocal()
    try:
        alerts = db.query(Alert).order_by(Alert.timestamp.desc()).all()
        data = [{
            "Timestamp": a.timestamp.isoformat() + "Z",
            "Threat Type": a.alert_type,
            "Severity": a.severity,
            "Source IP": a.source_ip,
            "Confidence": f"{a.confidence:.2f}",
            "MITRE Tactic": a.mitre_tactic,
            "AI Analysis": a.ai_summary or "N/A",
            "Raw Description": a.description
        } for a in alerts]

        df = pd.DataFrame(data)
        
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Threat Alerts')
            
        output.seek(0)
        
        return send_file(
            output,
            download_name="security_alerts_export.xlsx",
            as_attachment=True,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()
