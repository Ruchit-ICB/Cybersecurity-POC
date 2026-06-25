"""REST API blueprint for the enterprise cybersecurity analytics platform."""

from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta

from .database import SessionLocal, Alert, SystemHealth, LogEntry, Vulnerability
from .config import Config
from .ingestion import LogIngestor
from .feature_engineering import aggregate_window, extract_features
from .predictive_analytics import PredictiveAnalytics
from .vulnerability_assessment import VulnerabilityAssessment

api = Blueprint("api", __name__, url_prefix="/api")

_config = Config()
_ingestor = LogIngestor(_config)

@api.route("/start-ingestion", methods=["POST"])
def start_ingestion():
    """Start the background data ingestion loop."""
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
        one_hour_ago = now - timedelta(hours=1)
        
        
        recent_alerts_query = db.query(Alert).order_by(Alert.timestamp.desc()).limit(15).all()
        live_threats = [{
            "id": a.id,
            "timestamp": a.timestamp.isoformat() + "Z",
            "type": a.alert_type,
            "severity": a.severity,
            "description": a.description,
            "source_ip": a.source_ip,
            "mitre": a.mitre_tactic,
            "gemini_summary": getattr(a, "gemini_summary", None)
        } for a in recent_alerts_query]
        
        
        recent_health = db.query(SystemHealth).order_by(SystemHealth.timestamp.desc()).limit(1).first()
        system_health = {
            "cpu_usage": recent_health.cpu_usage if recent_health else 0,
            "memory_usage": recent_health.memory_usage if recent_health else 0,
            "active_connections": recent_health.active_connections if recent_health else 0
        }
        
        
        alerts_last_hour = db.query(Alert).filter(Alert.timestamp >= one_hour_ago).all()
        timeline_dict = {}
        for a in alerts_last_hour:
            minute_key = a.timestamp.strftime("%Y-%m-%dT%H:%M:00Z")
            timeline_dict[minute_key] = timeline_dict.get(minute_key, 0) + 1
            
        attack_timeline = [{"time": k, "count": v} for k, v in sorted(timeline_dict.items())]
        
        
        recent_logs = db.query(LogEntry).order_by(LogEntry.timestamp.desc()).limit(100).all()
        features = [extract_features(l.message) for l in recent_logs]
        assessment = VulnerabilityAssessment().assess(features)
        _persist_vulnerability_findings(db, assessment["findings"])
        vulnerability_summary = _build_vulnerability_summary(db)
        predictive = PredictiveAnalytics().predict_risk()
        
        return jsonify({
            "live_threats": live_threats,
            "system_health": system_health,
            "attack_timeline": attack_timeline,
            "vulnerability_summary": vulnerability_summary,
            "predictive_risk": predictive
        })
    finally:
        db.close()

@api.route("/scan", methods=["POST"])
def manual_scan():
    """Manual log scan endpoint for debugging."""
    from .threat_detection import ThreatDetector
    from .gemini_client import GeminiAnalyzer
    
    log_text = request.json.get("log_text", "") if request.is_json else ""
    if not log_text:
        return jsonify({"error": "No log_text provided"}), 400
        
    entries = [log_text]
    features = [extract_features(entry) for entry in entries]
    
    detections = ThreatDetector().detect(features)
    assessment = VulnerabilityAssessment().assess(features)
    gemini_analysis = GeminiAnalyzer().analyze_log(log_text)

    db = SessionLocal()
    try:
        _persist_vulnerability_findings(db, assessment["findings"])
    finally:
        db.close()
    
    return jsonify({
        "detections": detections,
        "assessment": assessment,
        "aggregate": aggregate_window(features),
        "gemini_analysis": gemini_analysis
    })

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
            "AI Analysis": a.gemini_summary or "N/A",
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
