import logging
from datetime import datetime, timedelta
from typing import Any, Dict

from .database import LogEntry, SessionLocal, SystemHealth

logger = logging.getLogger(__name__)

class PredictiveAnalytics:
    """Analyzes historical database trends to forecast potential future attacks."""
    
    def predict_risk(self) -> Dict[str, Any]:
        db = SessionLocal()
        try:
            now = datetime.utcnow()
            one_hour_ago = now - timedelta(hours=1)
            
            # Fetch recent health metrics
            recent_health = db.query(SystemHealth).filter(SystemHealth.timestamp >= one_hour_ago).all()
            
            # Fetch recent logs
            recent_logs = db.query(LogEntry).filter(LogEntry.timestamp >= one_hour_ago).all()
            
            # Compute historical heuristics
            cpu_spikes = sum(1 for h in recent_health if h.cpu_usage > 85.0)
            network_spikes = sum(1 for h in recent_health if h.network_tx > 20000.0 or h.network_rx > 20000.0)
            failed_logins = sum(1 for l in recent_logs if "failed" in l.message.lower() and ("password" in l.message.lower() or "login" in l.message.lower()))
            
            # Base forecasting logic
            risk_score = 0.0
            attack_category = "None Predicted"
            likelihood = "Low"
            target = "None"
            action = "Continue standard monitoring."
            
            if failed_logins > 30:
                risk_score += 40
                attack_category = "Credential Stuffing / Distributed Brute Force"
                target = "Authentication / Identity Service"
                action = "Enable rate limiting, CAPTCHA, and temporarily block offending IPs."
            elif failed_logins > 5:
                risk_score += 20
                attack_category = "Targeted Brute Force"
                target = "SSH / Admin Portal"
                
            if cpu_spikes > 5 and network_spikes > 5:
                risk_score += 45
                if attack_category == "None Predicted":
                    attack_category = "DDoS or Cryptomining Botnet"
                else:
                    attack_category += " + Resource Exhaustion (DoS)"
                target = target if target != "None" else "Web Frontend / Infrastructure"
                action = "Deploy WAF rate limiting, scale up resources, and investigate malicious processes."
                
            risk_score = min(100.0, risk_score)
            
            if risk_score >= 70:
                likelihood = "High"
            elif risk_score >= 40:
                likelihood = "Medium"
                
            return {
                "prediction_timestamp": now.isoformat(),
                "predicted_attack_category": attack_category,
                "forecasted_likelihood": likelihood,
                "confidence_score": round(min(1.0, (risk_score / 100) + 0.1), 2) if risk_score > 0 else 0.0,
                "predicted_target": target,
                "recommended_action": action
            }
            
        except Exception as e:
            logger.error("Error computing predictive analytics: %s", e)
            return {"error": "Failed to compute predictions"}
        finally:
            db.close()
