import json
import logging
from typing import Any, Dict

from apscheduler.schedulers.background import BackgroundScheduler

from .config import Config
from .database import LogEntry, SessionLocal, SystemHealth
from .integrations import LokiClient, PrometheusClient

logger = logging.getLogger(__name__)


class LogIngestor:
    """Ingests logs and metrics via background scheduler, writing them to the database."""

    def __init__(self, config: Config):
        self.config = config
        self.loki = LokiClient(config)
        self.prometheus = PrometheusClient(config)
        
        self.scheduler = BackgroundScheduler()
        self.scheduler.add_job(self.poll_loki, "interval", seconds=10)
        self.scheduler.add_job(self.poll_prometheus, "interval", seconds=15)

    def start(self):
        """Start the background ingestion jobs."""
        if not self.scheduler.running:
            self.scheduler.start()
            logger.info("Started background data ingestion scheduler")

    def stop(self):
        """Stop the background ingestion jobs."""
        if self.scheduler.running:
            self.scheduler.shutdown()
            logger.info("Stopped background data ingestion scheduler")

    def poll_loki(self):
        """Fetch logs from Loki, run threat detection, and save to DB."""
        from .feature_engineering import extract_features
        from .threat_detection import ThreatDetector
        from .database import Alert
        from .gemini_client import GeminiAnalyzer
        
        # Instantiate detector lazily to avoid circular imports during init
        if not hasattr(self, 'detector'):
            self.detector = ThreatDetector()
            self.gemini = GeminiAnalyzer()
            
        logs = self.loki.query_logs('{job="varlogs"}', limit=20)
        db = SessionLocal()
        try:
            features_list = []
            for log_str in logs:
                entry = LogEntry(message=log_str, source="loki", level="INFO")
                db.add(entry)
                features_list.append(extract_features(log_str))
                
            # Run detection engine on incoming logs
            detections = self.detector.detect(features_list)
            for d in detections:
                gemini_summary = None
                if d["severity"] in ["high", "critical"]:
                    gemini_summary = self.gemini.analyze_alert(d["threat_type"], d["severity"], d["raw_message"])
                    
                alert = Alert(
                    alert_type=d["threat_type"],
                    severity=d["severity"],
                    description=f"Detected {d['threat_type']}: {d['raw_message'][:100]}",
                    source_ip=d["source_ip"],
                    confidence=d["confidence"],
                    mitre_tactic=",".join(d["mitre_tactics"]),
                    gemini_summary=gemini_summary
                )
                db.add(alert)
                
            db.commit()
            logger.debug("Ingested %d mock logs and generated %d alerts", len(logs), len(detections))
        except Exception as e:
            db.rollback()
            logger.error("Error ingesting logs: %s", e)
        finally:
            db.close()

    def poll_prometheus(self):
        """Fetch metrics from Prometheus and save to DB."""
        metrics = self.prometheus.query_metrics("system_health")
        db = SessionLocal()
        try:
            health = SystemHealth(
                cpu_usage=metrics["cpu_usage"],
                memory_usage=metrics["memory_usage"],
                network_tx=metrics["network_tx"],
                network_rx=metrics["network_rx"],
                active_connections=metrics["active_connections"]
            )
            db.add(health)
            db.commit()
            logger.debug("Ingested mock metrics from Prometheus")
        except Exception as e:
            db.rollback()
            logger.error("Error ingesting metrics: %s", e)
        finally:
            db.close()

    def parse_raw_entry(self, raw_entry: str) -> Dict[str, Any]:
        """Attempt to load a raw string as JSON, or return fallback dict."""
        try:
            data = json.loads(raw_entry)
            if isinstance(data, dict):
                return data
        except ValueError:
            pass
        return {"raw_message": raw_entry}
