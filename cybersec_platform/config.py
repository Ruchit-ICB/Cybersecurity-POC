"""Platform configuration with environment-variable defaults and optional JSON override."""

import copy
import json
import logging
import os
from typing import Any, Dict

logger = logging.getLogger(__name__)


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge *override* into *base*, returning a new dict."""
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


class Config:
    """Configuration for the cybersecurity analytics platform."""

    def __init__(self, config_path: str | None = None):
        self._config = self._load_config(config_path)

    def _load_config(self, config_path: str | None) -> Dict[str, Any]:
        default: Dict[str, Any] = {
            "grafana": {
                "base_url": os.environ.get("GRAFANA_URL", "http://localhost:3000"),
            },
            "loki": {
                "base_url": os.environ.get("LOKI_URL", "http://localhost:3100"),
            },
            "prometheus": {
                "base_url": os.environ.get("PROMETHEUS_URL", "http://localhost:9090"),
            },
            "model_store": os.environ.get("MODEL_STORE_PATH", "./models"),
            "llama_model_path": os.environ.get("LLAMA_MODEL_PATH", "./models/llama_model.gguf"),
            "llama_num_threads": int(os.environ.get("LLAMA_NUM_THREADS", "4")),
            "ingest": {
                "poll_interval_seconds": int(
                    os.environ.get("INGEST_POLL_INTERVAL", "30")
                ),
                "batch_size": int(os.environ.get("INGEST_BATCH_SIZE", "500")),
            },
            "logging": {
                "level": os.environ.get("LOG_LEVEL", "INFO"),
            },
        }

        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as handle:
                    loaded = json.load(handle)
                    default = _deep_merge(default, loaded)
            except Exception as exc:
                logger.warning(
                    "Failed to load config from %s: %s", config_path, exc
                )

        return default

    def get(self, key: str, default: Any = None) -> Any:
        return self._config.get(key, default)

    def __getitem__(self, item: str) -> Any:
        return self._config[item]
