

import os

from flask import Flask, render_template, request

from .api import api
from .classifier import (
    SimpleLogClassifier,
    analyze_log_text,
    create_sample_log_text,
    summarize_findings,
)
from .config import Config
from .utils import configure_logging


_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))


def create_app(config_path: str | None = None):
    
    config = Config(config_path)
    configure_logging(config["logging"]["level"])

    app = Flask(
        __name__,
        template_folder=os.path.join(_BASE_DIR, "templates"),
        static_folder=os.path.join(_BASE_DIR, "static"),
    )
    app.config.update(config._config)
    app.register_blueprint(api)

    
    model = SimpleLogClassifier()
    sample_text = create_sample_log_text()

    

    @app.route("/", methods=["GET"])
    def index():
        return render_template(
            "index.html",
            findings=None,
            summary=None,
            sample_text=sample_text,
            error=None,
        )

    @app.route("/scan", methods=["POST"])
    def scan():
        log_text = request.form.get("log_text", "").strip()
        if not log_text:
            return render_template(
                "index.html",
                findings=None,
                summary=None,
                sample_text=sample_text,
                error="Please paste log text or use the sample text.",
            )

        findings = analyze_log_text(log_text, model)
        summary = summarize_findings(findings)
        return render_template(
            "index.html",
            findings=findings,
            summary=summary,
            sample_text=log_text,
            error=None,
        )

    return app
