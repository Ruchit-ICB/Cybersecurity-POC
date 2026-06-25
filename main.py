import argparse
import os

try:
    from cybersec_platform.app import create_app

    _HAS_FLASK = True
except Exception:  # noqa: BLE001
    _HAS_FLASK = False

from cybersec_platform.classifier import (
    SimpleLogClassifier,
    analyze_log_text,
    create_sample_log_text,
    summarize_findings,
)


def run_cli() -> None:
    """Parse CLI arguments and run the classifier against log text."""
    parser = argparse.ArgumentParser(
        description="Vulnerability assessment and threat detection CLI.",
    )
    parser.add_argument(
        "--sample",
        action="store_true",
        help="Print a sample log and run the classifier against it",
    )
    parser.add_argument("--text", help="Raw log text to scan")
    args = parser.parse_args()

    model = SimpleLogClassifier()
    if args.sample:
        log_text = create_sample_log_text()
    elif args.text:
        log_text = args.text
    else:
        parser.print_help()
        return

    findings = analyze_log_text(log_text, model)
    summary = summarize_findings(findings)

    print("Vulnerability Assessment / Threat Detection Report")
    print(f"Total lines analyzed: {summary['total_lines']}")
    print(f"Predicted threats: {summary['ml_threat_count']}")
    print(f"Predicted vulnerabilities: {summary['ml_vulnerability_count']}")
    print(f"Rule-based indicators found: {summary['indicator_count']}")

    for item in findings:
        print("---")
        print(f"Line {item['line_number']}: {item['message']}")
        print(f"  ML prediction: {item['ml_label']} ({item['confidence']})")
        if item["indicators"]:
            for indicator in item["indicators"]:
                print(
                    f"  Rule indicator: {indicator['indicator']}"
                    f" [{indicator['severity']}]"
                )


def main() -> None:
    """Launch the web app (if Flask is available) or the CLI."""
    if _HAS_FLASK:
        app = create_app()
        debug = os.environ.get("FLASK_DEBUG", "0") == "1"
        app.run(host="127.0.0.1", port=5000, debug=debug)
    else:
        run_cli()


if __name__ == "__main__":
    main()
