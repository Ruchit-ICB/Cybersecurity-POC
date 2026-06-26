import argparse
import pandas as pd
from pathlib import Path
from sklearn.metrics import classification_report, confusion_matrix, precision_score, recall_score, f1_score
from cybersec_platform.threat_detection import ThreatDetector
from cybersec_platform.feature_engineering import extract_features

def load_data(csv_path: Path):
    
    df = pd.read_csv(csv_path)
    required_cols = {'log_entry', 'label'}
    if not required_cols.issubset(df.columns):
        raise ValueError(f"CSV must contain columns: {required_cols}")
    return df

def evaluate(df: pd.DataFrame, detector: ThreatDetector):
    
    pred_labels = []
    for log_entry in df['log_entry']:
        feature = extract_features(log_entry)
        detections = detector.detect([feature])
        if detections:
            pred_labels.append(detections[0]['threat_type'])
        else:
            pred_labels.append('benign')
    true_labels = df['label'].astype(str).tolist()
    return true_labels, pred_labels

def generate_report(true, pred, output_path: Path):
    report_lines = []
    report_lines.append('# Model Evaluation Report')
    report_lines.append('## Weighted Classification Metrics')
    report_lines.append(f"Precision: {precision_score(true, pred, average='weighted', zero_division=0):.3f}")
    report_lines.append(f"Recall:    {recall_score(true, pred, average='weighted', zero_division=0):.3f}")
    report_lines.append(f"F1 Score:  {f1_score(true, pred, average='weighted', zero_division=0):.3f}\n")
    report_lines.append('## Detailed Classification Report')
    report_lines.append(classification_report(true, pred, zero_division=0))
    report_lines.append('## Confusion Matrix')
    cm = confusion_matrix(true, pred)
    labels = sorted(list(set(true + pred)))
    df_cm = pd.DataFrame(cm, index=labels, columns=labels)
    report_lines.append(df_cm.to_markdown())
    output_path.write_text('\n'.join(report_lines))
    print(f"Report written to {output_path}")

def main():
    parser = argparse.ArgumentParser(description='Evaluate threat detection ML models')
    parser.add_argument('--dataset', type=str, required=True, help='Path to labeled CSV dataset')
    parser.add_argument('--output', type=str, default='evaluation_report.md', help='Markdown report file')
    args = parser.parse_args()
    dataset_path = Path(args.dataset)
    output_path = Path(args.output)
    df = load_data(dataset_path)
    detector = ThreatDetector()
    true, pred = evaluate(df, detector)
    generate_report(true, pred, output_path)

if __name__ == '__main__':
    main()
