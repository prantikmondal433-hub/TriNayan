"""TrustLens ML training pipeline.

Usage:
    python ml/train.py                          # uses synthetic data
    python ml/train.py --dataset ml/data/real.csv  # uses a real CSV (columns: url, label)

Outputs:
    ml/model.joblib         – trained XGBoost model
    ml/evaluation.md        – precision / recall / F1 / ROC-AUC table
    ml/feature_importance.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import shap
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit
from xgboost import XGBClassifier

# ── make backend importable ──────────────────────────────────────────
BACKEND_DIR = str(Path(__file__).resolve().parent.parent / "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.modules.threat.url_features import extract_features  # noqa: E402

try:
    import tldextract
except ImportError:
    tldextract = None  # fall back to naive domain extraction

warnings.filterwarnings("ignore", category=UserWarning)

ML_DIR = Path(__file__).resolve().parent
DEFAULT_DATASET = ML_DIR / "data" / "synthetic_dataset.csv"
MODEL_PATH = ML_DIR / "model.joblib"
EVAL_PATH = ML_DIR / "evaluation.md"
IMPORTANCE_PATH = ML_DIR / "feature_importance.csv"

# ── SHAP feature → plain-English mapping ─────────────────────────────
FEATURE_EXPLANATIONS: dict[str, str] = {
    "url_length": "The URL is unusually long, which is common in phishing links",
    "host_length": "The domain name is unusually long",
    "path_length": "The URL path is unusually long",
    "query_length": "The URL has a long query string with many parameters",
    "fragment_length": "The URL contains an unusual fragment section",
    "subdomain_depth": "The domain has many subdomains, making the real host hard to see",
    "path_depth": "The URL has a deeply nested path structure",
    "digit_ratio": "The domain name contains an unusual number of digits",
    "hyphen_count": "The domain name contains many hyphens",
    "at_sign": "The URL contains an @ sign that can redirect to a different site",
    "has_at_in_path": "The URL path contains an @ sign",
    "ip_as_host": "The website uses a raw IP address instead of a domain name",
    "punycode": "The domain uses international characters that can mimic real brands",
    "entropy": "The domain name looks randomly generated",
    "tld_risk": "The domain uses a top-level domain often abused by phishing sites",
    "keyword_count": "The URL contains words commonly used in phishing (login, verify, etc.)",
    "is_shortener": "The URL uses a link-shortening service that hides the real destination",
    "has_double_slash_redirect": "The URL contains a redirect trick using double slashes",
    "non_standard_port": "The website uses a non-standard port number",
    "uses_https": "The website does not use secure HTTPS encryption",
}


def _registered_domain(url: str) -> str:
    """Extract the registered domain for group-based splitting."""
    if tldextract is not None:
        ext = tldextract.extract(url)
        rd = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        return rd.lower()
    # Naive fallback
    from urllib.parse import urlparse
    host = (urlparse(url).hostname or "").lower()
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def load_dataset(path: str | Path) -> pd.DataFrame:
    """Load a CSV with columns 'url' and 'label' (0=safe, 1=phishing)."""
    df = pd.read_csv(path)
    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("CSV must have 'url' and 'label' columns")
    df = df.dropna(subset=["url", "label"])
    df["label"] = df["label"].astype(int)
    print(f"Loaded {len(df)} rows from {path}")
    print(f"  Class distribution: {dict(df['label'].value_counts())}")
    return df


def featurize(df: pd.DataFrame) -> pd.DataFrame:
    """Extract features for every URL using the shared url_features module."""
    print("Extracting features …")
    feature_dicts = [extract_features(url) for url in df["url"]]
    features_df = pd.DataFrame(feature_dicts)
    return features_df


def split_by_domain(
    df: pd.DataFrame,
    features_df: pd.DataFrame,
    test_size: float = 0.2,
    seed: int = 42,
) -> tuple:
    """Split by registered domain so the same domain never leaks across sets."""
    groups = df["url"].apply(_registered_domain)

    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    train_idx, test_idx = next(splitter.split(features_df, df["label"], groups))

    X_train = features_df.iloc[train_idx]
    X_test = features_df.iloc[test_idx]
    y_train = df["label"].iloc[train_idx]
    y_test = df["label"].iloc[test_idx]

    print(f"Train: {len(X_train)} rows ({y_train.sum()} phishing)")
    print(f"Test:  {len(X_test)} rows ({y_test.sum()} phishing)")

    # Verify no domain leakage
    train_domains = set(groups.iloc[train_idx])
    test_domains = set(groups.iloc[test_idx])
    leak = train_domains & test_domains
    if leak:
        print(f"  ⚠ Domain leakage: {len(leak)} domains in both sets")
    else:
        print("  ✓ No domain leakage")

    return X_train, X_test, y_train, y_test


def train_model(X_train, y_train, seed: int = 42) -> XGBClassifier:
    """Train an XGBoost classifier."""
    print("Training XGBoost …")
    model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=3,
        scale_pos_weight=1.0,
        random_state=seed,
        eval_metric="logloss",
        use_label_encoder=False,
    )
    model.fit(X_train, y_train, verbose=False)
    return model


def evaluate(model, X_test, y_test) -> dict:
    """Evaluate and return metrics."""
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    metrics = {
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_test, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_test, y_pred, zero_division=0), 4),
        "roc_auc": round(roc_auc_score(y_test, y_prob), 4),
    }

    print("\n── Evaluation ──")
    for k, v in metrics.items():
        print(f"  {k:>10}: {v}")
    print()
    print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))

    return metrics


def save_evaluation(metrics: dict, path: Path):
    """Write evaluation table as markdown."""
    lines = [
        "# TrustLens Threat ML – Evaluation",
        "",
        "| Metric    | Value  |",
        "|-----------|--------|",
    ]
    for k, v in metrics.items():
        lines.append(f"| {k.title():<9} | {v:.4f} |")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Evaluation table → {path}")


def save_feature_importance(model, feature_names: list[str], path: Path):
    """Save feature importance to CSV."""
    importances = model.feature_importances_
    df = pd.DataFrame({
        "feature": feature_names,
        "importance": importances,
    }).sort_values("importance", ascending=False)
    df.to_csv(path, index=False)
    print(f"Feature importance → {path}")
    print(df.to_string(index=False))


def explain_prediction(
    model,
    explainer: shap.TreeExplainer,
    features: dict,
    top_n: int = 5,
) -> list[dict]:
    """Convert SHAP values to plain-English findings for a single URL.

    Returns a list of dicts with 'id', 'severity', 'title', 'detail', 'evidence'.
    """
    feature_names = list(features.keys())
    X = pd.DataFrame([features])
    shap_values = explainer.shap_values(X)

    # shap_values shape: (1, n_features) for binary classification
    if isinstance(shap_values, list):
        sv = shap_values[1][0]  # class 1 (phishing)
    else:
        sv = shap_values[0]

    # Pair feature names with their SHAP contributions
    contributions = list(zip(feature_names, sv, [features[f] for f in feature_names]))
    # Sort by absolute SHAP value descending
    contributions.sort(key=lambda x: abs(x[1]), reverse=True)

    findings = []
    for fname, shap_val, fval in contributions[:top_n]:
        if abs(shap_val) < 0.01:
            continue  # skip negligible contributions

        # Determine severity from SHAP magnitude
        abs_sv = abs(shap_val)
        if abs_sv > 1.0:
            severity = "high"
        elif abs_sv > 0.3:
            severity = "medium"
        else:
            severity = "low"

        # Only report features that push toward phishing (positive SHAP)
        if shap_val <= 0:
            continue

        title = FEATURE_EXPLANATIONS.get(fname, f"Suspicious pattern in {fname}")
        finding_id = f"THREAT_ML_{fname.upper()}"

        findings.append({
            "id": finding_id,
            "severity": severity,
            "title": title,
            "detail": f"Feature '{fname}' = {fval} (contribution: {shap_val:+.3f})",
            "evidence": {"feature": fname, "value": fval, "shap_value": round(float(shap_val), 4)},
        })

    return findings


def main():
    parser = argparse.ArgumentParser(description="Train TrustLens phishing ML model")
    parser.add_argument("--dataset", type=str, default=str(DEFAULT_DATASET),
                        help="Path to CSV with 'url' and 'label' columns")
    parser.add_argument("--output", type=str, default=str(MODEL_PATH),
                        help="Path to save the model")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    # 1. Load
    df = load_dataset(args.dataset)

    # 2. Featurize
    features_df = featurize(df)
    feature_names = list(features_df.columns)

    # 3. Split by domain
    X_train, X_test, y_train, y_test = split_by_domain(df, features_df, seed=args.seed)

    # 4. Train
    model = train_model(X_train, y_train, seed=args.seed)

    # 5. Evaluate
    metrics = evaluate(model, X_test, y_test)
    save_evaluation(metrics, EVAL_PATH)
    save_feature_importance(model, feature_names, IMPORTANCE_PATH)

    # 6. Save model
    output_path = Path(args.output)
    joblib.dump({"model": model, "feature_names": feature_names}, output_path)
    print(f"\nModel saved → {output_path}")
    print(f"Model size: {output_path.stat().st_size / 1024:.1f} KB")

    # 7. Demo: explain one prediction
    print("\n── Demo SHAP explanation ──")
    explainer = shap.TreeExplainer(model)
    demo_url = "http://paypa1-secure-login.tk/verify/account"
    demo_features = extract_features(demo_url)
    prob = model.predict_proba(pd.DataFrame([demo_features]))[0][1]
    explanations = explain_prediction(model, explainer, demo_features)
    print(f"URL: {demo_url}")
    print(f"Phishing probability: {prob:.3f}")
    print(f"Risk score: {int(prob * 100)}")
    for exp in explanations:
        print(f"  [{exp['severity'].upper()}] {exp['title']}")
        print(f"         {exp['detail']}")


if __name__ == "__main__":
    main()

