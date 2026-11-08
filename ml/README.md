# ML Pipeline – TrustLens Threat Module

## Directory Structure

```
ml/
├── README.md          ← you are here
├── data/              ← datasets (gitignored – download locally)
│   ├── phishing/      ← phishing URL lists
│   └── benign/        ← benign URL lists
├── train.py           ← training pipeline (H8-16)
├── evaluate.py        ← evaluation & metrics
└── model.joblib       ← trained model (gitignored)
```

## Dataset Download Instructions

### 1. Phishing URLs

**PhishTank (recommended, free with registration)**
```bash
# Register at https://phishtank.org/ and get an API key
# Download verified phishing URLs (CSV):
curl -o ml/data/phishing/phishtank.csv \
  "http://data.phishtank.com/data/<YOUR_API_KEY>/online-valid.csv"
```

**OpenPhish (community feed, no registration)**
```bash
curl -o ml/data/phishing/openphish.txt \
  "https://openphish.com/feed.txt"
```
> Note: The free feed contains ~500 active URLs. For historical data, use PhishTank.

**Kaggle Phishing URL Dataset (alternative)**
```bash
# Download from https://www.kaggle.com/datasets/siddharthkumar25/malicious-and-benign-urls
# Place CSV into ml/data/phishing/
```

**UCI Phishing Websites Dataset**
```bash
# Download from https://archive.ics.uci.edu/dataset/327/phishing+websites
# Place into ml/data/phishing/
```

### 2. Benign URLs

**Tranco Top 1M (recommended)**
```bash
curl -o ml/data/benign/tranco_top1m.csv \
  "https://tranco-list.eu/download/XLQVZ/1000000"
```
> Tranco aggregates multiple top-site lists (Alexa, Umbrella, Majestic, Chrome UX).
> The ID in the URL (`XLQVZ`) changes daily. Get the latest from https://tranco-list.eu/

### 3. Quick Setup Script

```python
# ml/download_data.py (run once)
import os, subprocess

os.makedirs("ml/data/phishing", exist_ok=True)
os.makedirs("ml/data/benign", exist_ok=True)

print("Download these manually:")
print("  PhishTank  → ml/data/phishing/phishtank.csv")
print("  OpenPhish  → ml/data/phishing/openphish.txt")
print("  Tranco     → ml/data/benign/tranco_top1m.csv")
```

## Training Pipeline (H8-16)

```bash
cd ml
python train.py --phishing data/phishing/phishtank.csv \
                --benign data/benign/tranco_top1m.csv \
                --output model.joblib
```

### Key Design Decisions

1. **Feature extraction reuses `backend/app/modules/threat/url_features.py`**
   – training and inference always use the same code, preventing train/serve skew.

2. **Split by registered domain** (not by row) so the same domain never
   appears in both train and test. Otherwise precision/recall will be inflated.

3. **SHAP explanations** are converted to plain-English findings, not raw
   feature names, so they can be returned directly in `ModuleResult.findings`.

4. **model.joblib is gitignored.** For sharing: attach to a GitHub release,
   or commit a small final model once we're happy with it.

## Evaluation (H34-40)

The training script outputs an evaluation table:

| Metric     | Value |
|------------|-------|
| Precision  | TBD   |
| Recall     | TBD   |
| F1         | TBD   |
| ROC-AUC    | TBD   |
| Accuracy   | TBD   |

This table will be included in our slides.

## Model Sharing

Options (agree with P1):
- **GitHub Release asset** – attach `model.joblib` to a tagged release
- **Git LFS** – track `*.joblib` with LFS
- **Small model** – if < 10MB, commit directly with a note

Current decision: **GitHub Release asset** (keeps the repo lightweight).

