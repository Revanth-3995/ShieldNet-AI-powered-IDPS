# ShieldNet — ML Training Pipeline

Everything in `backend/services/idps/training/`.

---

## Overview

The training pipeline loads CICIDS2017 (and optionally IDS2018 / UNSW-NB15) CSV files, unifies them into a single schema, handles class imbalance, tunes XGBoost hyperparameters with Optuna, calibrates probabilities, and saves a deployment-ready artifact to `models/idps_model.pkl`.

---

## Files

| File | What it does |
|---|---|
| `train_xgboost.py` | Main entry point. Runs the full pipeline end to end. |
| `dataset_manager.py` | Loads, unifies, and preprocesses all datasets. Owns the LabelEncoder and scaler. |
| `benchmark.py` | Evaluates the saved model on a held-out dataset. |
| `feature_optimization.py` | Feature selection, schema gap analysis. |
| `fetch_datasets.py` | Download helpers for public datasets. |
| `train_sequence.py` | Separate training pipeline for the BiLSTM temporal model. |
| `validate_deployment.py` | Post-save sanity checks before the model goes live. |

---

## Running Training

```bash
# From the project root (main_el/)
python -m backend.services.idps.training.train_xgboost
```

This runs 10 Optuna trials and takes ~10–15 minutes on a standard machine. The best model is saved automatically to `models/idps_model.pkl`.

**Back up the model before re-running:**
```bash
cp models/idps_model.pkl models/idps_model_backup_$(date +%Y%m%d).pkl
```

---

## Pipeline Steps

```
1. Load CSVs          dataset_manager.load_and_unify()
        ↓
2. Preprocess         dataset_manager.preprocess_for_training()
   (encode labels,    → fits LabelEncoder + scaler HERE
    scale features)   → SAVE these with the model artifact
        ↓
3. Train/Test Split   dataset_manager.prepare_train_test()
        ↓
4. SMOTE Balancing    dataset_manager.balance_dataset()
        ↓
5. Optuna Tuning      XGBoostTrainer._optimize()   (10 trials)
        ↓
6. Final Train        XGBClassifier + CalibratedClassifierCV (5-fold isotonic)
        ↓
7. Threshold Opt.     XGBoostTrainer._find_optimal_thresholds()
        ↓
8. Save Artifact      models/idps_model.pkl
```

---

## Saved Model Artifact

`models/idps_model.pkl` is a pickle dict containing:

```python
{
    "model":      CalibratedClassifierCV,   # the trained + calibrated model
    "classes":    List[str],                # class label strings
    "features":   List[str],               # XGBoostDetector.FEATURES
    "thresholds": Dict[str, float],         # per-class optimal thresholds
    "version":    "2.0.0-behavioral-research"
}
```

> ⚠️ **Known gap**: the fitted `LabelEncoder` and `RobustScaler` are NOT currently saved in this artifact. This causes the benchmark to use a different fit and produces wrong results. Fix: add `"encoder"` and `"scaler"` keys to the dict in `_save_model()`.

---

## Current Results

### Training Report (566,109 test samples)

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| Benign | 1.00 | 0.98 | 0.99 | 454,580 |
| Bot | 0.60 | 0.62 | **0.61** ⚠️ | 393 |
| DoS | 1.00 | 1.00 | 1.00 | 25,605 |
| Infiltration | 1.00 | 0.86 | 0.92 | 7 |
| Other | 0.85 | 0.98 | 0.91 | 53,738 |
| PortScan | 0.99 | 1.00 | 1.00 | 31,786 |
| **Weighted avg** | **0.98** | **0.98** | **0.98** | |

### Best Optuna Trial (Trial 6 / 10)

```
n_estimators:     290
max_depth:        7
learning_rate:    0.0234
subsample:        0.8197
colsample_bytree: 0.7142
macro F1:         0.9028
```

---

## Known Issues

### 1. Benchmark accuracy is 0.44 (critical)
The benchmark reports 44% accuracy vs 98% in training. Root cause: `benchmark.py` creates a fresh `LabelEncoder` and `RobustScaler` fit on the benchmark data, which doesn't match the fit used during training. Fix: save the encoder and scaler inside the model artifact and load them in `benchmark.py`.

### 2. Benchmark crash
`classification_report` throws `ValueError: Number of classes, 4, does not match size of target_names, 3` because the benchmark data contains a class not seen during training. Fix: derive `target_names` dynamically from actual labels using `np.union1d(y_true, y_pred)`.

### 3. Schema Gap — 2 missing features
`payload_entropy` and `dst_port_type` are flagged as missing every run. Either engineer these columns in `dataset_manager.py` or remove them from `XGBoostDetector.FEATURES`.

### 4. Bot class underperformance (F1 = 0.61)
Only 393 Bot samples in the dataset. Standard SMOTE isn't enough. Fix: apply targeted oversampling for Bot specifically in `balance_dataset()`.

---

## Benchmarking

```bash
python -m backend.services.idps.training.benchmark
```

> ⚠️ Currently broken — see Known Issues #1 and #2 above before running.

---

## Datasets

| Dataset | Location | Used for |
|---|---|---|
| CICIDS2017 | `data/datasets/cicids2017/` | Primary training (8 CSV files) |
| IDS2018 | `data/datasets/ids2018/` | Cross-dataset generalization test |
| UNSW-NB15 | `data/datasets/unsw_nb15/` | Cross-dataset generalization test |

All 8 CICIDS2017 files must be present for full training. Missing files cause a schema gap warning but won't crash the pipeline.
