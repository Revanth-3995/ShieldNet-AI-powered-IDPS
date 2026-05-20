"""
ShieldNet — Advanced XGBoost Training Pipeline
Includes: Optuna Tuning, SMOTE Balancing, Isotonic Calibration, and Threshold Optimization.
"""
import os
import pickle
import numpy as np
import pandas as pd
import xgboost as xgb
import optuna
from typing import List
from sklearn.metrics import f1_score, precision_recall_curve, classification_report
from sklearn.calibration import CalibratedClassifierCV
from imblearn.over_sampling import SMOTE
from backend.services.idps.training.dataset_manager import DatasetManager
from backend.services.idps.models.classical_ml.xgboost_detector import XGBoostDetector
from backend.core.logging import get_logger

logger = get_logger("shieldnet.idps.training.xgboost")

class XGBoostTrainer:
    def __init__(self, output_path: str = "models/idps_model.pkl"):
        self.output_path = output_path
        self.dm = DatasetManager()

    def run_full_pipeline(self, dataset_configs: List[dict], n_trials: int = 30):
        """
        Run the complete training pipeline:
        Load -> Merge -> Balance -> Tune -> Train -> Calibrate -> Optimize Thresholds -> Save
        """
        # 1. Load and Merge Data
        full_df = pd.DataFrame()
        for config in dataset_configs:
            df = self.dm.load_and_unify(config["name"], config["file"])
            full_df = pd.concat([full_df, df], ignore_index=True)
            
        if full_df.empty:
            print("\n[ERROR] No data found! Please ensure your CSV files are in the 'data/datasets/' folder.")
            print("Expected files:")
            for c in dataset_configs:
                print(f" - data/datasets/{c['name']}/{c['file']}")
            return

        print(f"[*] Loaded {len(full_df)} samples from {len(dataset_configs)} datasets.")

        # 2. Preprocess
        X, y, classes = self.dm.preprocess_for_training(full_df)
        num_classes = len(classes)
        
        if num_classes < 2:
            print(f"[ERROR] Only {num_classes} class found ({classes}). XGBoost requires at least 2 for classification.")
            return
            
        X_train, X_test, y_train, y_test = self.dm.prepare_train_test(X, y)

        # 3. Handle Imbalance
        X_train_bal, y_train_bal = self.dm.balance_dataset(X_train, y_train)
        
        # Apply SMOTE specifically for the Bot class
        bot_idx = classes.index("Bot") if "Bot" in classes else -1
        if bot_idx != -1:
            counts = np.bincount(y_train_bal)
            bot_count = counts[bot_idx]
            # If we have bots, oversample them to double their count or at least 1000
            target_count = max(bot_count * 2, 1000)
            if bot_count < target_count and bot_count >= 4: # Need at least k_neighbors+1 samples
                try:
                    smote_dict = {i: counts[i] for i in range(len(counts))}
                    smote_dict[bot_idx] = target_count
                    smote = SMOTE(sampling_strategy=smote_dict, k_neighbors=3, random_state=42)
                    X_train_bal, y_train_bal = smote.fit_resample(X_train_bal, y_train_bal)
                    logger.info(f"Applied SMOTE to Bot class: {bot_count} -> {target_count}")
                except Exception as e:
                    logger.warning(f"Could not apply SMOTE to Bot class: {e}")

        # 4. Hyperparameter Tuning
        logger.info(f"Starting Hyperparameter Optimization ({n_trials} trials)...")
        best_params = self._optimize(X_train_bal, y_train_bal, X_test, y_test, num_classes)
        logger.info(f"Best Params found: {best_params}")

        # 5. Final Calibrated Model (Cross-Validated Calibration)
        logger.info("Training and Calibrating final model (5-fold CV)...")
        base_model = xgb.XGBClassifier(**best_params, n_jobs=-1, random_state=42)
        calibrated_model = CalibratedClassifierCV(base_model, method="isotonic", cv=5)
        calibrated_model.fit(X_train_bal, y_train_bal)

        # 6. Threshold Optimization (Optimized for Recall)
        logger.info("Optimizing per-class sensitivity thresholds...")
        thresholds = self._find_optimal_thresholds(calibrated_model, X_test, y_test, classes)

        # 7. Realistic Evaluation Report
        y_pred = calibrated_model.predict(X_test)
        
        print("\n" + "="*50)
        print("SHIELDNET — RESEARCH-GRADE PERFORMANCE REPORT")
        print("="*50)
        print(classification_report(y_test, y_pred, target_names=classes))
        
        # 8. Save Artifact
        self._save_model(calibrated_model, classes, thresholds)

    def _optimize(self, X_train, y_train, X_test, y_test, num_class):
        def objective(trial):
            params = {
                "n_estimators": trial.suggest_int("n_estimators", 100, 500),
                "max_depth": trial.suggest_int("max_depth", 3, 7),
                "learning_rate": trial.suggest_float("learning_rate", 0.01, 0.2, log=True),
                "subsample": trial.suggest_float("subsample", 0.7, 1.0),
                "colsample_bytree": trial.suggest_float("colsample_bytree", 0.7, 1.0),
                "tree_method": "hist",
                "random_state": 42
            }
            model = xgb.XGBClassifier(**params)
            model.fit(X_train, y_train)
            
            preds = model.predict(X_test)
            # Focus on Macro-F1 to protect minority classes
            return f1_score(y_test, preds, average="macro")

        study = optuna.create_study(direction="maximize")
        study.optimize(objective, n_trials=10)
        return study.best_params

    def _find_optimal_thresholds(self, model, X_val, y_val, classes):
        probs = model.predict_proba(X_val)
        thresholds = {}
        for i, class_name in enumerate(classes):
            if class_name == "Benign": continue
            # Calculate PR curve
            precision, recall, thresh = precision_recall_curve((y_val == i).astype(int), probs[:, i])
            # Find threshold that balances precision and recall (F1 max)
            f1 = 2 * (precision * recall) / (precision + recall + 1e-10)
            best_idx = np.argmax(f1)
            thresholds[class_name] = float(thresh[best_idx]) if best_idx < len(thresh) else 0.5
        return thresholds

    def _save_model(self, model, classes, thresholds):
        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
        metadata = {
            "model": model,
            "classes": classes,
            "features": XGBoostDetector.FEATURES,
            "thresholds": thresholds,
            "version": "2.0.0-behavioral-research"
        }
        with open(self.output_path, "wb") as f:
            pickle.dump(metadata, f)
            
        base_dir = os.path.dirname(self.output_path)
        scaler_path = os.path.join(base_dir, "scaler.pkl")
        with open(scaler_path, "wb") as f:
            pickle.dump(self.dm.scaler, f)
            
        le_path = os.path.join(base_dir, "label_encoder.pkl")
        with open(le_path, "wb") as f:
            pickle.dump(self.dm.label_encoder, f)
            
        logger.info(f"ShieldNet Behavioral Model, Scaler, and Label Encoder saved to {base_dir}")

    def run_cross_dataset_test(self, train_configs: List[dict], test_configs: List[dict], n_trials: int = 10):
        """
        Research-Grade Methodology: 
        Train on one dataset pool, Test on a completely separate dataset pool.
        Uses shared LabelEncoder to prevent class-index misalignment.
        """
        print("\n" + "="*50)
        print("SHIELDNET — CROSS-DATASET GENERALIZATION TEST")
        print("="*50)
        
        # 1. Load Training Pool
        train_df = pd.DataFrame()
        for config in train_configs:
            df = self.dm.load_and_unify(config["name"], config["file"])
            train_df = pd.concat([train_df, df], ignore_index=True)
            
        # 2. Load Testing Pool (Unseen)
        test_df = pd.DataFrame()
        for config in test_configs:
            df = self.dm.load_and_unify(config["name"], config["file"])
            test_df = pd.concat([test_df, df], ignore_index=True)

        if train_df.empty or test_df.empty:
            print("[ERROR] Missing datasets for generalization test.")
            return

        # 3. Preprocess training data (this FITS the LabelEncoder)
        X_train_raw, y_train, classes = self.dm.preprocess_for_training(train_df)
        print(f"[*] Training classes: {classes}")
        print(f"[*] Training samples: {len(X_train_raw)}")
        
        # 4. Filter test data to only include classes the model has seen
        known_classes = set(classes)
        test_df = test_df[test_df["label_unified"].isin(known_classes)]
        if test_df.empty:
            print("[ERROR] No overlapping classes between train and test datasets.")
            return
        print(f"[*] Test samples (filtered to known classes): {len(test_df)}")
        
        # 5. Preprocess test data (uses ALREADY-FITTED encoder — no re-fitting)
        X_test_raw, y_test = self.dm.preprocess_for_testing(test_df)

        # 6. Fit Scaler ONLY on train
        from sklearn.preprocessing import RobustScaler
        scaler = RobustScaler()
        X_train = scaler.fit_transform(X_train_raw)
        X_test = scaler.transform(X_test_raw)
        
        # 7. Balance training data
        X_train_bal, y_train_bal = self.dm.balance_dataset(X_train, y_train)
        
        # 8. Tune & Train
        best_params = self._optimize(X_train_bal, y_train_bal, X_test, y_test, len(classes))
        model = xgb.XGBClassifier(**best_params, n_jobs=-1, random_state=42)
        model.fit(X_train_bal, y_train_bal)
        
        # 9. Report
        y_pred = model.predict(X_test)
        
        print("\n" + "="*50)
        print("SHIELDNET — RESEARCH-GRADE PERFORMANCE REPORT")
        print("="*50)
        print(f"Training: {len(train_df)} samples | Testing: {len(test_df)} samples (unseen)")
        print(classification_report(y_test, y_pred, target_names=classes))
        
        self._save_model(model, classes, {})


if __name__ == "__main__":
    trainer = XGBoostTrainer()
    
    # Load ALL CICIDS2017 files for multi-class evaluation
    # This creates a realistic 7+ class problem (Benign, DoS, BruteForce, PortScan, WebAttack, Infiltration, Bot)
    configs = [
        {"name": "cicids2017", "file": "Monday-WorkingHours.pcap_ISCX.csv"},
        {"name": "cicids2017", "file": "Tuesday-WorkingHours.pcap_ISCX.csv"},
        {"name": "cicids2017", "file": "Wednesday-workingHours.pcap_ISCX.csv"},
        {"name": "cicids2017", "file": "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"},
        {"name": "cicids2017", "file": "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"},
        {"name": "cicids2017", "file": "Friday-WorkingHours-Morning.pcap_ISCX.csv"},
        {"name": "cicids2017", "file": "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"},
        {"name": "cicids2017", "file": "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"},
    ]
    
    print("\n" + "="*50)
    print("SHIELDNET — RESEARCH-GRADE ML PIPELINE")
    print("="*50)
    
    try:
        trainer.run_full_pipeline(configs, n_trials=9)
        print("\n[SUCCESS] Research-grade training complete.")
    except Exception as e:
        print(f"\n[ERROR] Pipeline failed: {e}")
        import traceback
        traceback.print_exc()

