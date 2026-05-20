"""
ShieldNet — Research-Grade Benchmarking Suite (Fast Mode)
Uses a representative subset for quick evaluation.
"""
import numpy as np
import os
from sklearn.metrics import (
    accuracy_score, f1_score, classification_report, balanced_accuracy_score
)
from sklearn.preprocessing import RobustScaler
from backend.services.idps.training.dataset_manager import DatasetManager
from backend.services.idps.models.classical_ml.xgboost_detector import XGBoostDetector

class Benchmarker:
    def __init__(self):
        self.dm = DatasetManager()

    def run(self, model_path: str = "models/idps_model.pkl"):
        if not os.path.exists(model_path):
            print(f"[ERROR] Model not found: {model_path}")
            return

        detector = XGBoostDetector(model_path)
        if not detector.model:
            print("[ERROR] Failed to load model.")
            return

        # Use 2 representative files (fast: ~450K samples instead of 2.8M)
        import pandas as pd
        files = [
            "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
            "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        ]

        full_df = pd.DataFrame()
        for f in files:
            df = self.dm.load_and_unify("cicids2017", f)
            if not df.empty:
                full_df = pd.concat([full_df, df], ignore_index=True)

        if full_df.empty:
            print("[ERROR] No data loaded.")
            return

        X, y_true, classes = self.dm.preprocess_for_training(full_df)
        X_scaled = RobustScaler().fit_transform(X)
        
        print(f"[*] Benchmarking on {len(X_scaled)} samples across {len(classes)} classes...")
        
        y_pred = detector.model.predict(X_scaled)

        print("\n" + "="*50)
        print("SHIELDNET — RESEARCH-GRADE BENCHMARK RESULTS")
        print("="*50)
        
        print(f"\nAccuracy:          {accuracy_score(y_true, y_pred):.4f}")
        print(f"Balanced Accuracy: {balanced_accuracy_score(y_true, y_pred):.4f}")
        print(f"Macro F1:          {f1_score(y_true, y_pred, average='macro'):.4f}")
        print(f"Weighted F1:       {f1_score(y_true, y_pred, average='weighted'):.4f}")
        
        print("\nPer-Class Report:")
        print(classification_report(y_true, y_pred, labels=range(len(classes)), target_names=classes, zero_division=0))
        
        print("[SUCCESS] Benchmark complete.")

if __name__ == "__main__":
    bm = Benchmarker()
    bm.run()
