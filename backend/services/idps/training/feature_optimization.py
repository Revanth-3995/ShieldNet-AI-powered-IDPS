"""
ShieldNet — Feature Optimization & Selection
Analyzes feature importance and reduces redundancy to improve model performance.
"""
import pandas as pd
import numpy as np
from typing import List
from sklearn.ensemble import RandomForestClassifier
from backend.services.idps.training.dataset_manager import DatasetManager
from backend.services.idps.models.classical_ml.xgboost_detector import XGBoostDetector
from backend.core.logging import get_logger

logger = get_logger("shieldnet.idps.training.features")

class FeatureOptimizer:
    def __init__(self):
        self.dm = DatasetManager()

    def analyze_dataset(self, dataset_name: str, file_name: str):
        """Perform full feature analysis on a dataset."""
        df = self.dm.load_and_unify(dataset_name, file_name)
        if df.empty: return
        
        # 1. Select numeric features that match our inference pipeline
        features = [f for f in XGBoostDetector.FEATURES if f in df.columns]
        X = df[features].replace([np.inf, -np.inf], 0).fillna(0)
        y = self.dm.label_encoder.fit_transform(df["label_unified"])
        
        # 2. Correlation Analysis
        self._run_correlation_analysis(X)
        
        # 3. Importance Ranking
        self._run_importance_ranking(X, y)

    def _run_correlation_analysis(self, X: pd.DataFrame, threshold: float = 0.95):
        """Identify highly redundant features."""
        corr_matrix = X.corr().abs()
        upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
        to_drop = [column for column in upper.columns if any(upper[column] > threshold)]
        
        if to_drop:
            logger.info(f"Redundant features found (> {threshold} correlation): {to_drop}")
        else:
            logger.info("No highly correlated features found. Feature set is diverse.")

    def _run_importance_ranking(self, X: pd.DataFrame, y: np.ndarray):
        """Rank features by their contribution to the classification task."""
        model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        model.fit(X, y)
        
        importances = pd.Series(model.feature_importances_, index=X.columns)
        top_20 = importances.nlargest(20)
        
        logger.info(f"Top 20 Critical Features for Detection:\n{top_20}")
        
        # Check for 'junk' features (zero importance)
        junk = importances[importances == 0]
        if not junk.empty:
            logger.warning(f"Found {len(junk)} useless features (zero importance): {junk.index.tolist()}")

if __name__ == "__main__":
    optimizer = FeatureOptimizer()
    # Example usage:
    # optimizer.analyze_dataset("cicids2017", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
