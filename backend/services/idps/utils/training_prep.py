"""
ShieldNet — IDPS Training Preparation Utility
Helps convert captured flows or datasets (CICIDS) into XGBoost-ready formats.
"""
import pandas as pd
from typing import List, Dict, Any
from backend.services.idps.features.flow_features import FeatureExtractor

def flows_to_dataframe(flows: List[Any]) -> pd.DataFrame:
    """Convert a list of Flow objects to a pandas DataFrame for training/analysis."""
    data = []
    for flow in flows:
        features = FeatureExtractor.extract_all(flow)
        data.append(features)
    return pd.DataFrame(data)

def preprocess_cicids(df: pd.DataFrame) -> pd.DataFrame:
    """Clean and normalize raw CICIDS dataset features."""
    # Mapping raw dataset columns to our internal FEATURE_ORDER
    # This would involve renaming columns and handling infinity/NaNs
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    return df
