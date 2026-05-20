"""
ShieldNet — Dataset Manager
Handles loading, cleaning, and preprocessing of intrusion detection datasets.
Supports: CICIDS2017, CSE-CIC-IDS2018, UNSW-NB15
"""
import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler, LabelEncoder
from typing import Tuple, Dict, List, Optional
from backend.core.logging import get_logger

logger = get_logger("shieldnet.idps.training.dataset_manager")

class DatasetManager:
    ATTACK_TAXONOMY = {
        "benign": "Benign",
        "dos": "DoS", "ddos": "DoS", "slowloris": "DoS", "hulk": "DoS", "goldeneye": "DoS",
        "brute_force": "BruteForce", "ssh-patator": "BruteForce", "ftp-patator": "BruteForce",
        "portscan": "PortScan", "port_scan": "PortScan",
        "web_attack": "WebAttack", "sql_injection": "WebAttack", "xss": "WebAttack",
        "infiltration": "Infiltration", "bot": "Bot",
        "exploit": "Exploit", "fuzzers": "Exploit",
        "analysis": "Recon", "backdoor": "Infiltration"
    }

    # Strict column mapping for CICIDS2017/2018 to internal features
    CIC_MAPPER = {
        "flow_duration": "flow_duration",
        "total_fwd_packets": "tot_fwd_pkts", "total_backward_packets": "tot_bwd_pkts",
        "total_length_of_fwd_packets": "tot_len_fwd_pkts", "total_length_of_bwd_packets": "tot_len_bwd_pkts",
        "fwd_packet_length_max": "fwd_pkt_len_max", "fwd_packet_length_min": "fwd_pkt_len_min",
        "fwd_packet_length_mean": "fwd_pkt_len_mean", "fwd_packet_length_std": "fwd_pkt_len_std",
        "bwd_packet_length_max": "bwd_pkt_len_max", "bwd_packet_length_min": "bwd_pkt_len_min",
        "bwd_packet_length_mean": "bwd_pkt_len_mean", "bwd_packet_length_std": "bwd_pkt_len_std",
        "flow_bytes_s": "flow_byts_s", "flow_packets_s": "flow_pkts_s",
        "flow_iat_mean": "flow_iat_mean", "flow_iat_std": "flow_iat_std",
        "flow_iat_max": "flow_iat_max", "flow_iat_min": "flow_iat_min",
        "fwd_iat_total": "fwd_iat_tot", "bwd_iat_total": "bwd_iat_tot",
        "fwd_iat_std": "fwd_iat_std", "bwd_iat_std": "bwd_iat_std",
        "fin_flag_count": "fin_flag_cnt", "syn_flag_count": "syn_flag_cnt",
        "rst_flag_count": "rst_flag_cnt", "psh_flag_count": "psh_flag_cnt",
        "ack_flag_count": "ack_flag_cnt", "urg_flag_count": "urg_flag_cnt",
        "packet_length_mean": "pkt_len_mean", "average_packet_size": "pkt_size_avg"
    }

    def __init__(self, data_dir: str = "data/datasets"):
        self.data_dir = data_dir
        self.scaler = RobustScaler()
        self.label_encoder = LabelEncoder()
        
    def load_and_unify(self, dataset_name: str, file_name: str) -> pd.DataFrame:
        """Load a dataset, deduplicate, and map labels/features to ShieldNet schema."""
        loaders = {
            "cicids2017": self.load_cicids2017,
            "ids2018": self.load_ids2018,
            "unsw_nb15": self.load_unsw_nb15
        }
        
        if dataset_name not in loaders:
            return pd.DataFrame()
            
        df = loaders[dataset_name](file_name)
        if df.empty: return df
        
        # Deduplication (Eliminate redundant flows)
        original_len = len(df)
        df = df.drop_duplicates()
        if len(df) < original_len:
            logger.info(f"Deduplication: Removed {original_len - len(df)} redundant samples.")

        # Unify Labels
        df['label_unified'] = df['label'].astype(str).str.lower().str.replace('[^a-z0-9]', '_', regex=True)
        df['label_unified'] = df['label_unified'].apply(lambda x: self.ATTACK_TAXONOMY.get(x, "Other"))
        
        logger.info(f"Loaded {dataset_name}: {len(df)} unique samples.")
        return df

    def _map_columns(self, df: pd.DataFrame, mapper: Dict[str, str]) -> pd.DataFrame:
        """Map raw dataset columns to internal snake_case schema and derive computed features."""
        # Standardize raw names first
        df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_').str.replace(r'(/|\.)', '_', regex=True)
        # Rename using mapper
        df = df.rename(columns=mapper)
        # Drop duplicate columns (keep first) to prevent multi-column assignment errors
        df = df.loc[:, ~df.columns.duplicated()]

        # --- Derive ALL computed features from raw columns ---
        # Flag ratios
        if "syn_ack_ratio" not in df.columns and "syn_flag_cnt" in df.columns:
            df["syn_ack_ratio"] = df["syn_flag_cnt"] / (df.get("ack_flag_cnt", 0) + 1)
        if "rst_syn_ratio" not in df.columns and "rst_flag_cnt" in df.columns:
            df["rst_syn_ratio"] = df["rst_flag_cnt"] / (df.get("syn_flag_cnt", 0) + 1)

        # Burstiness & directional ratios
        if "fwd_burstiness" not in df.columns and "fwd_pkt_len_max" in df.columns:
            df["fwd_burstiness"] = df["fwd_pkt_len_max"] / (df["fwd_pkt_len_mean"] + 1e-6)
        if "fwd_pkts_bwd_pkts_ratio" not in df.columns and "tot_fwd_pkts" in df.columns:
            df["fwd_pkts_bwd_pkts_ratio"] = df["tot_fwd_pkts"] / (df["tot_bwd_pkts"] + 1)
        if "fwd_bytes_bwd_bytes_ratio" not in df.columns and "tot_len_fwd_pkts" in df.columns:
            df["fwd_bytes_bwd_bytes_ratio"] = df["tot_len_fwd_pkts"] / (df["tot_len_bwd_pkts"] + 1)

        # Asymmetry metrics
        if "pkt_count_asymmetry" not in df.columns and "tot_fwd_pkts" in df.columns:
            total_pkts = df["tot_fwd_pkts"] + df["tot_bwd_pkts"]
            df["pkt_count_asymmetry"] = (df["tot_fwd_pkts"] - df["tot_bwd_pkts"]) / (total_pkts + 1e-6)
        if "byte_count_asymmetry" not in df.columns and "tot_len_fwd_pkts" in df.columns:
            total_bytes = df["tot_len_fwd_pkts"] + df["tot_len_bwd_pkts"]
            df["byte_count_asymmetry"] = (df["tot_len_fwd_pkts"] - df["tot_len_bwd_pkts"]) / (total_bytes + 1e-6)

        # Log-scaled features
        if "log_flow_byts_s" not in df.columns and "flow_byts_s" in df.columns:
            df["log_flow_byts_s"] = np.log1p(df["flow_byts_s"].clip(lower=0))
        if "log_flow_pkts_s" not in df.columns and "flow_pkts_s" in df.columns:
            df["log_flow_pkts_s"] = np.log1p(df["flow_pkts_s"].clip(lower=0))
        if "log_tot_len_fwd_pkts" not in df.columns and "tot_len_fwd_pkts" in df.columns:
            df["log_tot_len_fwd_pkts"] = np.log1p(df["tot_len_fwd_pkts"].clip(lower=0))
        if "log_tot_len_bwd_pkts" not in df.columns and "tot_len_bwd_pkts" in df.columns:
            df["log_tot_len_bwd_pkts"] = np.log1p(df["tot_len_bwd_pkts"].clip(lower=0))

        # Payload entropy & dst_port_type cannot be derived from CIC CSVs — will remain zero
        # (These require raw packet payloads which CIC datasets don't include)

        return df

    def load_cicids2017(self, file_name: str) -> pd.DataFrame:
        path = os.path.join(self.data_dir, "cicids2017", file_name)
        if not os.path.exists(path): return pd.DataFrame()
        df = pd.read_csv(path, encoding='latin-1', low_memory=False)
        return self._map_columns(df, self.CIC_MAPPER)

    def load_ids2018(self, file_name: str) -> pd.DataFrame:
        path = os.path.join(self.data_dir, "ids2018", file_name)
        if not os.path.exists(path): return pd.DataFrame()
        df = pd.read_csv(path)
        return self._map_columns(df, self.CIC_MAPPER)

    def load_unsw_nb15(self, file_name: str) -> pd.DataFrame:
        path = os.path.join(self.data_dir, "unsw_nb15", file_name)
        if not os.path.exists(path): return pd.DataFrame()
        df = pd.read_csv(path)
        return df # UNSW requires separate mapping

    def preprocess_for_training(self, df: pd.DataFrame, target_col: str = "label_unified") -> Tuple[pd.DataFrame, np.ndarray, List[str]]:
        """Extract aligned features and encode labels. Fits the LabelEncoder."""
        from backend.services.idps.models.classical_ml.xgboost_detector import XGBoostDetector
        inference_features = XGBoostDetector.FEATURES
        
        X = pd.DataFrame(index=df.index)
        missing = []
        for f in inference_features:
            if f in df.columns:
                X[f] = df[f]
            else:
                X[f] = 0.0
                missing.append(f)
        
        if missing:
            logger.warning(f"Schema Gap: {len(missing)} features missing ({missing}).")
            
        X = X.replace([np.inf, -np.inf], 0).fillna(0)
        y = self.label_encoder.fit_transform(df[target_col])
        classes = list(self.label_encoder.classes_)
        
        return X, y, classes

    def preprocess_for_testing(self, df: pd.DataFrame, target_col: str = "label_unified") -> Tuple[pd.DataFrame, np.ndarray]:
        """Extract aligned features using the ALREADY-FITTED LabelEncoder (no re-fitting)."""
        from backend.services.idps.models.classical_ml.xgboost_detector import XGBoostDetector
        inference_features = XGBoostDetector.FEATURES
        
        X = pd.DataFrame(index=df.index)
        for f in inference_features:
            X[f] = df[f] if f in df.columns else 0.0

        X = X.replace([np.inf, -np.inf], 0).fillna(0)
        
        # Use transform (NOT fit_transform) to keep class indices aligned with training
        y = self.label_encoder.transform(df[target_col])
        
        return X, y

    def prepare_train_test(self, X: pd.DataFrame, y: np.ndarray, test_size: float = 0.2):
        """Split and scale WITHOUT leakage (Fit on train, transform test)."""
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42, stratify=y)
        
        # Isolated Scaling
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        return X_train_scaled, X_test_scaled, y_train, y_test

    def balance_dataset(self, X: np.ndarray, y: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Balance using random undersampling of majority class (fast, memory-safe)."""
        counts = np.bincount(y)
        if len(counts) < 2:
            return X, y
        
        # Target: undersample majority to 2x the median class size
        median_count = int(np.median(counts[counts > 0]))
        target_per_class = min(median_count * 2, max(counts))
        
        indices = []
        for cls in range(len(counts)):
            cls_indices = np.where(y == cls)[0]
            if len(cls_indices) > target_per_class:
                # Undersample
                chosen = np.random.RandomState(42).choice(cls_indices, target_per_class, replace=False)
                indices.extend(chosen)
            else:
                indices.extend(cls_indices)
        
        indices = np.array(indices)
        np.random.RandomState(42).shuffle(indices)
        logger.info(f"Balanced: {len(X)} -> {len(indices)} samples (undersampled majority).")
        return X[indices], y[indices]

