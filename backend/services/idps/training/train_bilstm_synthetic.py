"""
ShieldNet — Synthetic Sequence Model Trainer (BiLSTM)
Generates synthetic temporal sequences and trains the BiLSTM IDS classifier.
Saves checkpoint to models/bilstm_ids.pth.
Run: python -m backend.services.idps.training.train_bilstm_synthetic
"""
from __future__ import annotations

import os
import random
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

from backend.core.config import settings
from backend.core.logging import get_logger
from backend.services.idps.models.sequence_models.model_arch import BiLSTMIDS
from backend.services.idps.models.classical_ml.xgboost_detector import XGBoostDetector

logger = get_logger("shieldnet.idps.training.bilstm_synthetic")

CLASSES = ["Benign", "Bot", "DoS", "Infiltration", "Other", "PortScan"]
SEQ_LEN = 10
FEATURE_DIM = len(XGBoostDetector.FEATURES)
EPOCHS = 5
BATCH_SIZE = 64


def generate_synthetic_data(num_samples: int = 1000):
    """Generate synthetic sequential flow data matching XGBoostDetector features."""
    # We want to create SEQ_LEN flows for each sample
    # Shape: (num_samples, SEQ_LEN, FEATURE_DIM)
    X = np.zeros((num_samples, SEQ_LEN, FEATURE_DIM), dtype=np.float32)
    y = np.zeros(num_samples, dtype=np.int64)

    features = XGBoostDetector.FEATURES
    
    # Feature indices
    syn_idx = features.index("syn_flag_cnt") if "syn_flag_cnt" in features else -1
    duration_idx = features.index("flow_duration") if "flow_duration" in features else -1
    packets_idx = features.index("tot_fwd_pkts") if "tot_fwd_pkts" in features else -1
    bytes_idx = features.index("tot_len_fwd_pkts") if "tot_len_fwd_pkts" in features else -1

    for i in range(num_samples):
        # Choose class
        cls_idx = i % len(CLASSES)
        cls_name = CLASSES[cls_idx]
        y[i] = cls_idx

        # Generate SEQ_LEN sequential steps
        for step in range(SEQ_LEN):
            # Base benign flow
            flow = np.random.normal(loc=1.0, scale=0.2, size=FEATURE_DIM).astype(np.float32)
            
            # Apply class-specific behavior over sequence steps
            if cls_name == "Benign":
                pass
            elif cls_name == "DoS":
                # Escalating packet count, flags, duration
                if packets_idx != -1:
                    flow[packets_idx] = 100.0 + step * 20.0 + np.random.normal(0, 5)
                if syn_idx != -1:
                    flow[syn_idx] = 1.0 if step > 5 else 0.0
                if duration_idx != -1:
                    flow[duration_idx] = 50.0 + step * 10.0
            elif cls_name == "PortScan":
                # Short duration, sequential flow spikes
                if duration_idx != -1:
                    flow[duration_idx] = 0.1 + np.random.normal(0, 0.02)
                if packets_idx != -1:
                    flow[packets_idx] = 2.0
            elif cls_name == "Bot":
                # Periodic communication bursts
                if bytes_idx != -1:
                    flow[bytes_idx] = 500.0 if (step % 3 == 0) else 10.0
            elif cls_name == "Infiltration":
                # Long duration, low packets (stealthy)
                if duration_idx != -1:
                    flow[duration_idx] = 500.0 + step * 50.0
                if packets_idx != -1:
                    flow[packets_idx] = 5.0
            else:  # Other
                flow = flow * 2.0

            X[i, step, :] = flow

    return X, y


def train_bilstm():
    """Train sequence model on synthetic dataset."""
    model_path = settings.ai.BILSTM_MODEL_PATH
    model_path.parent.mkdir(parents=True, exist_ok=True)

    logger.info("Generating synthetic sequential training data...")
    X, y = generate_synthetic_data(1200)

    # Split into train/validation
    split = int(0.8 * len(X))
    X_train, X_val = X[:split], X[split:]
    y_train, y_val = y[:split], y[split:]

    train_ds = TensorDataset(torch.tensor(X_train), torch.tensor(y_train))
    val_ds = TensorDataset(torch.tensor(X_val), torch.tensor(y_val))

    train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=BATCH_SIZE, shuffle=False)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Training BiLSTM sequence model on device: {device}")

    model = BiLSTMIDS(
        input_dim=FEATURE_DIM,
        hidden_dim=128,
        num_layers=2,
        num_classes=len(CLASSES),
        dropout=0.2
    ).to(device)

    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)

    for epoch in range(EPOCHS):
        model.train()
        train_loss = 0.0
        correct = 0
        total = 0
        for batch_x, batch_y in train_loader:
            batch_x, batch_y = batch_x.to(device), batch_y.to(device)
            optimizer.zero_grad()
            outputs = model(batch_x)
            loss = criterion(outputs, batch_y)
            loss.backward()
            optimizer.step()
            
            train_loss += loss.item()
            _, preds = torch.max(outputs, 1)
            correct += (preds == batch_y).sum().item()
            total += batch_y.size(0)

        # Validation
        model.eval()
        val_correct = 0
        val_total = 0
        with torch.no_grad():
            for batch_x, batch_y in val_loader:
                batch_x, batch_y = batch_x.to(device), batch_y.to(device)
                outputs = model(batch_x)
                _, preds = torch.max(outputs, 1)
                val_correct += (preds == batch_y).sum().item()
                val_total += batch_y.size(0)

        logger.info(
            f"Epoch {epoch+1}/{EPOCHS} — "
            f"loss: {train_loss/len(train_loader):.4f}, "
            f"train_acc: {correct/total:.3f}, "
            f"val_acc: {val_correct/val_total:.3f}"
        )

    # Save format expected by BiLSTMDetector:
    # {"model_state_dict": ..., "classes": [...], "input_dim": ...}
    checkpoint = {
        "model_state_dict": model.state_dict(),
        "classes": CLASSES,
        "input_dim": FEATURE_DIM
    }
    torch.save(checkpoint, model_path)
    logger.info(f"BiLSTM sequence model saved to {model_path}")
    print(f"[SUCCESS] BiLSTM model trained and saved to {model_path}")


if __name__ == "__main__":
    train_bilstm()
