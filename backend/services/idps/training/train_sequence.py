"""
ShieldNet — Sequence Model Training (BiLSTM)
Detects temporal progression of attacks using sliding window flow analysis.
"""
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from backend.services.idps.training.dataset_manager import DatasetManager
from backend.services.idps.models.sequence_models.bilstm_detector import BiLSTMDetector
from backend.core.logging import get_logger

logger = get_logger("shieldnet.idps.training.sequence")

class SequenceTrainer:
    def __init__(self, window_size: int = 10):
        self.window_size = window_size
        self.dm = DatasetManager()
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    def prepare_sequences(self, X: np.ndarray, y: np.ndarray):
        """Convert flat flow features into 3D sequences (Samples, Window, Features)."""
        X_seq, y_seq = [], []
        for i in range(len(X) - self.window_size):
            X_seq.append(X[i:i + self.window_size])
            # Target is the label of the last packet in the sequence
            y_seq.append(y[i + self.window_size - 1])
        
        return np.array(X_seq), np.array(y_seq)

    def train(self, data_path: str, model_path: str = "models/bilstm_ids.pth"):
        """Train the BiLSTM temporal model."""
        df = self.dm.load_and_unify("cicids2017", data_path)
        if df.empty: return
        
        X, y, classes = self.dm.preprocess_for_training(df)
        X_seq, y_seq = self.prepare_sequences(X, y)
        
        # Split
        split = int(0.8 * len(X_seq))
        X_train, X_val = X_seq[:split], X_seq[split:]
        y_train, y_val = y_seq[:split], y_seq[split:]
        
        # DataLoaders
        train_ds = TensorDataset(torch.FloatTensor(X_train), torch.LongTensor(y_train))
        val_ds = TensorDataset(torch.FloatTensor(X_val), torch.LongTensor(y_val))
        
        train_loader = DataLoader(train_ds, batch_size=64, shuffle=True)
        val_loader = DataLoader(val_ds, batch_size=64)
        
        # Model
        input_dim = X.shape[1]
        output_dim = len(classes)
        model = BiLSTMDetector(input_dim, 64, output_dim).to(self.device)
        
        criterion = nn.CrossEntropyLoss()
        optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
        
        # Training loop
        logger.info(f"Training BiLSTM on {len(X_train)} sequences...")
        for epoch in range(10):
            model.train()
            total_loss = 0
            for batch_X, batch_y in train_loader:
                batch_X, batch_y = batch_X.to(self.device), batch_y.to(self.device)
                optimizer.zero_grad()
                outputs = model(batch_X)
                loss = criterion(outputs, batch_y)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            
            logger.info(f"Epoch {epoch+1}/10, Loss: {total_loss/len(train_loader):.4f}")
            
        torch.save(model.state_dict(), model_path)
        logger.info(f"Sequence model saved to {model_path}")

if __name__ == "__main__":
    trainer = SequenceTrainer()
    # trainer.train("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
