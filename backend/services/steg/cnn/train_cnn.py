"""
ShieldNet — Pipeline B: EfficientNet-B0 Fine-tuning
Fine-tunes on BOSS/BOWS2 steganography detection dataset.
Run: python -m backend.services.steg.cnn.train_cnn
"""
from __future__ import annotations

import os
import random
from pathlib import Path

DATA_DIR = Path("data/steg_dataset")
MODEL_OUT = Path("models/steg_cnn.pth")
EPOCHS = 10
LR = 1e-4
WEIGHT_DECAY = 1e-5
MIXUP_ALPHA = 0.4
BATCH_SIZE = 32
IMG_SIZE = 224


def _check_dataset() -> bool:
    clean_dir = DATA_DIR / "clean"
    steg_dir = DATA_DIR / "steg"
    if not clean_dir.exists() or not steg_dir.exists():
        print("\n[ERROR] Training dataset not found.")
        print(f"Expected structure:")
        print(f"  {DATA_DIR}/clean/   — clean (cover) images from BOSS/BOWS2")
        print(f"  {DATA_DIR}/steg/    — steganographic images (LSB, F5, OutGuess, etc.)")
        print("\nTo download BOSS/BOWS2:")
        print("  https://dde.binghamton.edu/download/steganalysis_datasets/")
        print("  After downloading, place cover images in data/steg_dataset/clean/")
        print("  and steg images (run steghide/F5/openstego) in data/steg_dataset/steg/")
        print("\nFor a quick synthetic test dataset, run:")
        print("  python backend/utils/testing/generate_steg_dataset.py")
        return False
    n_clean = len(list(clean_dir.glob("*.jpg")) + list(clean_dir.glob("*.png")))
    n_steg = len(list(steg_dir.glob("*.jpg")) + list(steg_dir.glob("*.png")))
    if n_clean < 10 or n_steg < 10:
        print(f"[ERROR] Too few images: {n_clean} clean, {n_steg} steg. Need at least 10 each.")
        return False
    print(f"[*] Dataset: {n_clean} clean + {n_steg} steg images found.")
    return True


def _mixup(x, y, alpha=0.4):
    """Apply mixup augmentation to a batch."""
    import torch
    lam = float(torch.distributions.Beta(alpha, alpha).sample())
    idx = torch.randperm(x.size(0))
    mixed_x = lam * x + (1 - lam) * x[idx]
    y_a, y_b = y, y[idx]
    return mixed_x, y_a, y_b, lam


def _mixup_criterion(criterion, pred, y_a, y_b, lam):
    return lam * criterion(pred, y_a) + (1 - lam) * criterion(pred, y_b)


def train_or_load_model():
    """
    Train EfficientNet-B0 on steg dataset or load existing model.
    Returns True if model is available (trained or pre-existing).
    """
    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)

    if MODEL_OUT.exists():
        print(f"[*] Model already exists at {MODEL_OUT}. Skipping training.")
        return True

    if not _check_dataset():
        return False

    try:
        import torch
        import torch.nn as nn
        import torchvision.models as tv_models
        import torchvision.transforms as T
        from torch.utils.data import Dataset, DataLoader
        from PIL import Image
    except ImportError as e:
        print(f"[ERROR] Missing dependency: {e}. Install torch and torchvision.")
        return False

    class StegDataset(Dataset):
        def __init__(self, transform):
            self.samples = []
            for p in (DATA_DIR / "clean").glob("*"):
                if p.suffix.lower() in (".jpg", ".jpeg", ".png", ".bmp"):
                    self.samples.append((str(p), 0))
            for p in (DATA_DIR / "steg").glob("*"):
                if p.suffix.lower() in (".jpg", ".jpeg", ".png", ".bmp"):
                    self.samples.append((str(p), 1))
            random.shuffle(self.samples)
            self.transform = transform

        def __len__(self): return len(self.samples)

        def __getitem__(self, idx):
            path, label = self.samples[idx]
            try:
                img = Image.open(path).convert("RGB")
                return self.transform(img), label
            except Exception:
                return torch.zeros(3, IMG_SIZE, IMG_SIZE), label

    transform = T.Compose([
        T.Resize((IMG_SIZE, IMG_SIZE)),
        T.RandomHorizontalFlip(),
        T.RandomVerticalFlip(),
        T.ToTensor(),
        T.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
    ])

    dataset = StegDataset(transform)
    split = int(0.8 * len(dataset))
    train_ds, val_ds = torch.utils.data.random_split(dataset, [split, len(dataset) - split])
    train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True, num_workers=2)
    val_loader = DataLoader(val_ds, batch_size=BATCH_SIZE, num_workers=2)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[*] Training on {device}")

    model = tv_models.efficientnet_b0(weights=tv_models.EfficientNet_B0_Weights.IMAGENET1K_V1)
    model.classifier[1] = nn.Linear(1280, 2)
    model = model.to(device)

    optimizer = torch.optim.Adam(model.parameters(), lr=LR, weight_decay=WEIGHT_DECAY)
    criterion = nn.CrossEntropyLoss()
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=EPOCHS)

    best_val_acc = 0.0
    for epoch in range(EPOCHS):
        model.train()
        train_loss = 0.0
        for x, y in train_loader:
            x, y = x.to(device), y.to(device)
            x_mix, y_a, y_b, lam = _mixup(x, y, MIXUP_ALPHA)
            optimizer.zero_grad()
            out = model(x_mix)
            loss = _mixup_criterion(criterion, out, y_a, y_b, lam)
            loss.backward()
            optimizer.step()
            train_loss += loss.item()
        scheduler.step()

        # Validation
        model.eval()
        correct = total = 0
        with torch.no_grad():
            for x, y in val_loader:
                x, y = x.to(device), y.to(device)
                out = model(x)
                preds = out.argmax(dim=1)
                correct += (preds == y).sum().item()
                total += y.size(0)
        val_acc = correct / max(total, 1)
        print(f"  Epoch {epoch+1}/{EPOCHS} — loss: {train_loss/len(train_loader):.4f}, "
              f"val_acc: {val_acc:.3f}")

        if val_acc > best_val_acc:
            best_val_acc = val_acc
            torch.save(model.state_dict(), MODEL_OUT)
            print(f"  [*] Saved best model (val_acc={val_acc:.3f})")

    print(f"\n[✓] Training complete. Best val_acc={best_val_acc:.3f}. Model saved to {MODEL_OUT}")
    return True


if __name__ == "__main__":
    train_or_load_model()
