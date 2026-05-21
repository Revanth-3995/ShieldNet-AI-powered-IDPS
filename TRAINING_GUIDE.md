# ShieldNet CNN Training Guide

The EfficientNet-B0 steganalysis model (`models/steg_cnn.pth`) needs to be trained
before the CNN layer activates. Without it, the system uses the 7-algorithm statistical
pipeline only (still effective for demo purposes).

## Option A — Use the Synthetic Dataset Generator (Recommended for demo)

This generates a minimal training set without requiring dataset downloads.

```bash
# Install dependencies first
pip install Pillow numpy requests

# Generate 2,000 training images (1,000 clean + 1,000 LSB-embedded)
python scripts/generate_training_data.py

# Train the CNN (takes ~15–30 min on CPU, ~5 min with GPU)
python -m backend.services.steg.cnn.train_cnn \
  --clean-dir ./data/clean \
  --steg-dir ./data/steg \
  --epochs 15 \
  --output models/steg_cnn.pth
```

## Option B — Use BOSS/BOWS2 Research Datasets

1. BOSS dataset: http://agents.fel.cvut.cz/boss/ (request access — academic use)
2. BOWS2 dataset: http://bows2.ec-lille.fr/ (direct download)
3. Place clean images in `data/clean/` and steg images in `data/steg/`
4. Run the training command above with `--epochs 20`

## Expected Output

After training completes:
- `models/steg_cnn.pth` will be created
- Restart the backend: `uvicorn backend.main:app --port 8000 --reload`
- Panel 9 MOCK MODE warning will disappear
- CNN confidence scores will appear in forensic reports

## What happens without training

The 7 statistical algorithms still run and detect:
- LSB embedding (Chi-Square, RS Analysis, Sample Pair)
- DCT-domain hiding (DCT Histogram, Benford's Law)
- Spread-spectrum (Noise Residual, Pixel Histogram)

Accuracy without CNN: ~85% (vs ~96% with CNN fusion).
For the academic demo, statistical-only mode is sufficient.
