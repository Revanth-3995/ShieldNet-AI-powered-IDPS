#!/bin/bash
set -e
echo "╔══════════════════════════════════════╗"
echo "║     ShieldNet Setup                  ║"
echo "╚══════════════════════════════════════╝"

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "[1/4] Initializing database..."
python -m backend.db.init_db

echo "[2/4] Creating required directories..."
mkdir -p models quarantine data/clean data/steg logs

echo "[3/4] Seeding demo data (50 fake incidents for dashboard testing)..."
python backend/utils/testing/demo_seed.py

echo "[4/4] Checking CNN model..."
if [ -f "models/steg_cnn.pth" ]; then
  echo "  [+] CNN model found: models/steg_cnn.pth"
else
  echo "  [!] CNN model NOT found — steg detection will use statistical mode only."
  echo "      See TRAINING_GUIDE.md to train or generate the model."
fi

echo ""
echo "════════════════════════════════════════"
echo "Setup complete!"
echo ""
echo "Start backend:"
echo "  source .venv/bin/activate"
echo "  uvicorn backend.main:app --port 8000 --reload"
echo ""
echo "Open dashboard:"
echo "  Open dashboard.html in your browser (use Live Server or serve with:"
echo "  python -m http.server 8080  then visit http://localhost:8080/dashboard.html)"
echo ""
echo "Run demo:"
echo "  python apt_simulation.py"
echo "════════════════════════════════════════"
