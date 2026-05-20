#!/bin/bash
set -e
echo "[ShieldNet Setup]"
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python -m backend.db.init_db
echo ""
echo "Setup complete."
echo "Run: source .venv/bin/activate && uvicorn backend.main:app --port 8000 --reload"
echo "Dashboard: open http://127.0.0.1:8000/dashboard or serve dashboard.html on port 8080"
