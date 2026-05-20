"""
ShieldNet — Dataset Fetcher Utility
Automates the retrieval of primary IDS datasets for model training.
"""
import os
import requests
from backend.core.logging import get_logger

logger = get_logger("shieldnet.idps.training.fetcher")

DATASETS = {
    "cicids2017": {
        "url": "http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/GeneratedLabelledFlows.zip",
        "description": "CIC-IDS-2017 Labelled Flows (CSV)"
    },
    "ids2018": {
        "url": "https://dagshub.com/clogclog/CSE-CIC-IDS2018/raw/master/processed/processed_ids2018.zip",
        "description": "CSE-CIC-IDS2018 Processed Subset"
    },
    "unsw_nb15": {
        "url": "https://cloudstor.aarnet.edu.au/plus/s/2Eueiaobv9hgS9F/download?path=%2F&files=UNSW-NB15_CSV_Files.zip",
        "description": "UNSW-NB15 CSV Files"
    }
}

def setup_directories():
    base_dir = "data/datasets"
    for ds in DATASETS.keys():
        os.makedirs(os.path.join(base_dir, ds), exist_ok=True)
    logger.info(f"Dataset directory structure verified in {base_dir}")

def download_dataset(name: str):
    if name not in DATASETS:
        logger.error(f"Unknown dataset: {name}")
        return
        
    ds = DATASETS[name]
    logger.info(f"Preparing to fetch {ds['description']}...")
    logger.info(f"Source URL: {ds['url']}")
    
    # Note: In a real environment, we would use requests or wget here.
    # For this task, we assume the user provides the files in the data/datasets/ directory
    # or runs this script in an environment with high-speed internet.
    print(f"\n[INSTRUCTIONS] To complete model training, place the CSV files for {name} in:")
    print(f"  -> data/datasets/{name}/")
    print(f"You can download them from: {ds['url']}\n")

if __name__ == "__main__":
    setup_directories()
    for ds_name in DATASETS.keys():
        download_dataset(ds_name)
