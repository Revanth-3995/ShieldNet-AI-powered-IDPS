"""
ShieldNet — Deployment Validation
Checks if all models, pipelines, and engine components are ready for production.
"""
import os
import torch
import pickle
from backend.services.idps.detector import IDPSEngine
from backend.core.config import settings
from backend.core.logging import get_logger

logger = get_logger("shieldnet.idps.validation")

def validate_system():
    logger.info("Starting ShieldNet Deployment Validation...")
    
    # 1. Check Model Weights
    models_to_check = [
        str(settings.ai.IDPS_MODEL_PATH),
        "backend/services/idps/models/weights/bilstm_ids.pth"
    ]
    
    for m in models_to_check:
        if os.path.exists(m):
            logger.info(f"OK: Model found at {m}")
        else:
            logger.warning(f"MISSING: Model not found at {m}")
            
    # 2. Test Engine Initialization
    try:
        engine = IDPSEngine()
        logger.info("OK: IDPS Engine initialized successfully.")
    except Exception as e:
        logger.error(f"FAILED: Engine initialization error: {e}")
        return False
        
    # 3. Test Feature Extraction
    from backend.services.idps.capture.flow_generator import Flow
    try:
        dummy_flow = Flow("test", "1.1.1.1", "2.2.2.2", 80, 443, "TCP")
        from backend.services.idps.features.feature_schema import FeatureExtractor
        features = FeatureExtractor.extract_all(dummy_flow)
        if features:
            logger.info("OK: Feature extraction working.")
        else:
            logger.error("FAILED: Feature extraction returned empty.")
    except Exception as e:
        logger.error(f"FAILED: Feature extraction error: {e}")
        
    logger.info("Validation complete.")
    return True

if __name__ == "__main__":
    validate_system()
