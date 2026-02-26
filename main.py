import numpy as np
import pickle
import warnings
import logging
import os
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from feature import FeatureExtraction

warnings.filterwarnings('ignore')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

phisingServer = FastAPI(title="Phishing Link Detection API")

class URLEntry(BaseModel):
    url: str

# Load model
model_path = os.path.join(os.path.dirname(__file__), "pickle", "model.pkl")
meta_path = os.path.join(os.path.dirname(__file__), "pickle", "features_metadata.pkl")

gbc = None
features_used = None


def load_model_assets():
    global gbc, features_used

    if os.path.exists(model_path):
        with open(model_path, "rb") as f:
            gbc = pickle.load(f)
        logger.info("Model loaded")

    if os.path.exists(meta_path):
        with open(meta_path, "rb") as f:
            features_used = pickle.load(f)


load_model_assets()


@phisingServer.get("/")
async def root():
    return {
        "message": "Phishing Link Detection API is running.",
    }


@phisingServer.post("/analyze")
async def analyze(entry: URLEntry):
    url = entry.url

    if not (url.startswith("http://") or url.startswith("https://")):
        raise HTTPException(
            status_code=400, 
            detail="Missing protocol. Please provide a full URL starting with 'http://' or 'https://'."
        )

    if gbc is None:
        raise HTTPException(status_code=503, detail="Model not loaded on server.")

    try:
        logger.info(f"Analyzing URL: {url}")

        obj = FeatureExtraction(url)
        features = obj.getFeaturesList(features_used)

        x = np.array(features).reshape(1, -1)

        y_pred = gbc.predict(x)[0]
        y_proba = gbc.predict_proba(x)[0]

        safe_prob = float(y_proba[1])
        phishing_prob = float(y_proba[0])

        is_safe = bool(y_pred == 1)
        
        if is_safe:
            msg = f"It is {safe_prob*100:.2f}% safe to go."
        else:
            msg = f"It is {phishing_prob*100:.2f}% unsafe (phishing detected)."

        return {
            "url": url,
            "is_safe": is_safe,
            "safe_score": round(safe_prob, 4),
            "phishing_score": round(phishing_prob, 4),
            "prediction": "Safe" if is_safe else "Phishing",
            "message": msg
        }

    except Exception as e:
        logger.exception(e)
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(phisingServer, host="0.0.0.0", port=8000)
