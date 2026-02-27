import numpy as np
import pickle
import warnings
import logging
import os
import uvicorn
from fastapi import FastAPI, HTTPException
from urllib.parse import urlparse
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

model = None
features_used = None


def load_model_assets():
    global model, features_used

    if os.path.exists(model_path):
        with open(model_path, "rb") as f:
            model = pickle.load(f)
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

    parsed_url = urlparse(url)
    if parsed_url.scheme not in ["http", "https"]:
        raise HTTPException(
            status_code=400, 
            detail="Invalid protocol. Please provide a full URL starting with 'http://' or 'https://'."
        )

    if model is None:
        raise HTTPException(status_code=503, detail="Model not loaded on server.")

    try:
        logger.info(f"Analyzing URL: {url}")

        obj = FeatureExtraction(url)
        await obj.extract()
        features = obj.getFeaturesList(features_used)

        x = np.array(features).reshape(1, -1)

        y_pred = model.predict(x)[0]
        y_proba = model.predict_proba(x)[0]

        safe_prob = float(y_proba[1])
        phishing_prob = float(y_proba[0])

        is_safe = bool(y_pred == 1)
        
        if is_safe:
            msg = f"It is {safe_prob*100:.2f}% safe to go."
        else:
            msg = f"It is {phishing_prob*100:.2f}% unsafe (phishing detected)."

        ssl_status = obj.features_dict.get("HTTPS", -1)
        if ssl_status == 1:
            ssl_info = "Trusted CA (Verified)"
        elif ssl_status == 0:
            ssl_info = "Untrusted / Self-signed"
        elif ssl_status == -2:
            ssl_info = "Link Broken / Site Down"
        else:
            ssl_info = "No SSL (Plain HTTP)"

        # Prepare feature breakdown
        feature_results = {}
        for name, value in obj.features_dict.items():
            if value == 1:
                status = "Pass"
            elif value == 0:
                status = "Suspicious"
            else:
                status = "Fail"
            feature_results[name] = status

        return {
            "url": url,
            "is_safe": is_safe,
            "prediction": "Safe" if is_safe else "Phishing",
            "safe_score": round(safe_prob, 4),
            "phishing_score": round(phishing_prob, 4),
            "ssl_info": ssl_info,
            "message": msg,
            "feature_breakdown": feature_results
        }

    except Exception as e:
        logger.exception(e)
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(phisingServer, host="0.0.0.0", port=8000)
