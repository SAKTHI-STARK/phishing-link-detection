import numpy as np
import pickle
import warnings
import logging
import os
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
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

# Mount static files
os.makedirs("static", exist_ok=True)
phisingServer.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


@phisingServer.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


@phisingServer.post("/analyze")
async def analyze(entry: URLEntry):
    url = entry.url.strip()

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

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

        # --- Rule-based overrides for obvious phishing patterns ---
        fd = obj.features_dict
        red_flags = []

        if fd.get("UsingIP") == -1:
            red_flags.append("IP address instead of domain")
        if fd.get("NonStdPort") == -1:
            red_flags.append("Non-standard port")
        if fd.get("HTTPS") in (-1, -2):
            red_flags.append("No HTTPS / SSL issue")
        if fd.get("PrefixSuffix-") == -1:
            red_flags.append("Suspicious prefix/suffix in domain")
        if obj.connection_failed:
            red_flags.append("Site unreachable")
        if obj.ssl_error:
            red_flags.append("SSL certificate error")

        # If multiple strong red flags exist, override the model
        if len(red_flags) >= 3 and is_safe:
            is_safe = False
            phishing_prob = max(phishing_prob, 0.85)
            safe_prob = 1.0 - phishing_prob
            logger.info(f"Rule override: {red_flags}")
        elif len(red_flags) >= 2 and fd.get("UsingIP") == -1 and is_safe:
            # IP + any other red flag = override
            is_safe = False
            phishing_prob = max(phishing_prob, 0.75)
            safe_prob = 1.0 - phishing_prob
            logger.info(f"Rule override (IP+flag): {red_flags}")

        if is_safe:
            msg = f"It is {safe_prob*100:.2f}% safe to go."
        else:
            msg = f"It is {phishing_prob*100:.2f}% unsafe (phishing detected)."

        ssl_status = fd.get("HTTPS", -1)
        if ssl_status == 1:
            ssl_info = "Trusted CA (Verified)"
        elif ssl_status == 0:
            ssl_info = "Untrusted / Self-signed"
        elif ssl_status == -2:
            ssl_info = "Link Broken / Site Down"
        else:
            ssl_info = "No SSL (Plain HTTP)"

        return {
            "url": url,
            "is_safe": is_safe,
            "safe_score": round(safe_prob, 4),
            "phishing_score": round(phishing_prob, 4),
            "prediction": "Safe" if is_safe else "Phishing",
            "ssl_info": ssl_info,
            "red_flags": red_flags if red_flags else None,
            "message": msg
        }

    except Exception as e:
        logger.exception(e)
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(phisingServer, host="127.0.0.1", port=8000)
