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
from config import FEATURE_SEVERITY

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

def compute_severity_score(features_dict):
    accumulated_risk = 0.0
    red_flags = []
    
    severity_breakdown = {}
    
    for tier_name, tier_info in FEATURE_SEVERITY.items():
        weight = tier_info["weight"]
        tier_features = tier_info["features"]
        
        tier_flagged = 0
        tier_safe = 0
        tier_neutral = 0
        tier_total = len(tier_features)
        
        for feat_name in tier_features:
            val = features_dict.get(feat_name, 0)
            
            if val == -1:
                # Phishing indicator
                risk_contribution = 1.0 * weight
                tier_flagged += 1
            elif val == 0:
                # Neutral / Unavailable
                risk_contribution = 0.1 * weight
                tier_neutral += 1
            else:
                # Safe indicator
                risk_contribution = 0.0
                tier_safe += 1
            
            accumulated_risk += risk_contribution
            
        severity_breakdown[tier_name] = {
            "flagged": tier_flagged,
            "safe": tier_safe,
            "neutral": tier_neutral,
            "total": tier_total,
            "weight": weight
        }
    
    # Cap the maximum risk. 
    # With new weights, a score of 12.0 is considered 100% phishing from rules alone.
    MAX_EXPECTED_RISK = 12.0
    severity_phishing_score = min(1.0, accumulated_risk / MAX_EXPECTED_RISK)
    
    # Build human-readable red flags from Critical and High tiers
    flag_labels = {
        "UsingIP": "IP address instead of domain",
        "HTTPS": "No HTTPS / SSL issue",
        "ShortURL": "URL shortener detected",
        "StatsReport": "Matched known malicious URL/IP pattern",
        "AgeofDomain": "Very new domain (< 6 months)",
        "DomainRegLen": "Short domain registration period",
        "DNSRecording": "No or recent DNS record",
        "AbnormalURL": "URL doesn't match WHOIS record",
        "HTTPSDomainURL": "Deceptive 'https' token in domain name",
        "NonStdPort": "Non-standard port in URL",
        "SubDomains": "Excessive sub-domains",
        "PrefixSuffix-": "Suspicious hyphen in domain",
        "FreeHosting": "Hosted on a free provider",
        "DomainEntropy": "Suspicious / randomly generated domain name",
        "ServerFormHandler": "Server form handler is suspicious",
        "RequestURL": "Unsafe external resources",
        "AnchorURL": "Mostly external anchor links",
        "LinksInScriptTags": "Mostly external scripts linked",
        "WebsiteForwarding": "Multiple redirects detected",
        "IframeRedirection": "Hidden Iframe redirection",
        "DisableRightClick": "Right click disabled",
        "UsingPopupWindow": "Pop-up window on load"
    }
    
    for feat_name, label in flag_labels.items():
        if features_dict.get(feat_name) == -1:
            red_flags.append(label)
    
    # Add connection-level flags
    return severity_phishing_score, severity_breakdown, red_flags


def compute_final_score(model_phishing_prob, severity_phishing_score, severity_breakdown, features_dict, connection_failed, ssl_error):
    """
    Blend ML model probability with severity-weighted score to produce
    a final phishing probability. Apply tier-based override rules.
    
    Strategy:
        - Base: 70% ML model + 30% severity score
        - Override if critical/high indicators are overwhelming
        - Never override to phishing based only on low/medium flags
    
    Returns:
        final_phishing_prob (float): 0.0 = safe, 1.0 = phishing
        is_safe (bool): final verdict
        override_reason (str or None): explanation if overridden
    """
    # Count flags per tier
    critical_flagged = severity_breakdown["critical"]["flagged"]
    high_flagged = severity_breakdown["high"]["flagged"]
    medium_flagged = severity_breakdown["medium"]["flagged"]
    low_flagged = severity_breakdown["low"]["flagged"]
    
    # Base blended score: 70% ML + 30% severity
    blended = 0.70 * model_phishing_prob + 0.30 * severity_phishing_score
    
    override_reason = None
    is_safe = blended < 0.50  # Default threshold
    
    # Combo Rule: External anchors + external scripts + redirects
    comb_flags = sum(1 for feat in ["AnchorURL", "LinksInScriptTags", "WebsiteForwarding"] if features_dict.get(feat) == -1)
    
    # --- Tier-based override rules ---
    # These ensure we don't miss real phishing (preserve true positives)
    
    # Rule 1: Connection failure or SSL error is itself suspicious
    if connection_failed or ssl_error:
        extra_penalty = 0.15
        blended = min(1.0, blended + extra_penalty)
        if connection_failed:
            override_reason = "Site unreachable"
        elif ssl_error:
            override_reason = "SSL certificate error"
            
    # Rule Combo: Medium/High-Risk Combination -> force phishing
    if comb_flags >= 3:
        blended = max(blended, 0.85)
        is_safe = False
        if not override_reason: # Keep earlier connection error reason if any, or overwrite
            override_reason = "Suspicious combination: external resources and multiple redirects"
            
    # Rule 2: ≥ 2 Critical flags → force phishing
    elif critical_flagged >= 2:
        blended = max(blended, 0.90)
        is_safe = False
        override_reason = f"{critical_flagged} critical indicators flagged"
    
    # Rule 3: 1 Critical + ≥ 2 High flags → force phishing
    elif critical_flagged >= 1 and high_flagged >= 2:
        blended = max(blended, 0.85)
        is_safe = False
        override_reason = f"{critical_flagged} critical + {high_flagged} high indicators"
    
    # Rule 4: ≥ 4 High flags (no critical) → force phishing
    elif high_flagged >= 4:
        blended = max(blended, 0.80)
        is_safe = False
        override_reason = f"{high_flagged} high-severity indicators"
    
    # Rule 5: Only low/medium flags → trust the ML model (prevents false positives)
    elif critical_flagged == 0 and high_flagged == 0 and comb_flags < 3:
        # Pure ML decision — low/medium signals alone are not enough to override
        is_safe = model_phishing_prob < 0.50
        blended = model_phishing_prob  # Trust the model
    
    # For remaining cases, use the blended score
    else:
        is_safe = blended < 0.50
    
    # Clamp
    blended = max(0.0, min(1.0, blended))
    
    return blended, is_safe, override_reason


@phisingServer.post("/analyze")
async def analyze(entry: URLEntry):
    url = entry.url.strip()

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed_url = urlparse(url)
    if parsed_url.scheme not in ["http", "https"]:
        raise HTTPException(status_code=400, detail="Invalid protocol. Please provide a full URL starting with 'http://' or 'https://'.")

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

        model_safe_prob = float(y_proba[1])
        model_phishing_prob = float(y_proba[0])

        fd = obj.features_dict
        severity_phishing_score, severity_breakdown, red_flags = compute_severity_score(fd)
        if obj.connection_failed:
            red_flags.insert(0, "Site unreachable")
        if obj.ssl_error:
            red_flags.insert(0, "SSL certificate error")
        
        # --- Compute final blended score ---
        final_phishing_prob, is_safe, override_reason = compute_final_score(
            model_phishing_prob, severity_phishing_score, severity_breakdown,
            fd, obj.connection_failed, obj.ssl_error
        )
        
        final_safe_prob = 1.0 - final_phishing_prob
        
        if override_reason:
            logger.info(f"Score override: {override_reason} | Final phishing prob: {final_phishing_prob:.2f}")

        if is_safe:
            msg = f"It is {final_safe_prob*100:.2f}% safe to go."
        else:
            msg = f"It is {final_phishing_prob*100:.2f}% unsafe (phishing detected)."

        ssl_status = fd.get("HTTPS", -1)
        if ssl_status == 1:
            ssl_info = "Trusted CA (Verified)"
        elif ssl_status == 0:
            ssl_info = "Untrusted / Self-signed"
        elif ssl_status == -2:
            ssl_info = "Link Broken / Site Down"
        else:
            ssl_info = "No SSL (Plain HTTP)"

        # Build per-feature detail for frontend
        feature_labels = {
            "UsingIP": "Using IP Address",
            "LongURL": "URL Length",
            "ShortURL": "URL Shortener",
            "Symbol@": "@ Symbol in URL",
            "Redirecting//": "Double-Slash Redirect",
            "PrefixSuffix-": "Prefix/Suffix in Domain",
            "SubDomains": "Sub-Domain Count",
            "HTTPS": "HTTPS / SSL Certificate",
            "DomainRegLen": "Domain Registration Length",
            "Favicon": "Favicon Source",
            "NonStdPort": "Non-Standard Port",
            "HTTPSDomainURL": "HTTPS Token in Domain",
            "RequestURL": "External Request Resources",
            "AnchorURL": "Anchor URL Analysis",
            "LinksInScriptTags": "Links in Script Tags",
            "ServerFormHandler": "Server Form Handler",
            "InfoEmail": "Mail-to Link",
            "AbnormalURL": "Abnormal URL vs WHOIS",
            "WebsiteForwarding": "Website Forwarding",
            "StatusBarCust": "Status Bar Customization",
            "DisableRightClick": "Right-Click Disabled",
            "UsingPopupWindow": "Pop-up Window",
            "IframeRedirection": "Iframe Redirection",
            "AgeofDomain": "Age of Domain",
            "DNSRecording": "DNS Record",
            "PageRank": "Page Rank",
            "LinksPointingToPage": "Links Pointing to Page",
            "StatsReport": "Statistical Report",
            "DomainEntropy": "Domain Entropy (Randomness)",
            "FreeHosting": "Free Hosting Provider"
        }

        # Assign severity tier to each feature for frontend display
        feature_to_tier = {}
        for tier_name, tier_info in FEATURE_SEVERITY.items():
            for feat in tier_info["features"]:
                feature_to_tier[feat] = tier_name

        features_detail = {}
        for fname, fval in fd.items():
            features_detail[fname] = {
                "value": fval,
                "label": feature_labels.get(fname, fname),
                "severity": feature_to_tier.get(fname, "low"),
            }

        return {
            "url": url,
            "is_safe": is_safe,
            "safe_score": round(final_safe_prob, 4),
            "phishing_score": round(final_phishing_prob, 4),
            "prediction": "Safe" if is_safe else "Phishing",
            "ssl_info": ssl_info,
            "red_flags": red_flags if red_flags else None,
            "override_reason": override_reason,
            "message": msg,
            "features_detail": features_detail,
            "severity_breakdown": severity_breakdown,
            "model_raw": {
                "phishing_prob": round(model_phishing_prob, 4),
                "safe_prob": round(model_safe_prob, 4),
            }
        }

    except Exception as e:
        logger.exception(e)
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(phisingServer, host="127.0.0.1", port=8000)
