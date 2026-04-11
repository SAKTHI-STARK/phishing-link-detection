import argparse
import asyncio
import csv
import logging
import os
import pickle
import random
import time
from urllib.parse import urlparse

import numpy as np

from feature import FeatureExtraction

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Same paths as in main.py
MODEL_PATH = os.path.join(os.path.dirname(__file__), "pickle", "model.pkl")
META_PATH = os.path.join(os.path.dirname(__file__), "pickle", "features_metadata.pkl")

async def analyze_url(url, model, features_used, semaphore):
    async with semaphore:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        try:
            parsed_url = urlparse(url)
            if parsed_url.scheme not in ["http", "https"]:
                return "Invalid protocol", False

            obj = FeatureExtraction(url)
            await obj.extract()
            features = obj.getFeaturesList(features_used)

            x = np.array(features).reshape(1, -1)

            y_pred = model.predict(x)[0]
            
            is_safe = bool(y_pred == 1)

            # Rule-based overrides
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
            overridden = False
            if len(red_flags) >= 3 and is_safe:
                is_safe = False
                overridden = True
            elif len(red_flags) >= 2 and fd.get("UsingIP") == -1 and is_safe:
                is_safe = False
                overridden = True

            prediction = "Safe" if is_safe else "Phishing"
            return prediction, overridden

        except Exception as e:
            return f"Error: {str(e)}", False

async def main():
    parser = argparse.ArgumentParser(description="Test Phishing Link Detection Model")
    parser.add_argument("--csv", default="Phishing URLs.csv", help="Path to CSV file with URLs")
    parser.add_argument("--samples", type=int, default=100, help="Number of URLs to test (default: 100)")
    parser.add_argument("--concurrency", type=int, default=10, help="Max concurrent requests (default: 10)")
    args = parser.parse_args()

    # Load model
    if not os.path.exists(MODEL_PATH) or not os.path.exists(META_PATH):
        logger.error(f"Model or metadata not found at expected paths.")
        return

    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    
    with open(META_PATH, "rb") as f:
        features_used = pickle.load(f)

    # Read CSV
    urls = []
    logger.info(f"Loading URLs from {args.csv}...")
    try:
        with open(args.csv, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader) # Skip header
            for row in reader:
                if len(row) >= 2:
                    urls.append((row[0], row[1])) # url, Type
    except Exception as e:
        logger.error(f"Error reading CSV: {e}")
        return

    if not urls:
        logger.error("No URLs loaded from CSV.")
        return

    # All labels in this specific dataset seem to be 'Phishing', but we'll adapt.
    # Take a random sample or all if less than specified
    sample_size = min(args.samples, len(urls))
    sampled_urls = random.sample(urls, sample_size)

    logger.info(f"Testing {sample_size} URLs with concurrency {args.concurrency}...")
    
    semaphore = asyncio.Semaphore(args.concurrency)
    
    tasks = []
    for url, actual_type in sampled_urls:
        tasks.append(analyze_url(url, model, features_used, semaphore))

    start_time = time.time()
    results = await asyncio.gather(*tasks)
    end_time = time.time()

    # Evaluate results
    correct = 0
    errors = 0
    overrides = 0
    safe_predictions = 0

    for i, (predicted_type, overridden) in enumerate(results):
        actual_type = sampled_urls[i][1]
        
        if "Error" in predicted_type or "Invalid protocol" in predicted_type:
            errors += 1
            # logger.warning(f"Failed to process {sampled_urls[i][0]}: {predicted_type}")
        else:
            if predicted_type == actual_type:
                correct += 1
            if predicted_type == "Safe":
                safe_predictions += 1
            if overridden:
                overrides += 1

    tested = sample_size - errors
    accuracy = (correct / tested * 100) if tested > 0 else 0.0

    logger.info("=" * 40)
    logger.info("TESTING COMPLETE")
    logger.info(f"Time Taken: {end_time - start_time:.2f} seconds")
    logger.info(f"Total Samples Requested: {sample_size}")
    logger.info(f"Successfully Analyzed: {tested}")
    logger.info(f"Errors/Invalid: {errors}")
    logger.info("=" * 40)
    logger.info(f"Accuracy (incl. Rules): {accuracy:.2f}% ({correct}/{tested})")
    logger.info(f"Safe Predictions (False Negatives if all Phishing): {safe_predictions}")
    logger.info(f"Predictions Corrected by Red Flags Rules: {overrides}")
    logger.info("=" * 40)

if __name__ == "__main__":
    asyncio.run(main())
