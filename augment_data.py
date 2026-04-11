import argparse
import asyncio
import csv
import logging
import os
import random
import time

import pandas as pd
from feature import FeatureExtraction
from config import DEFAULT_FEATURE_NAMES

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def extract_features(url, semaphore):
    async with semaphore:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        try:
            obj = FeatureExtraction(url)
            await obj.extract()
            # We want to return exactly the features in DEFAULT_FEATURE_NAMES
            features = obj.getFeaturesList(DEFAULT_FEATURE_NAMES)
            return features
        except Exception as e:
            logger.debug(f"Failed to extract {url}: {e}")
            return None

async def main():
    parser = argparse.ArgumentParser(description="Augment Dataset with New Phishing URLs")
    parser.add_argument("--original-csv", default="phishing dataset.csv", help="Original dataset")
    parser.add_argument("--new-csv", default="Phishing URLs.csv", help="New URLs to add")
    parser.add_argument("--output", default="phishing_augmented.csv", help="Output augmented dataset")
    parser.add_argument("--samples", type=int, default=1500, help="Number of URLs to extract")
    parser.add_argument("--concurrency", type=int, default=30, help="Max concurrent extractions")
    args = parser.parse_args()

    # Load new URLs
    if not os.path.exists(args.new_csv):
        logger.error(f"Cannot find new URL dataset at {args.new_csv}")
        return

    urls = []
    with open(args.new_csv, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader) # Skip header
        for row in reader:
            if len(row) >= 2:
                urls.append(row[0])

    if not urls:
        logger.error("No URLs loaded from source CSV.")
        return

    # Take a random sample
    sample_size = min(args.samples, len(urls))
    sampled_urls = random.sample(urls, sample_size)

    logger.info(f"Extracting features for {sample_size} new phishing URLs (Concurrency: {args.concurrency})...")
    
    semaphore = asyncio.Semaphore(args.concurrency)
    tasks = []
    for url in sampled_urls:
        tasks.append(extract_features(url, semaphore))

    start_time = time.time()
    results = await asyncio.gather(*tasks)
    end_time = time.time()

    logger.info(f"Feature extraction completed in {end_time - start_time:.2f} seconds.")

    # Filter out failed extractions (optional, but our exception handler catches most and defaults to -1, which is fine)
    # Actually, we should keep all results that are not None
    valid_results = [res for res in results if res is not None]

    logger.info(f"Successfully extracted {len(valid_results)} rows.")

    # Load original dataset
    if not os.path.exists(args.original_csv):
        logger.error(f"Cannot find original dataset at {args.original_csv}")
        return
        
    df_old = pd.read_csv(args.original_csv)
    
    # Check if 'Index' column exists and remove it for appending, or we can just ignore it
    # We will construct a DataFrame for the new data
    new_data = []
    for row in valid_results:
        # Create a dict from DEFAULT_FEATURE_NAMES to values
        row_dict = dict(zip(DEFAULT_FEATURE_NAMES, row))
        # Since all these are from 'Phishing URLs.csv', the class is -1 (Phishing)
        row_dict['class'] = -1
        # Add a dummy Index if original dataset requires it
        if 'Index' in df_old.columns:
            row_dict['Index'] = 0 
        new_data.append(row_dict)

    df_new = pd.DataFrame(new_data)
    
    # Ensure columns match old structure before concatenating
    # Missing columns will become NaN, which shouldn't happen if DEFAULT_FEATURE_NAMES is correct
    df_combined = pd.concat([df_old, df_new], ignore_index=True)

    # Rewrite the 'Index' column so it's sequential
    if 'Index' in df_combined.columns:
        df_combined['Index'] = range(1, len(df_combined) + 1)

    df_combined.to_csv(args.output, index=False)
    logger.info(f"Saved augmented dataset to {args.output}")
    logger.info(f"Old size: {len(df_old)}, New Size: {len(df_combined)}")

if __name__ == "__main__":
    asyncio.run(main())
