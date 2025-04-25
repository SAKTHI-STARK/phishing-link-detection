from flask import Flask, request, render_template
import numpy as np
import pandas as pd
from sklearn import metrics
import warnings
import pickle
warnings.filterwarnings('ignore')
from feature import FeatureExtraction

# Load model from pickle file
model_path = "pickle/model.pkl"  # Ensure this path is relative, adjust accordingly
with open(model_path, "rb") as file:
    gbc = pickle.load(file)

# Initialize Flask app
app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        # Get the URL input from the form
        url = request.form["url"]
        
        # Feature extraction for the provided URL
        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1, -1)  # Ensure it is a 2D array

        # Predict the class (safe or unsafe)
        y_pred = gbc.predict(x)[0]  # y_pred will be either 1 or -1
        y_pro_phishing = gbc.predict_proba(x)[0, 0]  # Probability for phishing (class -1)
        y_pro_non_phishing = gbc.predict_proba(x)[0, 1]  # Probability for non-phishing (class 1)

        # Prepare prediction message
        if y_pred == 1:
            pred_message = f"It is {y_pro_non_phishing*100:.2f}% safe to go."
        else:
            pred_message = f"It is {y_pro_phishing*100:.2f}% unsafe (phishing detected)."

        # Return the results to the HTML template
        return render_template('index.html', xx=round(y_pro_non_phishing, 2), 
                               pred_message=pred_message, url=url)
    
    # If it's a GET request (first load), initialize with a default value
    return render_template("index.html", xx=-1, pred_message="Enter a URL to check.")

if __name__ == "__main__":
    app.run(debug=True)
