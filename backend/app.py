import os
import json
import time
from flask import Flask, jsonify
import numpy as np
import requests
import joblib
from tensorflow.keras.models import load_model

# --------------------------
# CONFIG
# --------------------------
# The API key is left as an empty string. The execution environment will
# automatically provide it.
GEMINI_API_KEY = "AIzaSyAI6EbiSlut3OMhsAjgnYvHs0wAGhgrXeg"
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent"
LLM_MODEL = "gemini-2.5-flash-preview-05-20"
REPORT_MAX_TOKENS = 800
TEMPERATURE = 0.0
MAX_RETRIES = 3  # for 429 errors

# --------------------------
# APP INIT
# --------------------------
app = Flask(__name__)

# --------------------------
# LOAD MODELS & SCALERS
# --------------------------
# Note: Ensure these model and scaler files are in the same directory.
# You might need to download them if you don't have them locally.
try:
    model1 = load_model("best_model.h5", compile=False)
    model2 = load_model("best_multiclass_model.h5", compile=False)
    scaler1 = joblib.load("scaler1.gz")
    scaler2 = joblib.load("scaler2.gz")
except (IOError, FileNotFoundError) as e:
    print(f"Error loading model or scaler files: {e}")
    print("Please ensure 'best_model.h5', 'best_multiclass_model.h5', 'scaler1.gz', and 'scaler2.gz' are present.")
    # Exit or handle gracefully if files are missing
    model1, model2, scaler1, scaler2 = None, None, None, None


# --------------------------
# HELPER: call Gemini API with structured JSON response
# --------------------------
def call_gemini_with_json_request(system_prompt: str, user_prompt: str) -> dict:
    """
    Calls the Gemini API, requesting a structured JSON response.
    Includes exponential backoff for rate limit errors (429).
    """
    api_url = f"{GEMINI_API_URL}?key={GEMINI_API_KEY}"

    # Define the JSON schema for the expected LLM response.
    # This ensures the model's output is in the correct format.
    json_schema = {
        "type": "OBJECT",
        "properties": {
            "attack_detected": {"type": "BOOLEAN"},
            "attack_type": {"type": "STRING"},
            "confidence": {"type": "NUMBER"},
            "ports": {"type": "ARRAY", "items": {"type": "INTEGER"}},
            "description": {"type": "STRING"},
            "recommended_mitigation": {"type": "ARRAY", "items": {"type": "STRING"}},
            "feature_insights": {"type": "STRING"}
        },
        "required": ["attack_detected", "attack_type", "confidence", "description"]
    }

    payload = {
        "contents": [{"parts": [{"text": user_prompt}]}],
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "generationConfig": {
            "temperature": TEMPERATURE,
            "maxOutputTokens": REPORT_MAX_TOKENS,
            "responseMimeType": "application/json",
            "responseSchema": json_schema
        }
    }

    headers = {"Content-Type": "application/json"}

    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.post(api_url, headers=headers, json=payload, timeout=45)
            resp.raise_for_status()
            data = resp.json()

            # Extract the generated text and parse it as JSON
            text_content = data["candidates"][0]["content"]["parts"][0]["text"]
            return json.loads(text_content)

        except requests.exceptions.HTTPError as e:
            if resp.status_code == 429:
                wait = 2 ** attempt
                print(f"Rate limit hit, retrying in {wait}s...")
                time.sleep(wait)
            else:
                print(f"HTTP Error: {e}")
                print(f"Response Body: {resp.text}")
                raise e
        except (KeyError, IndexError, json.JSONDecodeError) as e:
            print(f"Error parsing Gemini response: {e}")
            print(f"Raw Response: {data}")
            return {"error": "Failed to parse LLM response", "details": str(e)}

    raise RuntimeError("Failed to call Gemini API after multiple retries due to rate limiting.")

# --------------------------
# HELPER: build prompt for LLM
# --------------------------
def build_llm_prompt(raw_features, model_results):
    """
    Constructs the user prompt with the data for the LLM to analyze.
    """
    lines = []
    lines.append("Analyze the following network flow data and the predictions from our internal ML models.")
    lines.append(f"--- Data for Analysis ---")
    lines.append(f"- Model 1 (Binary Attack Detection) Probability of Attack: {model_results['model1_prob']:.6f}")
    lines.append(f"- Model 2 (Multiclass Attack Classifier) Triggered: {model_results['triggered']}")
    if model_results['triggered'] and model_results.get("model2_raw"):
        lines.append(f"- Model 2 Raw Classification Scores: {model_results['model2_raw']}")
    # The first feature is often 'Destination Port'
    lines.append(f"- Destination Port Feature: {raw_features[0][0] if raw_features and raw_features[0] else 'N/A'}")
    lines.append(f"- Sample of Raw Input Features (first 20): {raw_features[0][:20] if raw_features else 'N/A'}")
    lines.append("--- End of Data ---")
    lines.append("\nBased on all this data, provide your expert analysis in the required JSON format.")
    return "\n".join(lines)

# --------------------------
# ROUTES
# --------------------------
@app.route("/", methods=["GET"])
def root():
    return "Cybersecurity Analysis Server with Gemini is running ✅"

@app.route("/predict_random", methods=["GET"])
def predict_random():
    """
    Main endpoint to generate a random feature vector and run the full analysis pipeline.
    """
    if not all([model1, model2, scaler1, scaler2]):
        return jsonify({"error": "Models or scalers are not loaded. Cannot perform prediction."}), 500
    try:
        # 1) Generate a random input vector representing a network flow
        x_raw = np.random.rand(1, 78)

        # 2) Run Model 1 (Binary classifier: Benign vs. Attack)
        x1 = scaler1.transform(x_raw)
        pred1 = model1.predict(x1)
        p_attack = float(np.ravel(pred1)[0])
        result = {"model1_prob": p_attack, "triggered": False, "model2_raw": None}

        # 3) If Model 1 suspects an attack, trigger Model 2 (Multiclass classifier)
        if p_attack > 0.5:
            x2 = scaler2.transform(x_raw)
            pred2 = model2.predict(x2)
            result["model2_raw"] = [float(x) for x in np.ravel(pred2)]
            result["triggered"] = True

        # 4) Send the results to the Gemini API for a human-readable report
        system_prompt = "You are a senior cybersecurity analyst. Your task is to interpret ML model outputs related to network traffic and generate a concise, structured security report in JSON format. Provide clear, actionable insights."
        user_prompt = build_llm_prompt(x_raw.tolist(), result)
        llm_json_report = call_gemini_with_json_request(system_prompt, user_prompt)

        return jsonify({
            "ml_pipeline_results": result,
            "gemini_analyst_report": llm_json_report
        })

    except Exception as e:
        # Catch-all for any other errors during the process
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

# --------------------------
# RUN
# --------------------------
if __name__ == "__main__":
    # Use Gunicorn or another production-ready server in a real environment
    app.run(debug=True, host="127.0.0.1", port=5000)
