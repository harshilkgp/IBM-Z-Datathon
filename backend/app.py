import os
import json
import time
import re
import ast # Added for robust JSON parsing
from flask import Flask, jsonify
import numpy as np
import requests
import joblib
# tensorflow is needed if you run this outside of an environment that has it pre-installed
# If running in an environment without TensorFlow, you must mock model loading or install it.
from tensorflow.keras.models import load_model

# --------------------------
# CONFIG & SECRETS
# --------------------------

# IMPORTANT: Load API key from environment variables for security.
# Replace 'YOUR_GEMINI_API_KEY' with the actual environment variable name if different.
# If running locally, you must set an environment variable named GEMINI_API_KEY.
# Example: export GEMINI_API_KEY="your-real-key-here"
GEMINI_API_KEY = "AIzaSyAI6EbiSlut3OMhsAjgnYvHs0wAGhgrXeg" # Uses environment variable
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent"
REPORT_MAX_TOKENS = 800
TEMPERATURE = 0.0
MAX_RETRIES = 3

# --------------------------
# APP INIT
# --------------------------
app = Flask(__name__)

# --------------------------
# LOAD MODELS & SCALERS
# --------------------------
# NOTE: This application expects 'best_model.h5', 'best_multiclass_model.h5',
# 'scaler1.gz', and 'scaler2.gz' to be in the same directory.
try:
    # Compile=False is standard when loading H5 models trained outside Keras compile context
    model1 = load_model("best_model.h5", compile=False)
    model2 = load_model("best_multiclass_model.h5", compile=False)
    scaler1 = joblib.load("scaler1.gz")
    scaler2 = joblib.load("scaler2.gz")
    MODELS_LOADED = True
    print("Models and scalers loaded successfully.")
except (IOError, FileNotFoundError, ImportError) as e:
    print(f"Error loading model or scaler files. Model features will be disabled: {e}")
    # Set to None and disable functionality if files are missing
    model1, model2, scaler1, scaler2 = None, None, None, None
    MODELS_LOADED = False

# --------------------------
# HELPER: clean/robust JSON parser
# --------------------------
def robust_parse_json(text_content):
    """
    Tries to convert Gemini output to valid JSON.
    1) Try json.loads first.
    2) If fails, fix unquoted keys and try again.
    3) If still fails, use ast.literal_eval.
    """
    try:
        return json.loads(text_content)
    except json.JSONDecodeError:
        # Fix unquoted keys like: attack_detected: true -> "attack_detected": true
        # This is a common issue when LLMs generate slightly malformed JSON.
        fixed = re.sub(r'([{,]\s*)(\w+)\s*:', r'\1"\2":', text_content)
        try:
            return json.loads(fixed)
        except json.JSONDecodeError:
            try:
                # Fallback to ast.literal_eval for dictionary-like structures
                return ast.literal_eval(fixed)
            except Exception as e:
                return {"error": "Failed to parse LLM response", "details": str(e), "raw_output": text_content}

# --------------------------
# HELPER: call Gemini API
# --------------------------
def call_gemini_with_json_request(system_prompt: str, user_prompt: str) -> dict:
    """
    Calls the Gemini API with a structured JSON request and handles exponential backoff.
    """
    if not GEMINI_API_KEY:
        return {"error": "GEMINI_API_KEY is missing. Cannot generate report."}

    api_url = f"{GEMINI_API_URL}?key={GEMINI_API_KEY}"

    # Define the strict JSON schema for the output report
    json_schema = {
        "type": "OBJECT",
        "properties": {
            "attack_detected": {"type": "BOOLEAN", "description": "True if an attack is highly probable."},
            "attack_type": {"type": "STRING", "description": "The specific type of attack (e.g., DoS, Probe, Normal)."},
            "confidence": {"type": "NUMBER", "description": "Overall confidence score (0.0 to 1.0) based on all models."},
            "ports": {"type": "ARRAY", "items": {"type": "INTEGER"}, "description": "List of key ports involved in the flow."},
            "description": {"type": "STRING", "description": "A concise, plain-language summary of the incident."},
            "recommended_mitigation": {"type": "ARRAY", "items": {"type": "STRING"}, "description": "Actionable steps to resolve the threat."},
            "feature_insights": {"type": "STRING", "description": "Explanation of which raw features were most indicative of the finding."}
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

            # Safe extraction of generated text from the structured response
            text_content = (
                data.get("candidates", [{}])[0]
                .get("content", {})
                .get("parts", [{}])[0]
                .get("text", "")
            )

            if not text_content.strip():
                raise ValueError("Empty text content from Gemini.")

            # Robust JSON parse
            return robust_parse_json(text_content)

        except requests.exceptions.HTTPError as e:
            if resp.status_code == 429:
                wait = 2 ** attempt
                print(f"Rate limit hit, retrying in {wait}s...")
                time.sleep(wait)
            else:
                print(f"HTTP Error: {e}, Response Body: {resp.text}")
                return {"error": f"HTTP Error: {resp.status_code}", "details": resp.text}
        except (KeyError, IndexError, ValueError, Exception) as e:
            print(f"Error processing Gemini response: {e}")
            # Ensure raw response is included for debugging
            raw_data_str = json.dumps(data) if 'data' in locals() else "N/A"
            return {"error": "Failed to process Gemini response", "details": str(e), "raw_response": raw_data_str}

    # If all retries fail
    return {"error": "Failed to call Gemini API after multiple retries due to rate limiting or persistent error."}

# --------------------------
# HELPER: build prompt for LLM
# --------------------------
def build_llm_prompt(raw_features, model_results):
    """Formats the data for the LLM to analyze."""
    lines = []
    lines.append("Analyze the following network flow data and the predictions from our internal ML models.")
    lines.append(f"--- Data for Analysis ---")
    lines.append(f"- Model 1 (Binary Attack Detection) Probability of Attack: {model_results['model1_prob']:.6f}")
    lines.append(f"- Model 2 (Multiclass Attack Classifier) Triggered: {model_results['triggered']}")
    if model_results['triggered'] and model_results.get("model2_raw"):
        # Model 2 raw output is used to inform the attack_type
        raw_scores = [f"{x:.2e}" for x in model_results['model2_raw']]
        lines.append(f"- Model 2 Raw Classification Scores (5 classes): {raw_scores}")
    
    # Extract the destination port, which is the first feature in this dataset format
    dest_port = raw_features[0][0] if raw_features and raw_features[0] else 'N/A'
    lines.append(f"- Destination Port Feature: {dest_port}")
    # Show a sample of input features to give context on the data's scale
    lines.append(f"- Sample of Raw Input Features (first 5): {raw_features[0][:5] if raw_features else 'N/A'}")
    lines.append("--- End of Data ---")
    lines.append("\nBased on all this data, provide your expert analysis in the required JSON format. Assume the 5 Model 2 classes correspond to (Normal, DoS, Probe, R2L, U2R) in that order.")
    return "\n".join(lines)

# --------------------------
# ROUTES
# --------------------------
@app.route("/", methods=["GET"])
def root():
    return "Cybersecurity Analysis Server with Gemini is running ✅"

@app.route("/predict_random", methods=["GET"])
def predict_random():
    if not MODELS_LOADED:
        return jsonify({
            "error": "Model files are missing or failed to load. Please ensure 'best_model.h5', 'best_multiclass_model.h5', 'scaler1.gz', and 'scaler2.gz' are available.",
            "note": "The LLM report functionality requires the ML models to provide input data."
        }), 503
    
    try:
        # Static example data point known to represent an attack (based on the original data structure)
        x_raw = np.array([[80, 3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 666666.6667,
                            3, 0, 3, 3, 3, 3, 0, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 64,
                            0, 666666.6667, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
                            0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 251, -1, 0,
                            32, 0, 0, 0, 0, 0, 0, 0, 0, 1]])

        # 1. Model 1 (Binary Classification: Attack or Normal)
        x1 = scaler1.transform(x_raw)
        pred1 = model1.predict(x1)
        p_attack = float(pred1[0][0])
        result = {"model1_prob": p_attack, "triggered": False, "model2_raw": None}

        # 2. Model 2 (Multiclass Classification) - only run if Model 1 detects an attack
        if p_attack > 0.5:
            x2 = scaler2.transform(x_raw)
            pred2 = model2.predict(x2)
            result["model2_raw"] = [float(x) for x in np.ravel(pred2)]
            result["triggered"] = True

        # 3. Gemini Report Generation
        system_prompt = "You are a senior cybersecurity analyst. Your role is to interpret the provided ML model outputs and network flow features to generate a security incident report. The output must strictly be a JSON object conforming to the required schema. Ensure the confidence score reflects the strongest prediction and the description is concise."
        user_prompt = build_llm_prompt(x_raw.tolist(), result)
        llm_json_report = call_gemini_with_json_request(system_prompt, user_prompt)

        return jsonify({
            "ml_pipeline_results": result,
            "gemini_analyst_report": llm_json_report
        })

    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred during prediction: {str(e)}"}), 500

# --------------------------
# RUN APP
# --------------------------
if __name__ == "__main__":
    # The debug flag is useful for local development
    app.run(debug=True, host="127.0.0.1", port=5000)
