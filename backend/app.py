import os
import json
import time
import re
import ast
from flask import Flask, jsonify
import numpy as np
import requests
import joblib
from tensorflow.keras.models import load_model

GEMINI_API_KEY = "AIzaSyAI6EbiSlut3OMhsAjgnYvHs0wAGhgrXeg" 
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent"

REPORT_MAX_TOKENS = 4096 
TEMPERATURE = 0.0
MAX_RETRIES = 3


app = Flask(__name__)

try:

    model1 = load_model("best_model.h5", compile=False)
    model2 = load_model("best_multiclass_model.h5", compile=False)
    scaler1 = joblib.load("scaler1.gz")
    scaler2 = joblib.load("scaler2.gz")
    MODELS_LOADED = True
    print("Models and scalers loaded successfully.")
except (IOError, FileNotFoundError, ImportError) as e:
    print(f"Error loading model or scaler files. Model features will be disabled: {e}")

    model1, model2, scaler1, scaler2 = None, None, None, None
    MODELS_LOADED = False

def robust_parse_json(text_content):
  
    try:
        return json.loads(text_content)
    except json.JSONDecodeError:
        
        fixed = re.sub(r'([{,]\s*)(\w+)\s*:', r'\1"\2":', text_content)
        try:
            return json.loads(fixed)
        except json.JSONDecodeError:
            try:
                
                return ast.literal_eval(fixed)
            except Exception as e:
                return {"error": "Failed to parse LLM response", "details": str(e), "raw_output": text_content}

def call_gemini_with_json_request(system_prompt: str, user_prompt: str) -> dict:
    
   
    if not GEMINI_API_KEY:
        return {"error": "GEMINI_API_KEY is missing. Cannot generate report."}

    api_url = f"{GEMINI_API_URL}?key={GEMINI_API_KEY}"

    json_schema = {
        "type": "OBJECT",
        "properties": {
            "output": {"type": "STRING", "description": "A comprehensive summary string detailing the attack status, type, and mitigation steps."}
        },
        "required": ["output"]
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

            text_content = (
                data.get("candidates", [{}])[0]
                .get("content", {})
                .get("parts", [{}])[0]
                .get("text", "")
            )

            if not text_content.strip():
                raise ValueError("Empty text content from Gemini.")

            
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
            
            raw_data_str = json.dumps(data) if 'data' in locals() else "N/A"
            return {"error": "Failed to process Gemini response", "details": str(e), "raw_response": raw_data_str}

    return {"error": "Failed to call Gemini API after multiple retries due to rate limiting or persistent error."}

def build_llm_prompt(raw_features, model_results):
    
    lines = []
    lines.append("Analyze the following network flow data and the predictions from our internal ML models.")
    lines.append(f"--- Data for Analysis ---")
    lines.append(f"- Model 1 (Binary Attack Detection) Probability of Attack: {model_results['model1_prob']:.6f}")
    lines.append(f"- Model 2 (Multiclass Attack Classifier) Triggered: {model_results['triggered']}")
    if model_results['triggered'] and model_results.get("model2_raw"):
        
        raw_scores = [f"{x:.2e}" for x in model_results['model2_raw']]
        lines.append(f"- Model 2 Raw Classification Scores (5 classes): {raw_scores}")
    
    dest_port = raw_features[0][0] if raw_features and raw_features[0] else 0
    lines.append(f"- Destination Port Feature (Feature 1): {dest_port}")

    lines.append(f"- Sample of Raw Input Features (first 5): {raw_features[0][:5] if raw_features else 'N/A'}")
    lines.append("--- End of Data ---")
    

    lines.append(f"\nBased on all this data, you must generate a single string for the 'output' field. This string must contain the following information concisely and clearly, in this order: ")
    lines.append(f"1. A clear statement on whether an attack was detected (e.g., 'ATTACK DETECTED' or 'NO ATTACK').")
    
    lines.append(f"2. If an attack was detected, the most probable attack type, assuming the 5 Model 2 classes correspond to (DoS, Normal, Probe, R2L, U2R).")
    lines.append(f"3. One or two highly effective, immediate mitigation steps for the detected threat. If no attack is detected, recommend basic network monitoring steps.")
    lines.append(f"The final JSON output must strictly conform to the schema: {{\"output\": \"[Your analysis string here...]\"}}")
    
    return "\n".join(lines)

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
       
        x_raw = np.array([[80, 3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0,1000000, 2, 0, 2, 2, 2, 2, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 1000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 251, -1, 0, 32, 0, 0, 0, 0, 0, 0, 0]])

        x1 = scaler1.transform(x_raw)
        pred1 = model1.predict(x1)
        p_attack = float(pred1[0][0])
        result = {"model1_prob": p_attack, "triggered": False, "model2_raw": None}

        if p_attack > 0.5:
            x2 = scaler2.transform(x_raw)
            pred2 = model2.predict(x2)
            result["model2_raw"] = [float(x) for x in np.ravel(pred2)]
            result["triggered"] = True

    
        system_prompt = "You are a senior cybersecurity analyst. Your only task is to interpret the provided ML model outputs and network flow features and condense the findings into a single, comprehensive string formatted as a JSON object with only one key, 'output'. The string must clearly state the attack status, the attack type (if any), and actionable mitigation steps."
        
        user_prompt = build_llm_prompt(x_raw.tolist(), result)
        llm_json_report = call_gemini_with_json_request(system_prompt, user_prompt)

        return jsonify({
            "ml_pipeline_results": result,
            "gemini_analyst_report": llm_json_report # This now contains only {"output": "..."}
        })

    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred during prediction: {str(e)}"}), 500


if __name__ == "__main__":
    
    app.run(debug=True, host="127.0.0.1", port=5000)
