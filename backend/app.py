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
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
OPENAI_CHAT_URL = "https://api.openai.com/v1/chat/completions"
LLM_MODEL = "gpt-4o-mini"
REPORT_MAX_TOKENS = 600
TEMPERATURE = 0.0
MAX_RETRIES = 3  # for 429 errors

# --------------------------
# APP INIT
# --------------------------
app = Flask(__name__)

# --------------------------
# LOAD MODELS & SCALERS
# --------------------------
model1 = load_model("best_model.h5", compile=False)
model2 = load_model("best_multiclass_model.h5", compile=False)
scaler1 = joblib.load("scaler1.gz")
scaler2 = joblib.load("scaler2.gz")

# --------------------------
# HELPER: call LLM with retries on 429
# --------------------------
def call_llm_with_json_request(system_prompt: str, user_prompt: str) -> dict:
    if not OPENAI_API_KEY:
        raise RuntimeError("OPENAI_API_KEY not set in environment")

    payload = {
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": TEMPERATURE,
        "max_tokens": REPORT_MAX_TOKENS
    }

    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }

    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.post(OPENAI_CHAT_URL, headers=headers, json=payload, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            # extract LLM content
            text = data["choices"][0]["message"]["content"]
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                # fallback if not strict JSON
                start = text.find("{")
                end = text.rfind("}")
                if start != -1 and end != -1:
                    return json.loads(text[start:end+1])
                return {"llm_text": text}
        except requests.exceptions.HTTPError as e:
            if resp.status_code == 429:
                wait = 2 ** attempt
                print(f"Rate limit hit, retrying in {wait}s...")
                time.sleep(wait)
            else:
                raise e
    raise RuntimeError("Failed after retries due to rate limit")

# --------------------------
# HELPER: build prompt for LLM
# --------------------------
def build_llm_prompt_json(raw_features, model_results):
    lines = []
    lines.append("You are a senior cybersecurity analyst. Respond ONLY with JSON.")
    lines.append("")
    lines.append(f"- model1_attack_probability: {model_results['model1_prob']:.6f}")
    lines.append(f"- model2_triggered: {model_results['triggered']}")
    if model_results['triggered'] and model_results.get("model2_raw"):
        lines.append(f"- model2_raw_scores: {model_results['model2_raw']}")
    lines.append(f"- sample_features_first_20: {raw_features[0][:20]}")
    lines.append("")
    lines.append("Produce a JSON object with these keys:")
    lines.append(json.dumps({
        "attack_detected": "<bool>",
        "attack_type": "<str>",
        "confidence": "<float 0-1>",
        "ports": "<array of ints>",
        "description": "<str - why this is attack>",
        "recommended_mitigation": ["<list of steps>"],
        "feature_insights": "<str - notable features>"
    }, indent=2))
    lines.append("")
    lines.append("Use model outputs and features to infer attack type, ports, description, and mitigations. Return ONLY JSON.")
    return "\n".join(lines)

# --------------------------
# ROUTES
# --------------------------
@app.route("/", methods=["GET"])
def root():
    return "Server is running ✅"

@app.route("/predict_random", methods=["GET"])
def predict_random():
    try:
        # 1) Random input vector
        x_raw = np.random.rand(1, 78)

        # 2) Model 1
        x1 = scaler1.transform(x_raw)
        pred1 = model1.predict(x1)
        p_attack = float(np.ravel(pred1)[0])
        result = {"model1_prob": p_attack, "triggered": False, "model2_raw": None}

        # 3) Model 2 if triggered
        if p_attack > 0.5:
            x2 = scaler2.transform(x_raw)
            pred2 = model2.predict(x2)
            result["model2_raw"] = [float(x) for x in np.ravel(pred2)]
            result["triggered"] = True

        # 4) Build LLM prompt and call API
        prompt = build_llm_prompt_json(x_raw.tolist(), result)
        system_prompt = "You are a helpful cybersecurity analyst. Output ONLY JSON."
        llm_json = call_llm_with_json_request(system_prompt, prompt)

        return jsonify({
            "pipeline": result,
            "llm_report": llm_json
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --------------------------
# RUN
# --------------------------
if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
