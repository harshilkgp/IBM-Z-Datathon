# IBM-Z-Datathon

## Cybersecurity Analysis Solution

This project is a cybersecurity analysis server that leverages machine learning models and Google Gemini LLM to detect and analyze network attacks. It provides a REST API for predictions and generates human-readable reports for detected threats.

## File Structure

```
IBM-Z-Datathon/
│
├── backend/
│   ├── app.py                  # Flask API server
│   ├── best_model.h5           # Binary attack detection model
│   ├── best_multiclass_model.h5 # Multiclass attack classifier
│   ├── scaler1.gz              # Scaler for model 1
│   ├── scaler2.gz              # Scaler for model 2
│   └── requirements.txt        # Python dependencies
│
├── data_cleaning.ipynb         # Data cleaning notebook
├── IBM.ipynb                   # Main analysis notebook
├── README.md                   # Project documentation
```

## Backend API (`backend/app.py`)

The backend is a Flask server that loads two Keras models and two scalers. It exposes the following endpoints:

- `GET /` — Health check endpoint.
- `GET /predict_random` — Runs a sample prediction using random (hardcoded) network flow features, returns:
  - ML model results (probability of attack, multiclass scores)
  - A Gemini LLM-generated analyst report summarizing the threat and mitigation steps

### Example Response

```json
{
  "ml_pipeline_results": {
    "model1_prob": 0.87,
    "triggered": true,
    "model2_raw": [0.01, 0.95, 0.01, 0.01, 0.02]
  },
  "gemini_analyst_report": {
    "output": "ATTACK DETECTED: Type = Normal. Recommended mitigation: ..."
  }
}
```

## Setup & Usage

1. **Install dependencies:**

   ```sh
   cd backend
   pip install -r requirements.txt
   ```

2. **Ensure model and scaler files are present in `backend/`:**

   - `best_model.h5`, `best_multiclass_model.h5`, `scaler1.gz`, `scaler2.gz`

3. **Run the server:**

   ```sh
   python app.py
   ```

4. **Test the API:**
   - Open your browser or use curl/Postman:
     - [http://127.0.0.1:5000/](http://127.0.0.1:5000/) — Health check
     - [http://127.0.0.1:5000/predict_random](http://127.0.0.1:5000/predict_random) — Get a sample prediction

## Notebooks

- `data_cleaning.ipynb`: Data preprocessing and cleaning steps
- `IBM.ipynb`: Main analysis and modeling notebook

## Notes

- The Gemini API key is hardcoded in `app.py` for demonstration. For production, use environment variables or a config file.
- The LLM report requires working ML models and scalers.

---

For questions or contributions, please open an issue or pull request.
