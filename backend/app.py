from flask import Flask, request, jsonify
import numpy as np
from tensorflow.keras.models import load_model

# --------------------------
# Initialize Flask app
# --------------------------
app = Flask(__name__)

# --------------------------
# Load your models once
# --------------------------
# Replace with your actual model paths
model1 = load_model('best_model.h5', compile=False)
model2 = load_model('best_multiclass_model.h5', compile=False)

# --------------------------
# GET route to check server
# --------------------------
@app.route('/', methods=['GET'])
def home():
    print("GET request received at /")
    return "Server is running ✅"

# --------------------------
# Prediction route
# --------------------------
@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.json
        print("Received POST request with data:", data)

        # Convert features to NumPy array
        x_input = np.array(data['features']).reshape(1, -1)

        # Model 1 prediction (binary)
        pred1 = model1.predict(x_input)
        print("Model 1 output:", pred1)

        result = {'model1_output': float(pred1[0][0])}

        # Trigger Model 2 only if Model 1 predicts > 0.5
        if pred1[0][0] > 0.5:
            pred2 = model2.predict(x_input)
            print("Model 2 output:", pred2)
            result['model2_output'] = pred2.tolist()
            result['triggered'] = True
        else:
            result['model2_output'] = None
            result['triggered'] = False

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)})

# --------------------------
# Run the Flask app
# --------------------------
if __name__ == '__main__':
    app.run(debug=True)
