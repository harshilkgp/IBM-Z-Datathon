from flask import Flask, jsonify
import numpy as np
from tensorflow.keras.models import load_model
import joblib  # requires scikit-learn installed

app = Flask(__name__)

# Load models once
model1 = load_model('best_model.h5', compile=False)
model2 = load_model('best_multiclass_model.h5', compile=False)

# Load scalers once
scaler1 = joblib.load('scaler1.gz')
scaler2 = joblib.load('scaler2.gz')

@app.route('/', methods=['GET'])
def home():
    print("GET request received at /")
    return "Server is running ✅"

@app.route('/predict', methods=['GET'])
def predict():
    try:
        # Generate random synthetic input (78 features)
        x_input = np.random.rand(1, 78)

        # Scale for Model 1
        x_input1 = scaler1.transform(x_input)
        pred1 = model1.predict(x_input1)
        print("Model 1 output:", pred1)

        result = {'model1_output': float(pred1[0][0])}

        # Trigger Model 2 if Model 1 > 0.5
        if pred1[0][0] > 0.5:
            x_input2 = scaler2.transform(x_input)
            pred2 = model2.predict(x_input2)
            print("Model 2 output:", pred2)
            result['model2_output'] = pred2.tolist()
            result['triggered'] = True
        else:
            result['model2_output'] = None
            result['triggered'] = False

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True)
