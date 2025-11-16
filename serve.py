import pickle
from flask import Flask, request, jsonify
from waitress import serve

# Model paths
MODEL_FILE = 'model/model.bin'
DV_FILE = 'model/dv.bin'
SCALER_FILE = 'model/scaler.bin'

# Load model artifacts
print("Loading model artifacts...")
with open(MODEL_FILE, 'rb') as f_in:
    model = pickle.load(f_in)

with open(DV_FILE, 'rb') as f_in:
    dv = pickle.load(f_in)

with open(SCALER_FILE, 'rb') as f_in:
    scaler = pickle.load(f_in)

print("Model loaded successfully!")

# Initialize Flask app
app = Flask('intrusion-detector')


def predict_session(session):
    """Make prediction for a session"""
    # Transform features
    X = dv.transform([session])
    X_scaled = scaler.transform(X)
    
    # Predict
    y_pred_proba = model.predict_proba(X_scaled)[0, 1]
    y_pred = y_pred_proba >= 0.5
    
    return {
        'attack_probability': float(y_pred_proba),
        'attack_detected': bool(y_pred),
        'risk_level': get_risk_level(y_pred_proba)
    }


def get_risk_level(probability):
    """Determine risk level based on probability"""
    if probability < 0.3:
        return 'low'
    elif probability < 0.7:
        return 'medium'
    else:
        return 'high'


@app.route('/predict', methods=['POST'])
def predict():
    """Prediction endpoint"""
    try:
        session = request.get_json()
        
        # Validate required fields
        required_fields = [
            'protocol_type', 'encryption_used', 'browser_type',
            'network_packet_size', 'login_attempts', 'session_duration',
            'ip_reputation_score', 'failed_logins', 'unusual_time_access'
        ]
        
        missing_fields = [field for field in required_fields if field not in session]
        if missing_fields:
            return jsonify({
                'error': f'Missing required fields: {missing_fields}'
            }), 400
        
        # Make prediction
        result = predict_session(session)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'intrusion-detection',
        'version': '1.0.0'
    })


@app.route('/', methods=['GET'])
def home():
    """Home endpoint with API documentation"""
    return jsonify({
        'service': 'Cybersecurity Intrusion Detection API',
        'version': '1.0.0',
        'endpoints': {
            'POST /predict': 'Make intrusion detection prediction',
            'GET /health': 'Health check',
            'GET /': 'API documentation'
        },
        'example_request': {
            'protocol_type': 'tcp',
            'encryption_used': 'aes',
            'browser_type': 'chrome',
            'network_packet_size': 1500,
            'login_attempts': 5,
            'session_duration': 300,
            'ip_reputation_score': 0.8,
            'failed_logins': 2,
            'unusual_time_access': 0
        }
    })


if __name__ == '__main__':
    # Use waitress for production-ready serving
    print("Starting Intrusion Detection API on port 9696...")
    serve(app, host='0.0.0.0', port=9696)