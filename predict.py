import pickle
import numpy as np



# Model paths
MODEL_FILE = 'model/model.bin'
DV_FILE = 'model/dv.bin'
SCALER_FILE = 'model/scaler.bin'


def load_model():
    """Load the trained model, DictVectorizer, and Scaler"""
    with open(MODEL_FILE, 'rb') as f_in:
        model = pickle.load(f_in)
    
    with open(DV_FILE, 'rb') as f_in:
        dv = pickle.load(f_in)
    
    with open(SCALER_FILE, 'rb') as f_in:
        scaler = pickle.load(f_in)
    
    return model, dv, scaler


def predict_single(session, model, dv, scaler):
    """Make prediction for a single session"""
    # Transform features
    X = dv.transform([session])
    X_scaled = scaler.transform(X)
    
    # Predict
    y_pred_proba = model.predict_proba(X_scaled)[0, 1]
    y_pred = y_pred_proba >= 0.5
    
    return float(y_pred_proba), bool(y_pred)


def main():
    """Example usage"""
    print("Loading model...")
    model, dv, scaler = load_model()
    print("Model loaded successfully!")
    
    # Example session
    session = {
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
    
    print("\nSession details:")
    for key, value in session.items():
        print(f"  {key}: {value}")
    
    # Make prediction
    probability, is_attack = predict_single(session, model, dv, scaler)
    
    print(f"\nPrediction Results:")
    print(f"  Attack Probability: {probability:.4f}")
    print(f"  Attack Detected: {'YES' if is_attack else 'NO'}")
    
    if is_attack:
        print("\n  🚨 WARNING: Potential security threat detected!")
    else:
        print("\n  ✅ Session appears normal")


if __name__ == '__main__':
    main()