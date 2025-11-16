#!/usr/bin/env python
# test_service.py - Test the intrusion detection API

import requests

# API endpoint
host = "http://intrusion-detection-env.eba-beijepmj.eu-north-1.elasticbeanstalk.com"
url = f'{host}/predict'

# Test cases
test_sessions = [
    {
        'name': 'Normal Session (Typical in Training Data)',
        'data': {
            'protocol_type': 'tcp',
            'encryption_used': 'aes',
            'browser_type': 'chrome',
            'network_packet_size': 1200,
            'login_attempts': 4,        # Typical normal: 3-4
            'session_duration': 600,
            'ip_reputation_score': 0.30,  # Typical normal: ~0.30 (NOT 0.95!)
            'failed_logins': 1,          # Typical normal: 1
            'unusual_time_access': 0
        }
    },
    {
        'name': 'Suspicious Session - Higher Failed Logins',
        'data': {
            'protocol_type': 'tcp',
            'encryption_used': 'des',
            'browser_type': 'firefox',
            'network_packet_size': 1800,
            'login_attempts': 5,
            'session_duration': 400,
            'ip_reputation_score': 0.37,  # Typical attack: ~0.37
            'failed_logins': 2,          # Typical attack: ~2
            'unusual_time_access': 0
        }
    },
    {
        'name': 'High Risk Attack Session',
        'data': {
            'protocol_type': 'udp',
            'encryption_used': 'no_enc',
            'browser_type': 'unknown',
            'network_packet_size': 2500,
            'login_attempts': 6,
            'session_duration': 200,
            'ip_reputation_score': 0.45,  # Higher than typical
            'failed_logins': 3,          # Higher than typical
            'unusual_time_access': 1
        }
    }
]


def test_health():
    """Test health endpoint"""
    print("Testing /health endpoint...")
    response = requests.get(f'{host}/health')
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}\n")


def test_prediction(session_name, session_data):
    """Test prediction endpoint"""
    print(f"Testing: {session_name}")
    print(f"Session data: {session_data}")
    
    response = requests.post(url, json=session_data)
    
    if response.status_code == 200:
        result = response.json()
        print(f"Prediction successful!")
        print(f"  Attack Probability: {result['attack_probability']:.4f}")
        print(f"  Attack Detected: {result['attack_detected']}")
        print(f"  Risk Level: {result['risk_level']}")
        
        if result['attack_detected']:
            print(f"WARNING: Attack detected!")
        else:
            print(f"Session appears normal")
    else:
        print(f"✗ Error: {response.status_code}")
        print(f"  {response.json()}")
    
    print("-" * 20 + "\n")


def main():
    """Run all tests"""
    print("="*20)
    print("INTRUSION DETECTION API - TESTING")
    
    # Test health endpoint
    try:
        test_health()
    except Exception as e:
        print(f"Health check failed: {e}")
        print(f"Make sure the service is running on http://{host}\n")
        return
    
    # Test predictions
    for test in test_sessions:
        test_prediction(test['name'], test['data'])
    
    print("TESTING COMPLETE")


if __name__ == '__main__':
    main()