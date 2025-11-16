#!/usr/bin/env python
# test_service.py - Test the intrusion detection API

import requests

# API endpoint
url = 'http://localhost:9696/predict'

# Test cases
test_sessions = [
    {
        'name': 'Normal Session',
        'data': {
            'protocol_type': 'tcp',
            'encryption_used': 'aes',
            'browser_type': 'chrome',
            'network_packet_size': 1200,
            'login_attempts': 1,
            'session_duration': 600,
            'ip_reputation_score': 0.95,
            'failed_logins': 0,
            'unusual_time_access': 0
        }
    },
    {
        'name': 'Suspicious Session - Multiple Failed Logins',
        'data': {
            'protocol_type': 'tcp',
            'encryption_used': 'no_enc',
            'browser_type': 'firefox',
            'network_packet_size': 2000,
            'login_attempts': 15,
            'session_duration': 120,
            'ip_reputation_score': 0.3,
            'failed_logins': 10,
            'unusual_time_access': 1
        }
    },
    {
        'name': 'High Risk Session',
        'data': {
            'protocol_type': 'udp',
            'encryption_used': 'no_enc',
            'browser_type': 'safari',
            'network_packet_size': 3000,
            'login_attempts': 50,
            'session_duration': 30,
            'ip_reputation_score': 0.1,
            'failed_logins': 45,
            'unusual_time_access': 1
        }
    }
]


def test_health():
    """Test health endpoint"""
    print("Testing /health endpoint...")
    response = requests.get('http://localhost:9696/health')
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}\n")


def test_prediction(session_name, session_data):
    """Test prediction endpoint"""
    print(f"Testing: {session_name}")
    print(f"Session data: {session_data}")
    
    response = requests.post(url, json=session_data)
    
    if response.status_code == 200:
        result = response.json()
        print(f"✓ Prediction successful!")
        print(f"  Attack Probability: {result['attack_probability']:.4f}")
        print(f"  Attack Detected: {result['attack_detected']}")
        print(f"  Risk Level: {result['risk_level']}")
        
        if result['attack_detected']:
            print(f"🚨 WARNING: Attack detected!")
        else:
            print(f"✅ Session appears normal")
    else:
        print(f"✗ Error: {response.status_code}")
        print(f"  {response.json()}")
    
    print("-" * 80 + "\n")


def main():
    """Run all tests"""
    print("="*80)
    print("INTRUSION DETECTION API - TESTING")
    print("="*80 + "\n")
    
    # Test health endpoint
    try:
        test_health()
    except Exception as e:
        print(f"Health check failed: {e}")
        print("Make sure the service is running on http://localhost:9696\n")
        return
    
    # Test predictions
    for test in test_sessions:
        test_prediction(test['name'], test['data'])
    
    print("="*80)
    print("TESTING COMPLETE")
    print("="*80)


if __name__ == '__main__':
    main()