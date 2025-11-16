#!/usr/bin/env python
# validate_model.py - Validate model predictions make sense

import pickle
import pandas as pd
import numpy as np
from sklearn.metrics import confusion_matrix, classification_report

# Load artifacts
print("Loading model...")
with open('model/model.bin', 'rb') as f:
    model = pickle.load(f)
with open('model/dv.bin', 'rb') as f:
    dv = pickle.load(f)
with open('model/scaler.bin', 'rb') as f:
    scaler = pickle.load(f)

# Load dataset
print("Loading dataset...")
df = pd.read_csv('data/security_intrusion_dataset.csv')
df.columns = df.columns.str.lower().str.replace(' ', '_')
df["encryption_used"] = df["encryption_used"].fillna("No_enc")

categorical_columns = list(df.dtypes[df.dtypes == 'object'].index)
for c in categorical_columns:
    df[c] = df[c].str.lower().str.replace(' ', '_')

# Take some clearly normal and clearly attack sessions
print("\n" + "="*80)
print("VALIDATING MODEL ON KNOWN GOOD/BAD SESSIONS")
print("="*80)

# Get 5 normal sessions with best characteristics
normal_sessions = df[
    (df['attack_detected'] == 0) &
    (df['failed_logins'] == 0) &
    (df['ip_reputation_score'] > 0.8)
].head(5)

# Get 5 attack sessions with worst characteristics  
attack_sessions = df[
    (df['attack_detected'] == 1) &
    (df['failed_logins'] > 5) &
    (df['ip_reputation_score'] < 0.3)
].head(5)

print("\n" + "-"*80)
print("Testing on NORMAL sessions (should predict 0)")
print("-"*80)

FEATURES = ['protocol_type', 'encryption_used', 'browser_type', 
            'network_packet_size', 'login_attempts', 'session_duration',
            'ip_reputation_score', 'failed_logins', 'unusual_time_access']

for idx, row in normal_sessions.iterrows():
    session = row[FEATURES].to_dict()
    
    X = dv.transform([session])
    X_scaled = scaler.transform(X)
    prob = model.predict_proba(X_scaled)[0, 1]
    pred = int(prob >= 0.5)
    
    status = "✓ CORRECT" if pred == 0 else "✗ WRONG"
    print(f"\nSession {idx}: {status}")
    print(f"  failed_logins={session['failed_logins']}, "
          f"ip_score={session['ip_reputation_score']:.2f}, "
          f"encryption={session['encryption_used']}")
    print(f"  Predicted: {pred}, Probability: {prob:.4f}, Actual: 0")

print("\n" + "-"*80)
print("Testing on ATTACK sessions (should predict 1)")
print("-"*80)

for idx, row in attack_sessions.iterrows():
    session = row[FEATURES].to_dict()
    
    X = dv.transform([session])
    X_scaled = scaler.transform(X)
    prob = model.predict_proba(X_scaled)[0, 1]
    pred = int(prob >= 0.5)
    
    status = "✓ CORRECT" if pred == 1 else "✗ WRONG"
    print(f"\nSession {idx}: {status}")
    print(f"  failed_logins={session['failed_logins']}, "
          f"ip_score={session['ip_reputation_score']:.2f}, "
          f"encryption={session['encryption_used']}")
    print(f"  Predicted: {pred}, Probability: {prob:.4f}, Actual: 1")

# Test on full dataset
print("\n" + "="*80)
print("FULL DATASET VALIDATION")
print("="*80)

df_clean = df.drop(columns=['session_id'])
y_true = df_clean['attack_detected'].values
df_clean = df_clean.drop(columns=['attack_detected'])

dicts = df_clean[FEATURES].to_dict(orient='records')
X = dv.transform(dicts)
X_scaled = scaler.transform(X)
y_pred = (model.predict_proba(X_scaled)[:, 1] >= 0.5).astype(int)

print("\nConfusion Matrix:")
cm = confusion_matrix(y_true, y_pred)
print(cm)
print(f"\nTrue Negatives (Normal→Normal): {cm[0,0]}")
print(f"False Positives (Normal→Attack): {cm[0,1]}")
print(f"False Negatives (Attack→Normal): {cm[1,0]}")
print(f"True Positives (Attack→Attack): {cm[1,1]}")

print("\nClassification Report:")
print(classification_report(y_true, y_pred))

# Calculate error rate on normal sessions
normal_mask = y_true == 0
normal_errors = (y_pred[normal_mask] != 0).sum()
total_normal = normal_mask.sum()
error_rate = normal_errors / total_normal * 100

print(f"\n🚨 False Positive Rate (Normal flagged as Attack): {error_rate:.2f}%")
print(f"   ({normal_errors} out of {total_normal} normal sessions)")

if error_rate > 25:
    print("\n⚠️  WARNING: Model has high false positive rate!")
    print("   This means many normal sessions are incorrectly flagged as attacks.")
    print("   Consider retraining with different parameters or more data.")