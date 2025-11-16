#!/usr/bin/env python
# debug_model.py - Diagnose why normal sessions are flagged as attacks

import pickle
import pandas as pd
import numpy as np

# Load model artifacts
print("Loading model artifacts...")
with open('model/model.bin', 'rb') as f:
    model = pickle.load(f)

with open('model/dv.bin', 'rb') as f:
    dv = pickle.load(f)

with open('model/scaler.bin', 'rb') as f:
    scaler = pickle.load(f)

print("Model loaded successfully!\n")

# Check what features the model expects
print("="*80)
print("FEATURE ANALYSIS")
print("="*80)
print(f"\nFeatures expected by DictVectorizer ({len(dv.feature_names_)}): ")
for i, feat in enumerate(dv.feature_names_, 1):
    print(f"{i:2d}. {feat}")

# Test normal session
normal_session = {
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

print("\n" + "="*80)
print("DEBUGGING NORMAL SESSION")
print("="*80)
print("\nInput session:")
for key, val in normal_session.items():
    print(f"  {key}: {val}")

# Transform step by step
print("\n" + "-"*80)
print("Step 1: DictVectorizer transformation")
print("-"*80)
X = dv.transform([normal_session])
print(f"Shape after DictVectorizer: {X.shape}")
print(f"Values: {X[0]}")

print("\n" + "-"*80)
print("Step 2: StandardScaler transformation")
print("-"*80)
X_scaled = scaler.transform(X)
print(f"Shape after scaling: {X_scaled.shape}")
print(f"Scaled values: {X_scaled[0]}")

print("\n" + "-"*80)
print("Step 3: Model prediction")
print("-"*80)
y_pred_proba = model.predict_proba(X_scaled)[0]
print(f"Probability [Normal, Attack]: {y_pred_proba}")
print(f"Attack probability: {y_pred_proba[1]:.4f}")
print(f"Prediction: {'ATTACK' if y_pred_proba[1] >= 0.5 else 'NORMAL'}")

# Check feature importance for this prediction
if hasattr(model, 'feature_importances_'):
    print("\n" + "="*80)
    print("FEATURE IMPORTANCE")
    print("="*80)
    importances = model.feature_importances_
    feature_importance = list(zip(dv.feature_names_, importances, X_scaled[0]))
    feature_importance.sort(key=lambda x: abs(x[1]), reverse=True)
    
    print("\nTop 10 most important features for this model:")
    for feat, importance, value in feature_importance[:10]:
        print(f"{feat:40s}: importance={importance:.4f}, scaled_value={value:7.3f}")

# Load original dataset to compare
print("\n" + "="*80)
print("COMPARING WITH TRAINING DATA")
print("="*80)

try:
    df = pd.read_csv('data/security_intrusion_dataset.csv')
    df.columns = df.columns.str.lower().str.replace(' ', '_')
    df["encryption_used"] = df["encryption_used"].fillna("No_enc")
    
    categorical_columns = list(df.dtypes[df.dtypes == 'object'].index)
    for c in categorical_columns:
        df[c] = df[c].str.lower().str.replace(' ', '_')
    
    print(f"\nDataset loaded: {df.shape}")
    print(f"\nUnique values in training data:")
    print(f"  protocol_type: {sorted(df['protocol_type'].unique())}")
    print(f"  encryption_used: {sorted(df['encryption_used'].unique())}")
    print(f"  browser_type: {sorted(df['browser_type'].unique())}")
    
    print("\n" + "-"*80)
    print("Checking if test values match training data")
    print("-"*80)
    
    for key in ['protocol_type', 'encryption_used', 'browser_type']:
        if key in normal_session:
            if normal_session[key] in df[key].values:
                print(f"✓ {key}='{normal_session[key]}' EXISTS in training data")
            else:
                print(f"✗ {key}='{normal_session[key]}' NOT FOUND in training data!")
                print(f"  Available values: {sorted(df[key].unique())}")
    
    # Check normal sessions in training data
    print("\n" + "="*80)
    print("NORMAL SESSIONS IN TRAINING DATA")
    print("="*80)
    
    normal_mask = (df['attack_detected'] == 0)
    normal_df = df[normal_mask]
    
    print(f"\nNormal sessions: {len(normal_df)} ({len(normal_df)/len(df)*100:.1f}%)")
    print(f"\nNormal session characteristics:")
    print(f"  failed_logins: mean={normal_df['failed_logins'].mean():.2f}, median={normal_df['failed_logins'].median():.1f}")
    print(f"  ip_reputation_score: mean={normal_df['ip_reputation_score'].mean():.2f}, median={normal_df['ip_reputation_score'].median():.2f}")
    print(f"  login_attempts: mean={normal_df['login_attempts'].mean():.2f}, median={normal_df['login_attempts'].median():.1f}")
    
    # Check attack sessions
    attack_mask = (df['attack_detected'] == 1)
    attack_df = df[attack_mask]
    
    print(f"\nAttack sessions: {len(attack_df)} ({len(attack_df)/len(df)*100:.1f}%)")
    print(f"\nAttack session characteristics:")
    print(f"  failed_logins: mean={attack_df['failed_logins'].mean():.2f}, median={attack_df['failed_logins'].median():.1f}")
    print(f"  ip_reputation_score: mean={attack_df['ip_reputation_score'].mean():.2f}, median={attack_df['ip_reputation_score'].median():.2f}")
    print(f"  login_attempts: mean={attack_df['login_attempts'].mean():.2f}, median={attack_df['login_attempts'].median():.1f}")
    
    # Find similar sessions
    print("\n" + "="*80)
    print("SIMILAR SESSIONS IN TRAINING DATA")
    print("="*80)
    
    similar = df[
        (df['protocol_type'] == 'tcp') &
        (df['encryption_used'] == 'aes') &
        (df['failed_logins'] == 0) &
        (df['ip_reputation_score'] > 0.9)
    ]
    
    print(f"\nFound {len(similar)} similar sessions in training data")
    if len(similar) > 0:
        print(f"Attack rate in similar sessions: {similar['attack_detected'].mean()*100:.1f}%")
        print(f"\nFirst 5 similar sessions:")
        print(similar[['protocol_type', 'encryption_used', 'failed_logins', 
                      'ip_reputation_score', 'login_attempts', 'attack_detected']].head())

except Exception as e:
    print(f"Could not load dataset: {e}")

print("\n" + "="*80)
print("DIAGNOSIS COMPLETE")
print("="*80)