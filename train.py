
import pandas as pd
import numpy as np
import pickle
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction import DictVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, roc_auc_score, classification_report

# Parameters
DATA_PATH = 'data/security_intrusion_dataset.csv'
OUTPUT_MODEL = 'model/model.bin'
OUTPUT_DV = 'model/dv.bin'
OUTPUT_SCALER = 'model/scaler.bin'
RANDOM_STATE = 1
TEST_SIZE = 0.2
VAL_SIZE = 0.25

# Feature definitions
NUMERICAL = ['network_packet_size', 'login_attempts', 'session_duration', 
             'ip_reputation_score', 'failed_logins', 'unusual_time_access']

CATEGORICAL = ['protocol_type', 'encryption_used', 'browser_type']

TARGET = 'attack_detected'


def load_and_prepare_data(file_path):
    """Load and prepare the dataset"""
    print(f"Loading data from {file_path}...")
    df = pd.read_csv(file_path)
    
    # Standardize column names
    df.columns = df.columns.str.lower().str.replace(' ', '_')
    
    # Handle missing values
    df["encryption_used"] = df["encryption_used"].fillna("No_enc")
    
    # Standardize categorical values
    categorical_columns = list(df.dtypes[df.dtypes == 'object'].index)
    for c in categorical_columns:
        df[c] = df[c].str.lower().str.replace(' ', '_')
    
    print(f"Dataset shape: {df.shape}")
    print(f"Attack rate: {df[TARGET].mean():.4f}")
    
    return df


def split_data(df):
    """Split data into train/val/test sets"""
    print("\nSplitting data...")
    
    # First split: train+val vs test
    df_full_train, df_test = train_test_split(
        df, test_size=TEST_SIZE, random_state=RANDOM_STATE
    )
    
    # Second split: train vs val
    df_train, df_val = train_test_split(
        df_full_train, test_size=VAL_SIZE, random_state=RANDOM_STATE
    )
    
    # Reset indices
    df_train = df_train.reset_index(drop=True)
    df_val = df_val.reset_index(drop=True)
    df_test = df_test.reset_index(drop=True)
    df_full_train = df_full_train.reset_index(drop=True)
    
    print(f"Train size: {len(df_train)}")
    print(f"Validation size: {len(df_val)}")
    print(f"Test size: {len(df_test)}")
    print(f"Full train size: {len(df_full_train)}")
    
    return df_train, df_val, df_test, df_full_train


def prepare_features(df_train, df_val, df_test):
    """Prepare features using DictVectorizer and StandardScaler"""
    print("\nPreparing features...")
    
    # Extract target
    y_train = df_train[TARGET].values
    y_val = df_val[TARGET].values
    y_test = df_test[TARGET].values
    
    # Remove target from features
    df_train = df_train.drop(columns=[TARGET, 'session_id'])
    df_val = df_val.drop(columns=[TARGET, 'session_id'])
    df_test = df_test.drop(columns=[TARGET, 'session_id'])
    
    # Convert to dictionaries
    train_dicts = df_train[CATEGORICAL + NUMERICAL].to_dict(orient='records')
    val_dicts = df_val[CATEGORICAL + NUMERICAL].to_dict(orient='records')
    test_dicts = df_test[CATEGORICAL + NUMERICAL].to_dict(orient='records')
    
    # One-hot encoding
    dv = DictVectorizer(sparse=False)
    X_train = dv.fit_transform(train_dicts)
    X_val = dv.transform(val_dicts)
    X_test = dv.transform(test_dicts)
    
    # Scaling
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_val = scaler.transform(X_val)
    X_test = scaler.transform(X_test)
    
    print(f"Feature matrix shape: {X_train.shape}")
    print(f"Number of features: {len(dv.get_feature_names_out())}")
    
    return X_train, X_val, X_test, y_train, y_val, y_test, dv, scaler


def train_model(X_train, y_train, model_type='random_forest'):
    """Train the model"""
    print(f"\nTraining {model_type} model...")
    
    if model_type == 'random_forest':
        model = RandomForestClassifier(
            n_estimators=100, 
            max_depth=10, 
            min_samples_split=10,
            random_state=RANDOM_STATE,
            n_jobs=-1
        )
    elif model_type == 'logistic_regression':
        model = LogisticRegression(
            solver='lbfgs',
            max_iter=1000,
            random_state=RANDOM_STATE
        )
    elif model_type == 'decision_tree':
        model = DecisionTreeClassifier(
            max_depth=10,
            min_samples_split=10,
            random_state=RANDOM_STATE
        )
    else:
        raise ValueError(f"Unknown model type: {model_type}")
    
    model.fit(X_train, y_train)
    print(f"Model trained successfully!")
    
    return model


def evaluate_model(model, X_val, y_val, dataset_name='Validation'):
    """Evaluate model performance"""
    print(f"\n{dataset_name} Results:")
    
    y_pred_proba = model.predict_proba(X_val)[:, 1]
    y_pred = (y_pred_proba >= 0.5).astype(int)
    
    accuracy = accuracy_score(y_val, y_pred)
    roc_auc = roc_auc_score(y_val, y_pred_proba)
    
    print(f"Accuracy: {accuracy:.4f}")
    print(f"ROC AUC: {roc_auc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_val, y_pred))
    
    return accuracy, roc_auc


def save_model(model, dv, scaler, model_path, dv_path, scaler_path):
    """Save the trained model, DictVectorizer, and Scaler"""
    print(f"\nSaving model to {model_path}...")
    with open(model_path, 'wb') as f_out:
        pickle.dump(model, f_out)
    
    print(f"Saving DictVectorizer to {dv_path}...")
    with open(dv_path, 'wb') as f_out:
        pickle.dump(dv, f_out)
    
    print(f"Saving StandardScaler to {scaler_path}...")
    with open(scaler_path, 'wb') as f_out:
        pickle.dump(scaler, f_out)
    
    print("All artifacts saved successfully!")


def main():
    """Main training pipeline"""
    print("="*80)
    print("CYBERSECURITY INTRUSION DETECTION - MODEL TRAINING")
    print("="*80)
    
    # Load data
    df = load_and_prepare_data(DATA_PATH)
    
    # Split data
    df_train, df_val, df_test, df_full_train = split_data(df)
    
    # Prepare features
    X_train, X_val, X_test, y_train, y_val, y_test, dv, scaler = prepare_features(
        df_train, df_val, df_test
    )
    
    # Train and compare models
    models = {
        'logistic_regression': train_model(X_train, y_train, 'logistic_regression'),
        'decision_tree': train_model(X_train, y_train, 'decision_tree'),
        'random_forest': train_model(X_train, y_train, 'random_forest')
    }
    
    # Evaluate models on validation set
    print("\n" + "="*80)
    print("MODEL COMPARISON ON VALIDATION SET")
    print("="*80)
    
    results = {}
    for name, model in models.items():
        acc, auc = evaluate_model(model, X_val, y_val, name.replace('_', ' ').title())
        results[name] = {'accuracy': acc, 'roc_auc': auc}
    
    # Select best model based on ROC AUC
    best_model_name = max(results, key=lambda x: results[x]['roc_auc'])
    best_model = models[best_model_name]
    
    print("\n" + "="*80)
    print(f"BEST MODEL: {best_model_name.replace('_', ' ').upper()}")
    print("="*80)
    
    # Train final model on full training set
    print("\nRetraining best model on full training set...")
    df_full_train_clean = df_full_train.drop(columns=['session_id'])
    y_full_train = df_full_train_clean[TARGET].values
    df_full_train_clean = df_full_train_clean.drop(columns=[TARGET])
    
    full_train_dicts = df_full_train_clean[CATEGORICAL + NUMERICAL].to_dict(orient='records')
    
    dv_final = DictVectorizer(sparse=False)
    X_full_train = dv_final.fit_transform(full_train_dicts)
    
    scaler_final = StandardScaler()
    X_full_train = scaler_final.fit_transform(X_full_train)
    
    final_model = train_model(X_full_train, y_full_train, best_model_name)
    
    # Evaluate on test set
    df_test_clean = df_test.drop(columns=['session_id'])
    y_test_final = df_test_clean[TARGET].values
    df_test_clean = df_test_clean.drop(columns=[TARGET])
    
    test_dicts = df_test_clean[CATEGORICAL + NUMERICAL].to_dict(orient='records')
    X_test_final = dv_final.transform(test_dicts)
    X_test_final = scaler_final.transform(X_test_final)
    
    evaluate_model(final_model, X_test_final, y_test_final, 'Final Test Set')
    
    # Save the final model
    save_model(final_model, dv_final, scaler_final, OUTPUT_MODEL, OUTPUT_DV, OUTPUT_SCALER)
    
    print("\n" + "="*80)
    print("TRAINING COMPLETE!")
    print("="*80)
    print(f"\nModel saved to: {OUTPUT_MODEL}")
    print(f"DictVectorizer saved to: {OUTPUT_DV}")
    print(f"StandardScaler saved to: {OUTPUT_SCALER}")


if __name__ == '__main__':
    main()