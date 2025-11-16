# Cybersecurity Intrusion Detection - ML Midterm Project

My project is a machine learning service for detecting cybersecurity intrusions using network session data. The project demonstrates a complete ML workflow from data exploration to production deployment with Docker.

## The Problem

**Objective**: Detect malicious network sessions (attacks) based on session characteristics like protocol type, encryption, packet size, login attempts, and user behavior patterns.

**Dataset**: Cybersecurity intrusion detection dataset with 10,000+ network sessions

- **Features**: 10 features (3 categorical, 6 numerical, 1 identifier)
- **Target**: Binary classification (attack detected: 0 or 1)
- **Source**: [GitHub Repository](https://github.com/theBoringEngineer/classifing_cybersecurity_intrusion_detection)

**Business Value**: Early detection of security threats can prevent data breaches, protect systems, and reduce incident response time.

## Features

**Categorical Features:**

- `protocol_type`: Network protocol (tcp, udp, icmp)
- `encryption_used`: Encryption method (aes, des, no_enc)
- `browser_type`: Browser used (chrome, firefox, safari, edge)

**Numerical Features:**

- `network_packet_size`: Size of network packets (bytes)
- `login_attempts`: Number of login attempts
- `session_duration`: Duration of session (seconds)
- `ip_reputation_score`: IP reputation score (0-1)
- `failed_logins`: Number of failed login attempts
- `unusual_time_access`: Access during unusual hours (0 or 1)

## Models Evaluated

1. **Logistic Regression** - Simple baseline model
2. **Decision Tree** - Non-linear decision boundaries
3. **Random Forest** - Ensemble method (best performer)

**Metrics:**

- Accuracy: ~74-80%
- ROC AUC: ~80-85%

## Getting Started

To replicate this project:

### Prerequisites

- Python 3.13.9
- Docker (for containerization)
- pip (Python package manager)

### 1. Clone Repository

```bash
git clone https://github.com/theBoringEngineer/classifing_cybersecurity_intrusion_detection---Datatalks_midterm_project

cd cybersecurity-intrusion-detection
```

### 2. Download Dataset

```bash
wget https://raw.githubusercontent.com/theBoringEngineer/classifing_cybersecurity_intrusion_detection---Datatalks_midterm_project/refs/heads/main/data/raw/cybersecurity_intrusion_data.csv -O security_intrusion_dataset.csv
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

## 🏋️ Training the Model

Run the training script to train and evaluate all models:

```bash
python train.py
```

**Output:**

- `model.bin` - Best performing model
- `dv.bin` - DictVectorizer for feature encoding
- `scaler.bin` - StandardScaler for feature normalization

**Training Process:**

1. Loads and cleans data
2. Splits into train/val/test (60/20/20)
3. Trains 3 models (Logistic Regression, Decision Tree, Random Forest)
4. Selects best model based on ROC AUC
5. Retrains on full training set
6. Evaluates on test set
7. Saves model artifacts

## 🔮 Making Predictions

### Standalone Prediction Script

```bash
python predict.py
```

### Using the Model in Python

```python
import pickle

# Load model
with open('model.bin', 'rb') as f:
    model = pickle.load(f)

with open('dv.bin', 'rb') as f:
    dv = pickle.load(f)

with open('scaler.bin', 'rb') as f:
    scaler = pickle.load(f)

# Prepare session
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

# Transform and predict
X = dv.transform([session])
X_scaled = scaler.transform(X)
probability = model.predict_proba(X_scaled)[0, 1]

print(f"Attack probability: {probability:.4f}")
```

## 🌐 Web Service Deployment

### Running Locally

Start the Flask service with Waitress:

```bash
python serve.py
```

The service will be available at `http://localhost:9696`

### API Endpoints

**1. Health Check**

```bash
GET http://localhost:9696/health
```

**2. Home/Documentation**

```bash
GET http://localhost:9696/
```

**3. Prediction**

```bash
POST http://localhost:9696/predict
Content-Type: application/json

{
    "protocol_type": "tcp",
    "encryption_used": "aes",
    "browser_type": "chrome",
    "network_packet_size": 1500,
    "login_attempts": 5,
    "session_duration": 300,
    "ip_reputation_score": 0.8,
    "failed_logins": 2,
    "unusual_time_access": 0
}
```

**Response:**

```json
{
  "attack_probability": 0.3245,
  "attack_detected": false,
  "risk_level": "medium"
}
```

### Testing the API

```bash
python test_service.py
```

This runs multiple test cases including normal and suspicious sessions.

## 🐳 Docker Deployment

### Build Docker Image

```bash
docker build -t intrusion-detection:v1 .
```

### Run Docker Container

```bash
docker run -it --rm -p 9696:9696 intrusion-detection:v1
```

### Test the Dockerized Service

```bash
python test_service.py
```

### Docker Compose (Optional)

Create `docker-compose.yml`:

```yaml
version: "3.8"

services:
  intrusion-detection:
    build: .
    ports:
      - "9696:9696"
    restart: unless-stopped
```

Run with:

```bash
docker-compose up
```

## 📊 Model Performance

**Random Forest (Final Model):**

- Test Accuracy: ~80%
- ROC AUC: ~85%
- Precision (Attack): ~75%
- Recall (Attack): ~70%

**Key Insights:**

- `failed_logins` is the most important feature
- `ip_reputation_score` strongly correlates with attacks
- `encryption_used` = 'no_enc' increases attack probability
- Sessions with high `login_attempts` are suspicious

## 🔄 Reproducibility

**Fixed Random Seed**: `RANDOM_STATE = 1`

- Ensures consistent train/test splits
- Reproducible model training
- Enables proper model comparison

**Version Pinning**:

- All dependencies pinned in `requirements.txt`
- Docker image uses specific Python version
- Training script logs all parameters

## ☁️ Cloud Deployment (Bonus)

### AWS Elastic Beanstalk

```bash
# Install EB CLI
pip install awsebcli

# Initialize
eb init -p docker intrusion-detection

# Create environment and deploy
eb create intrusion-detection-env
```

### Google Cloud Run

```bash
# Build and push to Container Registry
gcloud builds submit --tag gcr.io/PROJECT_ID/intrusion-detection

# Deploy
gcloud run deploy intrusion-detection \
  --image gcr.io/PROJECT_ID/intrusion-detection \
  --platform managed \
  --port 9696
```

### Azure Container Instances

```bash
# Build and push to ACR
az acr build --registry myregistry --image intrusion-detection:v1 .

# Deploy
az container create \
  --resource-group myResourceGroup \
  --name intrusion-detection \
  --image myregistry.azurecr.io/intrusion-detection:v1 \
  --ports 9696
```

## 🧪 Testing Checklist

- [x] Train model successfully
- [x] Make predictions with standalone script
- [x] Start Flask service locally
- [x] Test API endpoints
- [x] Build Docker image
- [x] Run Docker container
- [x] Test Dockerized service
- [ ] Deploy to cloud (optional)

## 📝 Development Notes

**Why These Technologies?**

- **pandas/numpy**: Data manipulation and numerical operations
- **scikit-learn**: ML algorithms and preprocessing
- **flask**: Lightweight web framework
- **waitress**: Production-ready WSGI server
- **matplotlib**: Data visualization in EDA
- **Docker**: Containerization for reproducibility

**Best Practices Implemented:**

- Proper train/val/test split
- Feature scaling for convergence
- Model comparison with consistent metrics
- Clean code structure with separate scripts
- API with proper error handling
- Health check endpoint
- Comprehensive documentation

## 🤝 Peer Review Criteria

- [x] Problem description clearly documented
- [x] EDA performed in notebook
- [x] Model training script with multiple models
- [x] Model exported properly (pickle)
- [x] Web service with Flask
- [x] Dependency management (requirements.txt)
- [x] Dockerfile for containerization
- [x] Instructions for running locally and with Docker
- [x] README with complete documentation

---

**Built with ❤️ for ML Zoomcamp Midterm Project**
