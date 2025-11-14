## Project Checklist

1. Problem & Data

- Define project goal (risk detection, early intervention)

- Summarize dataset origin, features, and missing values

- Describe ethical considerations (privacy, consent, labeling bias)

2. Baseline Model

- Train Logistic Regression on labeled subset

- Record metrics: accuracy, precision, recall, F1, AUC

- Interpret coefficients to find key predictors

3. Semi-Supervised Extension

- Implement SelfTrainingClassifier with Logistic Regression base

- Choose confidence threshold (e.g., 0.9)

- Evaluate improvement over baseline

4. Model Explainability

- Use SHAP for global feature importance

- Generate top positive/negative contributing factors

- Add interpretability plots to reports/figures/

5. Reproducibility

- Fix random seeds

- Save trained model (.pkl)

- Store requirements.txt or use conda env export

- Write all parameters in config.yaml

6. Deployment

- Build simple serve.py API/Streamlit dashboard

- Containerize with Docker

- Optionally deploy on Render / Hugging Face Spaces / AWS

7. Documentation

- Update README.md (overview, setup, usage)

- Include ethical statement and citation for dataset

- Include reproducibility steps (exact commands to rerun results)
