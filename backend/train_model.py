import pandas as pd
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from xgboost import XGBClassifier
import joblib

# 1. Dataset: Tambah lebih banyak features
data = pd.DataFrame({
    'positives': [1, 0, 5, 10, 0, 3, 7],
    'harmless': [68, 70, 60, 50, 70, 62, 50],
    'suspicious': [1, 0, 3, 5, 0, 2, 5],
    'undetected': [0, 0, 2, 5, 0, 2, 3],
    'label': [1, 0, 1, 1, 0, 1, 1]  # 1 = Malicious, 0 = Safe
})

# 2. Split Dataset
X = data[['positives', 'harmless', 'suspicious', 'undetected']]
y = data['label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 3. Train RandomForest with Hyperparameter Tuning
param_grid = {
    'n_estimators': [100, 200, 300],
    'max_depth': [5, 10, 15],
    'min_samples_split': [2, 5, 10],
    'min_samples_leaf': [1, 2, 4]
}

print("Training RandomForest...")
rf = RandomForestClassifier(random_state=42)
rf_search = RandomizedSearchCV(rf, param_grid, n_iter=10, cv=3, random_state=42, verbose=2, n_jobs=-1)
rf_search.fit(X_train, y_train)

# Best model
rf_model = rf_search.best_estimator_
rf_accuracy = accuracy_score(y_test, rf_model.predict(X_test))
print(f"RandomForest Accuracy: {rf_accuracy:.2f}")

# 4. Train XGBoost
print("Training XGBoost...")
xgb = XGBClassifier(use_label_encoder=False, eval_metric='logloss', random_state=42)
xgb.fit(X_train, y_train)
xgb_accuracy = accuracy_score(y_test, xgb.predict(X_test))
print(f"XGBoost Accuracy: {xgb_accuracy:.2f}")

# 5. Save Both Models
joblib.dump(rf_model, 'file_analyzer_model.pkl')
joblib.dump(xgb, 'xgb_file_analyzer_model.pkl')
print("Both models saved successfully!")
