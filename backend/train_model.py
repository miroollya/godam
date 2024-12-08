import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

# Contoh dataset: features dan labels
data = pd.DataFrame({
    'positives': [1, 0, 5, 10, 0, 3, 7],
    'total_scans': [70, 70, 65, 60, 70, 66, 60],
    'label': [1, 0, 1, 1, 0, 1, 1]  # 1 = Malicious, 0 = Safe
})

# Split dataset
X = data[['positives', 'total_scans']]
y = data['label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy: {accuracy:.2f}")

# Save model
joblib.dump(model, 'file_analyzer_model.pkl')
print("Model saved successfully!")
