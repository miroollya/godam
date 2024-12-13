"""Security classification using ML"""
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib
from typing import Dict, Any, Optional, List
import os

class SecurityClassifier:
    def __init__(self, model_type: str):
        self.model_type = model_type
        self.model_path = f'models/{model_type}_classifier.pkl'
        self.model = self._load_model()
        self.training_data = {
            'features': [],
            'labels': []
        }

    def _load_model(self) -> Optional[RandomForestClassifier]:
        """Load existing model if available"""
        if os.path.exists(self.model_path):
            return joblib.load(self.model_path)
        return RandomForestClassifier(n_estimators=100, random_state=42)

    def train(self, features: List[np.ndarray], labels: List[int]) -> None:
        """Train or update the model with new data"""
        if not features or not labels:
            return

        # Convert lists to numpy arrays
        X = np.vstack(features)
        y = np.array(labels)

        # Update training data
        self.training_data['features'].extend(features)
        self.training_data['labels'].extend(labels)

        # Train model
        self.model.fit(X, y)
        
        # Save model
        os.makedirs('models', exist_ok=True)
        joblib.dump(self.model, self.model_path)

    def predict(self, features: np.ndarray) -> Dict[str, Any]:
        """Make prediction and return confidence scores"""
        if not isinstance(self.model, RandomForestClassifier):
            return {'error': 'Model not initialized'}

        try:
            # Get prediction and probability
            prediction = self.model.predict(features)[0]
            probabilities = self.model.predict_proba(features)[0]
            
            return {
                'prediction': int(prediction),
                'confidence': float(max(probabilities)),
                'is_suspicious': bool(prediction == 1)
            }
        except Exception as e:
            return {'error': str(e)}