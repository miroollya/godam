"""Machine learning service for security analysis"""
import numpy as np
import joblib
import os
from typing import Dict, Any
from sklearn.ensemble import RandomForestClassifier
from models.feature_extractor import FeatureExtractor

class MLService:
    def __init__(self):
        self.models_dir = 'models'
        os.makedirs(self.models_dir, exist_ok=True)
        
        # Initialize feature extractor
        self.feature_extractor = FeatureExtractor()
        
        # Initialize models with some basic training data
        self.models = {
            'file': self._initialize_file_model(),
            'url': self._initialize_url_model(),
            'email': self._initialize_email_model()
        }

    def _initialize_file_model(self) -> RandomForestClassifier:
        """Initialize file model with some basic training data"""
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        
        # Basic training data for files
        X = np.array([
            [0, 0, 100, 100, 0, 0, 100, 0],  # Clean file example
            [50, 10, 40, 100, 0.5, -50, 10, 90],  # Suspicious file example
            [80, 15, 5, 100, 0.8, -80, 5, 95],  # Malicious file example
        ])
        y = np.array([0, 1, 1])  # 0 for clean, 1 for suspicious/malicious
        
        model.fit(X, y)
        return model

    def _initialize_url_model(self) -> RandomForestClassifier:
        """Initialize URL model with some basic training data"""
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        
        # Basic training data for URLs
        X = np.array([
            # [length, dots, slashes, queries, equals, risk_score, suspicious_patterns, is_https]
            [20, 1, 2, 0, 0, 0, 0, 1],  # Clean URL example
            [45, 3, 4, 2, 3, 0.6, 2, 0],  # Suspicious URL example
            [60, 4, 5, 3, 4, 0.8, 3, 0]   # Malicious URL example
        ])
        y = np.array([0, 1, 1])
        
        model.fit(X, y)
        return model

    def _initialize_email_model(self) -> RandomForestClassifier:
        """Initialize email model with some basic training data"""
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        
        # Basic training data for emails
        X = np.array([
            # [length, numbers, special_chars, domain_reputation, risk_score, suspicious_patterns]
            [20, 0, 0, 0, 0, 0],  # Clean email example
            [30, 2, 1, -20, 0.6, 2],  # Suspicious email example
            [35, 4, 2, -50, 0.8, 3]   # Malicious email example
        ])
        y = np.array([0, 1, 1])
        
        model.fit(X, y)
        return model

    def analyze_and_learn(self, data: Dict[str, Any], data_type: str) -> Dict[str, Any]:
        """Analyze data and update model with new information"""
        try:
            # Extract features based on data type
            if data_type == 'file':
                features = self.feature_extractor.extract_virustotal_features(data)
            elif data_type == 'url':
                features = self.feature_extractor.extract_url_features(data)
            else:  # email
                features = self.feature_extractor.extract_email_features(data)

            # Get model prediction
            model = self.models[data_type]
            prediction = model.predict(features)[0]
            probabilities = model.predict_proba(features)[0]
            confidence = float(max(probabilities))

            # Update model if we have confirmed results
            if 'is_suspicious' in data or 'is_malicious' in data:
                is_bad = data.get('is_suspicious', data.get('is_malicious', False))
                model.fit(
                    np.vstack([model.feature_importances_.reshape(1, -1), features]),
                    np.array([int(is_bad), prediction])
                )

            return {
                'features_analyzed': features.shape[1],
                'ml_prediction': {
                    'prediction': int(prediction),
                    'confidence': confidence,
                    'is_suspicious': bool(prediction == 1)
                }
            }

        except Exception as e:
            return {
                'error': str(e),
                'features_analyzed': 0,
                'ml_prediction': {
                    'prediction': 0,
                    'confidence': 0,
                    'is_suspicious': False
                }
            }