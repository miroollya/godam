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
        
        self.feature_extractor = FeatureExtractor()
        self.models = {
            'file': self._initialize_file_model(),
            'url': self._initialize_url_model(),
            'email': self._initialize_email_model()
        }

    def _initialize_file_model(self) -> RandomForestClassifier:
        """Initialize file model with stronger bias towards VirusTotal results"""
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        
        # Enhanced training data with more weight on malicious indicators
        X = np.array([
            [0, 0, 100, 100, 0, 0, 100, 0],    # Clean file
            [1, 0, 99, 100, 0.01, -10, 90, 10], # Slightly suspicious
            [10, 2, 88, 100, 0.1, -20, 80, 20], # Moderately suspicious
            [50, 10, 40, 100, 0.5, -50, 40, 60], # Highly suspicious
            [80, 15, 5, 100, 0.8, -80, 20, 80],  # Definitely malicious
        ])
        y = np.array([0, 0, 1, 1, 1])
        
        model.fit(X, y)
        return model

    def _initialize_url_model(self) -> RandomForestClassifier:
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        
        X = np.array([
            [20, 1, 2, 0, 0, 0, 0, 1],      # Clean URL
            [30, 2, 2, 1, 1, 0.2, 1, 1],    # Slightly suspicious
            [45, 3, 4, 2, 3, 0.6, 2, 0],    # Moderately suspicious
            [60, 4, 5, 3, 4, 0.8, 3, 0],    # Highly suspicious
            [80, 5, 6, 4, 5, 0.9, 4, 0]     # Definitely malicious
        ])
        y = np.array([0, 0, 1, 1, 1])
        
        model.fit(X, y)
        return model

    def _initialize_email_model(self) -> RandomForestClassifier:
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        
        X = np.array([
            [20, 0, 0, 0, 0, 0],       # Clean email
            [25, 1, 0, -10, 0.3, 1],   # Slightly suspicious
            [30, 2, 1, -20, 0.6, 2],   # Moderately suspicious
            [35, 3, 2, -40, 0.8, 3],   # Highly suspicious
            [40, 4, 3, -50, 0.9, 4]    # Definitely malicious
        ])
        y = np.array([0, 0, 1, 1, 1])
        
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
            
            # Check VirusTotal results
            vt_malicious = data.get('malicious', 0) > 0
            vt_suspicious = data.get('suspicious', 0) > 0
            
            # Determine if the target is suspicious based on VirusTotal
            is_suspicious = vt_malicious or vt_suspicious
            
            # If VirusTotal found it suspicious/malicious, force ML to align
            if is_suspicious:
                prediction = 1
                confidence = 0.95 if vt_malicious else 0.85  # Higher confidence for malicious
            else:
                # Only trust ML prediction if VirusTotal says it's clean
                probabilities = model.predict_proba(features)[0]
                prediction = model.predict(features)[0]
                confidence = float(max(probabilities))
                
                # If ML thinks it's suspicious but VT doesn't, lower confidence
                if prediction == 1:
                    confidence = min(confidence, 0.6)

            # Update model with the new data point
            model.fit(
                np.vstack([features, features]),  # Add more weight to this example
                np.array([int(is_suspicious), int(is_suspicious)])  # Use VT result for training
            )

            return {
                'features_analyzed': features.shape[1],
                'ml_prediction': {
                    'prediction': int(prediction),
                    'confidence': confidence,
                    'is_suspicious': bool(prediction == 1 or is_suspicious)  # Consider both ML and VT
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