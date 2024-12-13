"""Machine learning service for security analysis"""
from models.security_classifier import SecurityClassifier
from models.feature_extractor import FeatureExtractor
from typing import Dict, Any

class MLService:
    def __init__(self):
        self.feature_extractor = FeatureExtractor()
        self.classifiers = {
            'file': SecurityClassifier('file'),
            'url': SecurityClassifier('url'),
            'email': SecurityClassifier('email')
        }

    def analyze_and_learn(self, data: Dict[str, Any], data_type: str) -> Dict[str, Any]:
        """Analyze data and update model with new information"""
        try:
            # Extract features based on data type
            if data_type == 'file':
                features = self.feature_extractor.extract_virustotal_features(data)
            elif data_type == 'url':
                features = self.feature_extractor.extract_url_features(data['url'])
            else:  # email
                features = self.feature_extractor.extract_email_features(data['email'])

            # Get prediction
            classifier = self.classifiers[data_type]
            prediction = classifier.predict(features)

            # If we have confirmed results (e.g., from VirusTotal), use them for training
            if 'is_malicious' in data:
                classifier.train([features], [1 if data['is_malicious'] else 0])

            return {
                'ml_prediction': prediction,
                'features_analyzed': features.shape[1]
            }
        except Exception as e:
            return {'error': str(e)}