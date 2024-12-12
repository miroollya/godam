import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from config import Config
import os

class SecurityModel:
    def __init__(self):
        self.model = None
        self.load_model()

    def load_model(self):
        """Load the trained model if it exists"""
        if os.path.exists(Config.MODEL_PATH):
            self.model = joblib.load(Config.MODEL_PATH)

    def train(self, features, labels):
        """Train the security model"""
        self.model = RandomForestClassifier(n_estimators=100)
        self.model.fit(features, labels)
        
        # Save the trained model
        os.makedirs(os.path.dirname(Config.MODEL_PATH), exist_ok=True)
        joblib.dump(self.model, Config.MODEL_PATH)

    def predict(self, features):
        """Make predictions using the trained model"""
        if self.model is None:
            return None
        return self.model.predict(features)