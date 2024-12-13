import os
import joblib
import json
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from config import Config

class SecurityModel:
    def __init__(self):
        self.model = None
        self.training_data_path = "data/training_data.json"
        self.load_model()

    def load_model(self):
        """Load model if exists"""
        if os.path.exists(Config.MODEL_PATH):
            self.model = joblib.load(Config.MODEL_PATH)

    def save_model(self):
        """Save the trained model"""
        os.makedirs(os.path.dirname(Config.MODEL_PATH), exist_ok=True)
        joblib.dump(self.model, Config.MODEL_PATH)

    def save_training_data(self, features, labels):
        """Save or append training data"""
        os.makedirs("data", exist_ok=True)
        data = {"features": features, "labels": labels}

        # Append new data
        if os.path.exists(self.training_data_path):
            with open(self.training_data_path, "r") as f:
                existing_data = json.load(f)
                data["features"].extend(existing_data["features"])
                data["labels"].extend(existing_data["labels"])

        # Save updated data
        with open(self.training_data_path, "w") as f:
            json.dump(data, f)

    def train(self):
        """Train the model using saved training data"""
        if not os.path.exists(self.training_data_path):
            return {"error": "No training data available"}

        # Load training data
        with open(self.training_data_path, "r") as f:
            data = json.load(f)

        features, labels = data["features"], data["labels"]

        # Train the model
        self.model = RandomForestClassifier(n_estimators=100)
        self.model.fit(features, labels)

        # Save the model
        self.save_model()
        return {"message": "Model trained successfully"}
