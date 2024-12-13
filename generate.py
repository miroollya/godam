import os
import json
import random

def generate_synthetic_data(output_path="data/training_data.json"):
    engines = ["ZeroFox", "alphaMountain.ai", "benkow.cc", "GoogleSafeBrowsing", "BitDefender"]
    methods = ["blacklist", "whitelist", "heuristic"]
    categories = ["malicious", "harmless", "undetected"]

    features, labels = [], []

    for _ in range(1000):
        feature = [
            random.randint(5, 20),  # Engine name length
            random.randint(0, 1),  # Malicious flag
            random.randint(0, 1),  # Harmless flag
            random.randint(0, 1)   # Blacklist method flag
        ]
        label = "malicious" if feature[1] == 1 else "harmless"
        features.append(feature)
        labels.append(label)

    # Save to JSON
    os.makedirs("data", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump({"features": features, "labels": labels}, f)
    print(f"Synthetic dataset created at {output_path}")

if __name__ == "__main__":
    generate_synthetic_data()
