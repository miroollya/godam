"""Feature extraction for ML model"""
import numpy as np
from typing import Dict, List, Any

class FeatureExtractor:
    def extract_virustotal_features(self, vt_results: Dict[str, Any]) -> np.ndarray:
        """Extract numerical features from VirusTotal results"""
        features = [
            vt_results.get('malicious', 0),
            vt_results.get('suspicious', 0),
            vt_results.get('undetected', 0),
            vt_results.get('total_scans', 0),
            vt_results.get('malicious', 0) / max(vt_results.get('total_scans', 1), 1),  # Detection ratio
        ]
        return np.array(features).reshape(1, -1)

    def extract_url_features(self, url: str) -> np.ndarray:
        """Extract features from URLs"""
        features = [
            len(url),
            url.count('.'),
            url.count('/'),
            url.count('?'),
            url.count('='),
            url.count('-'),
            url.count('_'),
            any(c.isdigit() for c in url),
        ]
        return np.array(features).reshape(1, -1)

    def extract_email_features(self, email: str) -> np.ndarray:
        """Extract features from email addresses"""
        domain = email.split('@')[1] if '@' in email else ''
        features = [
            len(email),
            email.count('.'),
            email.count('@'),
            len(domain),
            any(c.isdigit() for c in email),
            email.count('-'),
            email.count('_'),
        ]
        return np.array(features).reshape(1, -1)