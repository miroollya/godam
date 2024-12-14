"""Feature extraction for ML models"""
import numpy as np
from typing import Dict, Any
import re
from urllib.parse import urlparse

class FeatureExtractor:
    def __init__(self):
        self.url_patterns = [
            r'password',
            r'login',
            r'account',
            r'bank',
            r'secure',
            r'update',
            r'\d{4}',  # 4 digits in sequence
            r'[^/]*/.*\.(exe|zip|rar)$',  # Executable/compressed files
            r'verify',
            r'confirm'
        ]
        
        self.email_patterns = [
            r'admin',
            r'support',
            r'service',
            r'security',
            r'update',
            r'account',
            r'verify',
            r'bank',
            r'\d{6,}',  # 6 or more digits
            r'[^a-zA-Z0-9.@_-]'  # Special characters
        ]

    def extract_virustotal_features(self, data: Dict[str, Any]) -> np.ndarray:
        """Extract features from VirusTotal results"""
        features = [
            data.get('malicious', 0),
            data.get('suspicious', 0),
            data.get('undetected', 0),
            data.get('total_scans', 0),
            data.get('malicious', 0) / max(data.get('total_scans', 1), 1),  # Detection ratio
            data.get('reputation', 0) if 'reputation' in data else 0,
            data.get('total_votes', {}).get('harmless', 0) if 'total_votes' in data else 0,
            data.get('total_votes', {}).get('malicious', 0) if 'total_votes' in data else 0
        ]
        return np.array(features, dtype=float).reshape(1, -1)

    def extract_url_features(self, data: Dict[str, Any]) -> np.ndarray:
        """Extract features from URL data"""
        url = data.get('url', '')
        parsed_url = urlparse(url)
        
        # Basic URL characteristics
        features = [
            len(url),
            url.count('.'),
            url.count('/'),
            url.count('?'),
            url.count('='),
            data.get('url_analysis', {}).get('risk_score', 0),
            len(data.get('url_analysis', {}).get('matches', [])),
            int(parsed_url.scheme == 'https')
        ]
        
        return np.array(features, dtype=float).reshape(1, -1)

    def extract_email_features(self, data: Dict[str, Any]) -> np.ndarray:
        """Extract features from email data"""
        email = data.get('email', '')
        local_part = email.split('@')[0] if '@' in email else email
        
        features = [
            len(email),
            sum(c.isdigit() for c in local_part),
            sum(not c.isalnum() for c in local_part),
            data.get('vt_results', {}).get('reputation', 0),
            data.get('email_analysis', {}).get('risk_score', 0),
            len(data.get('email_analysis', {}).get('matches', []))
        ]
        
        return np.array(features, dtype=float).reshape(1, -1)