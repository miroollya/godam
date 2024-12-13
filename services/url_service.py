"""Service for URL analysis"""
import re
from typing import Dict, Any

class URLService:
    def __init__(self):
        self.suspicious_patterns = [
            r'bit\.ly',
            r'goo\.gl',
            r'tinyurl\.com',
            r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',  # IP addresses
            r'[^/]*/.*\.exe$',  # Executable files
            r'[^/]*/.*\.zip$',  # Zip files
            r'[^/]*/.*\.rar$',  # RAR files
            r'free.*download',
            r'password.*reset',
            r'account.*verify',
        ]

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze URL for suspicious patterns"""
        try:
            suspicious_count = 0
            matches = []

            # Check for suspicious patterns
            for pattern in self.suspicious_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    suspicious_count += 1
                    matches.append(pattern)

            # Calculate risk score (0-1)
            risk_score = suspicious_count / len(self.suspicious_patterns)

            return {
                'risk_score': risk_score,
                'suspicious_patterns_found': suspicious_count,
                'total_patterns_checked': len(self.suspicious_patterns),
                'matches': matches,
                'is_suspicious': risk_score > 0.3  # Threshold for suspicious URLs
            }
        except Exception as e:
            return {'error': str(e)}