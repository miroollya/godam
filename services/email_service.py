"""Service for email analysis"""
import re
from typing import Dict, Any

class EmailService:
    def __init__(self):
        self.suspicious_patterns = [
            r'bank',
            r'verify',
            r'account.*suspended',
            r'urgent',
            r'password',
            r'security',
            r'update.*required',
            r'[0-9]{8,}',  # Long number sequences
            r'[^@]+@.*\.(ru|cn|tk|top)$',  # Suspicious TLDs
            r'admin|support|service|security'
        ]

        self.legitimate_domains = [
            'gmail.com',
            'yahoo.com',
            'hotmail.com',
            'outlook.com',
            'aol.com',
            'protonmail.com',
            'icloud.com'
        ]

    def analyze_email(self, email: str) -> Dict[str, Any]:
        """Analyze email address for suspicious patterns"""
        try:
            suspicious_count = 0
            matches = []
            
            # Split email into local part and domain
            local_part, domain = email.split('@')

            # Check domain legitimacy
            is_legitimate_domain = domain.lower() in self.legitimate_domains
            
            # Check for suspicious patterns
            for pattern in self.suspicious_patterns:
                if re.search(pattern, email, re.IGNORECASE):
                    suspicious_count += 1
                    matches.append(pattern)

            # Additional checks
            has_numbers = bool(re.search(r'\d', local_part))
            has_special_chars = bool(re.search(r'[^a-zA-Z0-9.]', local_part))
            
            # Calculate risk score (0-1)
            risk_factors = [
                not is_legitimate_domain,
                has_numbers,
                has_special_chars,
                suspicious_count / len(self.suspicious_patterns)
            ]
            risk_score = sum(risk_factors) / len(risk_factors)

            return {
                'risk_score': risk_score,
                'suspicious_patterns_found': suspicious_count,
                'total_patterns_checked': len(self.suspicious_patterns),
                'matches': matches,
                'is_legitimate_domain': is_legitimate_domain,
                'has_numbers': has_numbers,
                'has_special_chars': has_special_chars,
                'is_suspicious': risk_score > 0.5  # Threshold for suspicious emails
            }
        except Exception as e:
            return {'error': str(e)}