class FeatureExtractor:
    @staticmethod
    def extract_vt_features(vt_results):
        """Extract numerical features from VirusTotal results."""
        malicious_count = sum(1 for res in vt_results.values() if res["category"] == "malicious")
        harmless_count = sum(1 for res in vt_results.values() if res["category"] == "harmless")
        undetected_count = sum(1 for res in vt_results.values() if res["category"] == "undetected")
        
        blacklist_count = sum(1 for res in vt_results.values() if res["method"] == "blacklist")
        
        total_engines = len(vt_results)

        return [
            malicious_count,   # Total malicious results
            harmless_count,    # Total harmless results
            undetected_count,  # Total undetected results
            blacklist_count,   # Total engines using 'blacklist' method
            total_engines      # Total engines scanned
        ]

        @staticmethod
        def extract_email_features(email):
            """Extract features from email address"""
            if not email:
                return {'length': 0, 'has_number': 0, 'domain_length': 0}
            
            local, domain = email.split('@') if '@' in email else (email, '')
            features = {
                'length': len(email),
                'has_number': int(any(c.isdigit() for c in email)),
                'local_length': len(local),
                'domain_length': len(domain),
                'has_dot_in_domain': int('.' in domain),
            }
            return features

        @staticmethod
        def extract_features(input_data):
            # Add logic for extracting relevant features here
            features = [input_data['value1'], input_data['value2']]  # Example
            return features
