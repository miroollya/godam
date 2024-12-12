def extract_virustotal_features(vt_results):
    """Extract relevant features from VirusTotal results"""
    features = {
        'positives': vt_results.get('positives', 0),
        'total_scans': vt_results.get('total', 0),
        'has_permalink': 1 if vt_results.get('permalink') else 0,
    }
    return features

def extract_email_features(email):
    """Extract features from email address"""
    features = {
        'length': len(email),
        'has_number': any(c.isdigit() for c in email),
        'domain_length': len(email.split('@')[1]) if '@' in email else 0,
    }
    return features