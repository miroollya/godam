"""Data enrichment utilities for security analysis"""
from typing import Dict, Any, List
import json
import os

class DataEnrichment:
    def __init__(self):
        self.data_dir = 'data'
        self._load_threat_data()

    def _load_threat_data(self):
        """Load threat intelligence data from JSON files"""
        self.threat_data = {
            'known_malware': self._load_json('known_malware.json'),
            'threat_actors': self._load_json('threat_actors.json'),
            'ioc_patterns': self._load_json('ioc_patterns.json')
        }

    def _load_json(self, filename: str) -> Dict:
        """Load JSON file from data directory"""
        filepath = os.path.join(self.data_dir, filename)
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                return json.load(f)
        return {}

    def enrich_scan_data(self, data: Dict[str, Any], scan_type: str) -> Dict[str, Any]:
        """Enrich scan data with additional threat intelligence"""
        enriched_data = data.copy()
        
        # Add known malware information
        if scan_type == 'file':
            self._enrich_file_data(enriched_data)
        elif scan_type == 'url':
            self._enrich_url_data(enriched_data)
        else:  # email
            self._enrich_email_data(enriched_data)
        
        return enriched_data

    def _enrich_file_data(self, data: Dict[str, Any]):
        """Enrich file scan data"""
        threat_intel = data.get('threat_intelligence', {})
        detection_details = threat_intel.get('detection_details', {})
        
        # Add known malware family information
        if 'malware_family' in detection_details.get('hybrid_analysis', {}):
            malware_family = detection_details['hybrid_analysis']['malware_family']
            data['enriched_data'] = {
                'malware_info': self.threat_data['known_malware'].get(malware_family, {}),
                'related_actors': self._get_related_actors(malware_family)
            }

    def _enrich_url_data(self, data: Dict[str, Any]):
        """Enrich URL scan data"""
        url = data.get('url', '')
        threat_intel = data.get('threat_intelligence', {})
        
        # Add known threat actor information
        data['enriched_data'] = {
            'known_campaigns': self._find_related_campaigns(url),
            'threat_categories': self._categorize_url_threat(threat_intel)
        }

    def _enrich_email_data(self, data: Dict[str, Any]):
        """Enrich email scan data"""
        email = data.get('email', '')
        threat_intel = data.get('threat_intelligence', {})
        
        # Add known threat actor information
        data['enriched_data'] = {
            'sender_reputation': self._get_sender_reputation(email),
            'campaign_association': self._find_email_campaigns(email)
        }

    def _get_related_actors(self, malware_family: str) -> List[Dict[str, Any]]:
        """Get threat actors related to malware family"""
        return [
            actor for actor in self.threat_data['threat_actors'].values()
            if malware_family in actor.get('known_malware', [])
        ]

    def _find_related_campaigns(self, url: str) -> List[Dict[str, Any]]:
        """Find campaigns related to URL"""
        campaigns = []
        for pattern in self.threat_data['ioc_patterns'].get('url_patterns', []):
            if pattern['pattern'] in url:
                campaigns.append(pattern['campaign'])
        return campaigns

    def _categorize_url_threat(self, threat_intel: Dict[str, Any]) -> List[str]:
        """Categorize URL threat based on threat intelligence"""
        categories = set()
        if threat_intel.get('phishing', False):
            categories.add('phishing')
        if threat_intel.get('malware_distribution', False):
            categories.add('malware_distribution')
        if threat_intel.get('c2', False):
            categories.add('command_and_control')
        return list(categories)

    def _get_sender_reputation(self, email: str) -> Dict[str, Any]:
        """Get sender reputation data"""
        domain = email.split('@')[1]
        return self.threat_data.get('sender_reputation', {}).get(domain, {
            'score': 0,
            'categories': [],
            'first_seen': None,
            'last_seen': None
        })