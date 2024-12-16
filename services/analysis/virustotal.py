"""VirusTotal analysis service"""
from typing import Dict, Any
import requests
from config import Config

class VirusTotalAnalyzer:
    def __init__(self):
        self.api_key = Config.VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }

    def analyze_file(self, file_data: bytes) -> Dict[str, Any]:
        """Analyze file using VirusTotal API"""
        try:
            # Upload file
            files = {"file": ("sample", file_data)}
            response = self._make_request('files', 'POST', files=files)
            
            if response.get('error'):
                return response

            return self._get_analysis_results(response['data']['id'])
        except Exception as e:
            return {"error": str(e)}

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze URL using VirusTotal API"""
        try:
            data = {"url": url}
            response = self._make_request('urls', 'POST', data=data)
            
            if response.get('error'):
                return response

            return self._get_analysis_results(response['data']['id'])
        except Exception as e:
            return {"error": str(e)}

    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Analyze domain using VirusTotal API"""
        try:
            return self._make_request(f'domains/{domain}')
        except Exception as e:
            return {"error": str(e)}

    def _make_request(self, endpoint: str, method: str = 'GET', **kwargs) -> Dict:
        """Make request to VirusTotal API"""
        url = f"{self.base_url}/{endpoint}"
        
        try:
            if method == 'POST':
                response = requests.post(url, headers=self.headers, **kwargs)
            else:
                response = requests.get(url, headers=self.headers)
            
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def _get_analysis_results(self, analysis_id: str) -> Dict[str, Any]:
        """Get analysis results"""
        return self._make_request(f'analyses/{analysis_id}')