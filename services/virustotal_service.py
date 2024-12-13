"""Service for VirusTotal analysis"""
import requests
import time
from typing import Dict, Any
from config import Config

class VirusTotalService:
    def __init__(self):
        self.api_key = Config.VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"

    def _make_request(self, endpoint: str, method: str = 'GET', data: Dict = None, files: Dict = None) -> Dict:
        """Make request to VirusTotal API"""
        headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }
        
        url = f"{self.base_url}/{endpoint}"
        
        try:
            if method == 'POST':
                response = requests.post(url, headers=headers, data=data, files=files)
            else:
                response = requests.get(url, headers=headers)
            
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": True, "message": str(e)}

    def analyze_file(self, file) -> Dict[str, Any]:
        """Analyze file using VirusTotal API"""
        try:
            # Upload file
            files = {"file": (file.filename, file.stream, "application/octet-stream")}
            upload_response = self._make_request('files', 'POST', files=files)
            
            if upload_response.get('error'):
                return upload_response

            analysis_id = upload_response['data']['id']
            
            # Poll for results
            for _ in range(10):
                result_data = self._make_request(f'analyses/{analysis_id}')
                
                if result_data.get('data', {}).get('attributes', {}).get('status') == 'completed':
                    return result_data
                
                time.sleep(3)
            
            return {"error": True, "message": "Analysis timed out"}
            
        except Exception as e:
            return {"error": True, "message": str(e)}

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze URL using VirusTotal API"""
        try:
            # Submit URL for analysis
            data = {"url": url}
            submit_response = self._make_request('urls', 'POST', data=data)
            
            if submit_response.get('error'):
                return submit_response

            analysis_id = submit_response['data']['id']
            
            # Poll for results
            for _ in range(5):
                result_data = self._make_request(f'analyses/{analysis_id}')
                
                if result_data.get('data', {}).get('attributes', {}).get('status') == 'completed':
                    return result_data
                
                time.sleep(2)
            
            return {"error": True, "message": "Analysis timed out"}
            
        except Exception as e:
            return {"error": True, "message": str(e)}

    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Analyze domain from email address using VirusTotal API"""
        try:
            response = self._make_request(f'domains/{domain}')
            return response
        except Exception as e:
            return {"error": True, "message": str(e)}