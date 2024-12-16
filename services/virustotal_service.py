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
                if data:
                    headers["content-type"] = "application/x-www-form-urlencoded"
                response = requests.post(url, headers=headers, data=data, files=files)
            else:
                response = requests.get(url, headers=headers)
            
            # Check if response is JSON
            content_type = response.headers.get('content-type', '')
            if 'application/json' not in content_type:
                return {
                    "error": True,
                    "message": "Invalid response from VirusTotal API",
                    "details": "Response was not in JSON format"
                }

            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {
                "error": True,
                "message": f"Request failed: {str(e)}"
            }
        except ValueError as e:
            return {
                "error": True,
                "message": f"Invalid JSON response: {str(e)}"
            }
        except Exception as e:
            return {
                "error": True,
                "message": f"Unexpected error: {str(e)}"
            }

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze URL using VirusTotal API"""
        try:
            # First, submit URL for analysis
            data = {"url": url}
            submit_response = self._make_request('urls', 'POST', data=data)
            
            if submit_response.get('error'):
                return submit_response

            # Extract analysis ID from response
            try:
                analysis_id = submit_response['data']['id']
            except (KeyError, TypeError):
                return {
                    "error": True,
                    "message": "Failed to get analysis ID from response"
                }
            
            # Poll for results
            max_attempts = 5
            for attempt in range(max_attempts):
                result_data = self._make_request(f'analyses/{analysis_id}')
                
                if result_data.get('error'):
                    return result_data

                status = result_data.get('data', {}).get('attributes', {}).get('status')
                
                if status == 'completed':
                    return result_data
                
                if attempt < max_attempts - 1:
                    time.sleep(2)
            
            return {
                "error": True,
                "message": "Analysis timed out"
            }
            
        except Exception as e:
            return {
                "error": True,
                "message": f"URL analysis failed: {str(e)}"
            }

    def analyze_file(self, file) -> Dict[str, Any]:
        """Analyze file using VirusTotal API"""
        try:
            # Upload file
            files = {"file": (file.filename, file.stream, "application/octet-stream")}
            upload_response = self._make_request('files', 'POST', files=files)
            
            if upload_response.get('error'):
                return upload_response

            try:
                analysis_id = upload_response['data']['id']
            except (KeyError, TypeError):
                return {
                    "error": True,
                    "message": "Failed to get analysis ID from response"
                }
            
            # Poll for results
            max_attempts = 10
            for attempt in range(max_attempts):
                result_data = self._make_request(f'analyses/{analysis_id}')
                
                if result_data.get('error'):
                    return result_data

                status = result_data.get('data', {}).get('attributes', {}).get('status')
                
                if status == 'completed':
                    return result_data
                
                if attempt < max_attempts - 1:
                    time.sleep(3)
            
            return {
                "error": True,
                "message": "Analysis timed out"
            }
            
        except Exception as e:
            return {
                "error": True,
                "message": f"File analysis failed: {str(e)}"
            }

    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Analyze domain using VirusTotal API"""
        try:
            response = self._make_request(f'domains/{domain}')
            return response
        except Exception as e:
            return {
                "error": True,
                "message": f"Domain analysis failed: {str(e)}"
            }