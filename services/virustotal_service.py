import requests
import time
from config import Config
from utils.http_client import HTTPClient

class VirusTotalService:
    def __init__(self):
        self.api_key = Config.VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.http_client = HTTPClient()

    def analyze_file(self, file):
        """Analyze file using VirusTotal API v3"""
        try:
            # Step 1: Get upload URL
            headers = {
                "accept": "application/json",
                "x-apikey": self.api_key
            }

            # Step 2: Upload file
            upload_url = f"{self.base_url}/files"
            files = {"file": (file.filename, file.stream, "application/octet-stream")}
            
            response = requests.post(
                upload_url,
                headers=headers,
                files=files
            )
            response.raise_for_status()
            upload_data = response.json()

            # Step 3: Get analysis ID
            analysis_id = upload_data['data']['id']
            
            # Step 4: Get analysis results
            analysis_url = f"{self.base_url}/analyses/{analysis_id}"
            
            # Poll for results
            for _ in range(10):  # Try up to 10 times
                response = requests.get(
                    analysis_url,
                    headers=headers
                )
                response.raise_for_status()
                result_data = response.json()
                
                status = result_data.get('data', {}).get('attributes', {}).get('status')
                if status == 'completed':
                    return result_data
                
                time.sleep(3)  # Wait before retrying
            
            return {"error": True, "message": "Analysis timed out"}
            
        except requests.exceptions.RequestException as e:
            return {"error": True, "message": str(e)}
        except Exception as e:
            return {"error": True, "message": f"Unexpected error: {str(e)}"}