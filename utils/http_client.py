import requests
from typing import Dict, Any, Optional

class HTTPClient:
    def post(self, url: str, headers: Dict[str, str], files: Optional[Dict] = None, data: Optional[Dict] = None) -> Dict[str, Any]:
        """Make a POST request"""
        try:
            response = requests.post(url, headers=headers, files=files, data=data)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"HTTP request failed: {str(e)}")
        except ValueError as e:
            raise Exception(f"Invalid JSON response: {str(e)}")

    def get(self, url: str, headers: Dict[str, str], params: Optional[Dict] = None) -> Dict[str, Any]:
        """Make a GET request"""
        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"HTTP request failed: {str(e)}")
        except ValueError as e:
            raise Exception(f"Invalid JSON response: {str(e)}")