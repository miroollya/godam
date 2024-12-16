"""Service for Hybrid Analysis integration"""
import requests
from typing import Dict, Any, Optional
from config import Config

class HybridAnalysisService:
    def __init__(self):
        self.api_key = Config.HYBRID_ANALYSIS_API_KEY
        self.base_url = "https://www.hybrid-analysis.com/api/v2"
        self.headers = {
            "api-key": self.api_key,
            "User-Agent": "Falcon Sandbox"
        }

    async def analyze_file(self, file_data: bytes, filename: str) -> Dict[str, Any]:
        """Submit file for analysis"""
        try:
            files = {
                'file': (filename, file_data)
            }
            data = {
                'environment_id': 100,  # Windows 10 64-bit
                'allow_community_access': False,
                'no_share_third_party': True
            }
            
            response = requests.post(
                f"{self.base_url}/submit/file",
                headers=self.headers,
                files=files,
                data=data
            )
            response.raise_for_status()
            
            submission_data = response.json()
            return await self._poll_analysis_result(submission_data['job_id'])
        except Exception as e:
            return {"error": str(e)}

    async def analyze_url(self, url: str) -> Dict[str, Any]:
        """Submit URL for analysis"""
        try:
            data = {
                'url': url,
                'environment_id': 100
            }
            
            response = requests.post(
                f"{self.base_url}/submit/url",
                headers=self.headers,
                data=data
            )
            response.raise_for_status()
            
            submission_data = response.json()
            return await self._poll_analysis_result(submission_data['job_id'])
        except Exception as e:
            return {"error": str(e)}

    async def _poll_analysis_result(self, job_id: str, max_attempts: int = 30) -> Dict[str, Any]:
        """Poll for analysis results"""
        import asyncio
        
        for _ in range(max_attempts):
            try:
                response = requests.get(
                    f"{self.base_url}/report/{job_id}/summary",
                    headers=self.headers
                )
                response.raise_for_status()
                
                result = response.json()
                if result.get('status') == 'completed':
                    return self._format_analysis_result(result)
                
                await asyncio.sleep(10)
            except Exception as e:
                return {"error": str(e)}
        
        return {"error": "Analysis timed out"}

    def _format_analysis_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Format analysis results"""
        return {
            'verdict': result.get('verdict'),
            'threat_score': result.get('threat_score'),
            'threat_level': result.get('threat_level'),
            'malware_family': result.get('malware_family'),
            'signatures': result.get('signatures', []),
            'processes': result.get('processes', []),
            'network_connections': result.get('network_connections', []),
            'geolocation': result.get('geolocation', {})
        }