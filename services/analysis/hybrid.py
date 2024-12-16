"""Hybrid Analysis service"""
from typing import Dict, Any
import requests
import asyncio
from config import Config

class HybridAnalyzer:
    def __init__(self):
        self.api_key = Config.HYBRID_ANALYSIS_API_KEY
        self.base_url = "https://www.hybrid-analysis.com/api/v2"
        self.headers = {
            "api-key": self.api_key,
            "User-Agent": "Falcon Sandbox"
        }

    async def analyze_file(self, file_data: bytes, filename: str) -> Dict[str, Any]:
        """Analyze file using Hybrid Analysis"""
        try:
            submission = await self._submit_file(file_data, filename)
            if submission.get('error'):
                return submission
            
            return await self._poll_results(submission['job_id'])
        except Exception as e:
            return {"error": str(e)}

    async def analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze URL using Hybrid Analysis"""
        try:
            submission = await self._submit_url(url)
            if submission.get('error'):
                return submission
            
            return await self._poll_results(submission['job_id'])
        except Exception as e:
            return {"error": str(e)}

    async def _submit_file(self, file_data: bytes, filename: str) -> Dict[str, Any]:
        """Submit file for analysis"""
        files = {'file': (filename, file_data)}
        data = {'environment_id': 100}
        
        response = requests.post(
            f"{self.base_url}/submit/file",
            headers=self.headers,
            files=files,
            data=data
        )
        return response.json()

    async def _submit_url(self, url: str) -> Dict[str, Any]:
        """Submit URL for analysis"""
        data = {'url': url, 'environment_id': 100}
        
        response = requests.post(
            f"{self.base_url}/submit/url",
            headers=self.headers,
            data=data
        )
        return response.json()

    async def _poll_results(self, job_id: str, max_attempts: int = 30) -> Dict[str, Any]:
        """Poll for analysis results"""
        for _ in range(max_attempts):
            response = requests.get(
                f"{self.base_url}/report/{job_id}/summary",
                headers=self.headers
            )
            
            result = response.json()
            if result.get('status') == 'completed':
                return self._format_results(result)
            
            await asyncio.sleep(10)
        
        return {"error": "Analysis timed out"}

    def _format_results(self, result: Dict[str, Any]) -> Dict[str, Any]:
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