from typing import Dict, Any

class ResponseFormatter:
    @staticmethod
    def format_virustotal_response(response: Dict[str, Any]) -> Dict[str, Any]:
        """Format VirusTotal API response"""
        if response.get('error'):
            return response

        try:
            attributes = response.get('data', {}).get('attributes', {})
            stats = attributes.get('stats', {})
            
            return {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'total_scans': sum(stats.values()),
                'scan_date': attributes.get('date'),
                'status': attributes.get('status'),
                'results': attributes.get('results', {})
            }
        except Exception as e:
            return {
                'error': True,
                'message': f'Error formatting response: {str(e)}'
            }