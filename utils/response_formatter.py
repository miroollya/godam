"""Format API responses"""
from typing import Dict, Any

class ResponseFormatter:
    @staticmethod
    def format_virustotal_response(response: Dict[str, Any]) -> Dict[str, Any]:
        """Format VirusTotal API response"""
        if response.get('error'):
            return response

        try:
            attributes = response.get('data', {}).get('attributes', {})
            
            # Handle different response types
            if 'stats' in attributes:
                # File/URL scan results
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
            else:
                # Domain analysis results
                return {
                    'malicious': attributes.get('last_analysis_stats', {}).get('malicious', 0),
                    'suspicious': attributes.get('last_analysis_stats', {}).get('suspicious', 0),
                    'undetected': attributes.get('last_analysis_stats', {}).get('undetected', 0),
                    'reputation': attributes.get('reputation', 0),
                    'total_votes': {
                        'harmless': attributes.get('total_votes', {}).get('harmless', 0),
                        'malicious': attributes.get('total_votes', {}).get('malicious', 0)
                    },
                    'categories': attributes.get('categories', {}),
                    'results': attributes.get('last_analysis_results', {})
                }
        except Exception as e:
            return {
                'error': True,
                'message': f'Error formatting response: {str(e)}'
            }