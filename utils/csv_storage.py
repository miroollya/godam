"""CSV-based storage for security analysis results"""
import csv
import os
from datetime import datetime
from typing import Dict, Any, List

class CSVStorage:
    def __init__(self):
        self.data_dir = 'data'
        self.files = {
            'file_scans': os.path.join(self.data_dir, 'file_scans.csv'),
            'url_scans': os.path.join(self.data_dir, 'url_scans.csv'),
            'email_scans': os.path.join(self.data_dir, 'email_scans.csv')
        }
        self._init_storage()

    def _init_storage(self):
        """Initialize CSV files with headers"""
        os.makedirs(self.data_dir, exist_ok=True)
        
        headers = {
            'file_scans': ['timestamp', 'filename', 'threat_score', 'verdict', 'vt_detections', 'hybrid_score', 'yara_matches'],
            'url_scans': ['timestamp', 'url', 'threat_score', 'verdict', 'vt_detections', 'hybrid_score'],
            'email_scans': ['timestamp', 'email', 'threat_score', 'verdict', 'vt_detections', 'hybrid_score']
        }
        
        for file_type, filepath in self.files.items():
            if not os.path.exists(filepath):
                with open(filepath, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(headers[file_type])

    def save_scan_result(self, scan_type: str, data: Dict[str, Any]):
        """Save scan result to appropriate CSV file"""
        filepath = self.files.get(f'{scan_type}_scans')
        if not filepath:
            raise ValueError(f"Invalid scan type: {scan_type}")

        row = self._format_row(scan_type, data)
        
        with open(filepath, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(row)

    def _format_row(self, scan_type: str, data: Dict[str, Any]) -> List:
        """Format data into CSV row based on scan type"""
        timestamp = datetime.now().isoformat()
        threat_intel = data.get('threat_intelligence', {})
        summary = threat_intel.get('summary', {})
        detections = threat_intel.get('detection_details', {})
        
        base_row = [
            timestamp,
            summary.get('threat_score', 0),
            summary.get('verdict', 'unknown'),
            detections.get('virustotal', {}).get('malicious', 0),
            detections.get('hybrid_analysis', {}).get('threat_score', 0)
        ]
        
        if scan_type == 'file':
            return [timestamp, data.get('filename', 'unknown')] + base_row + [
                detections.get('yara', {}).get('total_matches', 0)
            ]
        elif scan_type == 'url':
            return [timestamp, data.get('url', '')] + base_row
        else:  # email
            return [timestamp, data.get('email', '')] + base_row

    def get_recent_scans(self, scan_type: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get most recent scan results"""
        filepath = self.files.get(f'{scan_type}_scans')
        if not filepath or not os.path.exists(filepath):
            return []

        results = []
        with open(filepath, 'r', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                results.append(row)
        
        return sorted(results, key=lambda x: x['timestamp'], reverse=True)[:limit]

    def get_statistics(self, scan_type: str) -> Dict[str, Any]:
        """Get statistics for scan type"""
        filepath = self.files.get(f'{scan_type}_scans')
        if not filepath or not os.path.exists(filepath):
            return {}

        stats = {
            'total_scans': 0,
            'malicious': 0,
            'suspicious': 0,
            'clean': 0,
            'avg_threat_score': 0.0
        }

        with open(filepath, 'r', newline='') as f:
            reader = csv.DictReader(f)
            total_threat_score = 0
            
            for row in reader:
                stats['total_scans'] += 1
                verdict = row.get('verdict', '').lower()
                
                if verdict == 'malicious':
                    stats['malicious'] += 1
                elif verdict == 'suspicious':
                    stats['suspicious'] += 1
                else:
                    stats['clean'] += 1
                
                total_threat_score += float(row.get('threat_score', 0))
            
            if stats['total_scans'] > 0:
                stats['avg_threat_score'] = total_threat_score / stats['total_scans']

        return stats