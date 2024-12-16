"""Service for aggregating and analyzing threat intelligence"""
from typing import Dict, Any, List
import json
from datetime import datetime

class ThreatIntelligenceService:
    def __init__(self):
        self.threat_levels = {
            'clean': 0,
            'suspicious': 1,
            'malicious': 2
        }

    def aggregate_results(self, 
                         vt_results: Dict[str, Any],
                         hybrid_results: Dict[str, Any],
                         yara_results: Dict[str, Any]) -> Dict[str, Any]:
        """Aggregate results from different scanning services"""
        
        # Calculate overall threat score
        threat_score = self._calculate_threat_score(vt_results, hybrid_results, yara_results)
        
        # Determine verdict
        verdict = self._determine_verdict(threat_score)
        
        # Collect IOCs
        iocs = self._extract_iocs(vt_results, hybrid_results)
        
        # Gather geographic data
        geo_data = self._collect_geo_data(vt_results, hybrid_results)
        
        return {
            'summary': {
                'threat_score': threat_score,
                'verdict': verdict,
                'scan_time': datetime.utcnow().isoformat(),
                'total_detections': self._count_total_detections(vt_results, hybrid_results, yara_results)
            },
            'threat_intel': {
                'iocs': iocs,
                'geo_data': geo_data,
                'malware_families': self._extract_malware_families(hybrid_results),
                'attack_techniques': self._extract_attack_techniques(hybrid_results)
            },
            'detection_details': {
                'virustotal': self._format_vt_detections(vt_results),
                'hybrid_analysis': self._format_hybrid_detections(hybrid_results),
                'yara': self._format_yara_detections(yara_results)
            }
        }

    def _calculate_threat_score(self, vt_results: Dict, hybrid_results: Dict, yara_results: Dict) -> float:
        """Calculate normalized threat score (0-100)"""
        score = 0
        total_weight = 0
        
        # VirusTotal score (weight: 0.4)
        if 'malicious' in vt_results:
            vt_score = (vt_results['malicious'] / max(vt_results.get('total_scans', 1), 1)) * 100
            score += vt_score * 0.4
            total_weight += 0.4
            
        # Hybrid Analysis score (weight: 0.4)
        if 'threat_score' in hybrid_results:
            score += hybrid_results['threat_score'] * 0.4
            total_weight += 0.4
            
        # YARA score (weight: 0.2)
        if 'total_matches' in yara_results:
            yara_score = min(yara_results['total_matches'] * 20, 100)
            score += yara_score * 0.2
            total_weight += 0.2
            
        return score / total_weight if total_weight > 0 else 0

    def _determine_verdict(self, threat_score: float) -> str:
        """Determine verdict based on threat score"""
        if threat_score >= 75:
            return 'Malicious'
        elif threat_score >= 30:
            return 'Suspicious'
        return 'Clean'

    def _extract_iocs(self, vt_results: Dict, hybrid_results: Dict) -> Dict[str, List[str]]:
        """Extract Indicators of Compromise"""
        iocs = {
            'ips': set(),
            'domains': set(),
            'urls': set(),
            'hashes': set()
        }
        
        # Extract from Hybrid Analysis
        if 'network_connections' in hybrid_results:
            for conn in hybrid_results['network_connections']:
                if 'ip' in conn:
                    iocs['ips'].add(conn['ip'])
                if 'domain' in conn:
                    iocs['domains'].add(conn['domain'])
                    
        # Extract from VirusTotal
        if 'network_traffic' in vt_results:
            for traffic in vt_results['network_traffic']:
                if 'ip' in traffic:
                    iocs['ips'].add(traffic['ip'])
                if 'domain' in traffic:
                    iocs['domains'].add(traffic['domain'])
                    
        return {k: list(v) for k, v in iocs.items()}

    def _collect_geo_data(self, vt_results: Dict, hybrid_results: Dict) -> List[Dict]:
        """Collect geographic data for threat mapping"""
        geo_data = []
        
        # Add Hybrid Analysis geo data
        if 'geolocation' in hybrid_results:
            for location in hybrid_results['geolocation']:
                geo_data.append({
                    'latitude': location.get('latitude'),
                    'longitude': location.get('longitude'),
                    'country': location.get('country'),
                    'city': location.get('city'),
                    'source': 'Hybrid Analysis'
                })
                
        # Add VirusTotal geo data
        if 'resolution' in vt_results:
            for resolution in vt_results['resolution']:
                if 'geo_location' in resolution:
                    geo_data.append({
                        'latitude': resolution['geo_location'].get('latitude'),
                        'longitude': resolution['geo_location'].get('longitude'),
                        'country': resolution['geo_location'].get('country'),
                        'city': resolution['geo_location'].get('city'),
                        'source': 'VirusTotal'
                    })
                    
        return geo_data

    def _extract_malware_families(self, hybrid_results: Dict) -> List[str]:
        """Extract malware family information"""
        families = set()
        
        if 'malware_family' in hybrid_results:
            families.add(hybrid_results['malware_family'])
            
        if 'signatures' in hybrid_results:
            for sig in hybrid_results['signatures']:
                if 'malware_family' in sig:
                    families.add(sig['malware_family'])
                    
        return list(families)

    def _extract_attack_techniques(self, hybrid_results: Dict) -> List[Dict]:
        """Extract MITRE ATT&CK techniques"""
        techniques = []
        
        if 'mitre_attck' in hybrid_results:
            for technique in hybrid_results['mitre_attck']:
                techniques.append({
                    'id': technique.get('technique_id'),
                    'name': technique.get('technique_name'),
                    'tactic': technique.get('tactic'),
                    'description': technique.get('description')
                })
                
        return techniques

    def _format_vt_detections(self, vt_results: Dict) -> Dict:
        """Format VirusTotal detections"""
        return {
            'malicious': vt_results.get('malicious', 0),
            'suspicious': vt_results.get('suspicious', 0),
            'undetected': vt_results.get('undetected', 0),
            'total_scans': vt_results.get('total_scans', 0),
            'scan_date': vt_results.get('scan_date')
        }

    def _format_hybrid_detections(self, hybrid_results: Dict) -> Dict:
        """Format Hybrid Analysis detections"""
        return {
            'verdict': hybrid_results.get('verdict'),
            'threat_score': hybrid_results.get('threat_score'),
            'threat_level': hybrid_results.get('threat_level'),
            'signatures': hybrid_results.get('signatures', [])
        }

    def _format_yara_detections(self, yara_results: Dict) -> Dict:
        """Format YARA detections"""
        return {
            'total_matches': yara_results.get('total_matches', 0),
            'matches': yara_results.get('matches', [])
        }

    def _count_total_detections(self, vt_results: Dict, hybrid_results: Dict, yara_results: Dict) -> int:
        """Count total detections across all services"""
        total = 0
        
        # VirusTotal detections
        total += vt_results.get('malicious', 0)
        total += vt_results.get('suspicious', 0)
        
        # Hybrid Analysis detections
        if hybrid_results.get('verdict') in ['malicious', 'suspicious']:
            total += 1
            
        # YARA detections
        total += yara_results.get('total_matches', 0)
        
        return total