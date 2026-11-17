"""
Risk scoring engine for NetSentry
"""


class RiskEngine:
    """Calculate risk scores based on reconnaissance patterns"""
    
    def calculate(self, nmap_data, pcap_data, detection_result):
        """
        Calculate overall risk score (0-100)
        
        Factors:
        - Number of unique destination ports
        - Number of SYN packets (probe volume)
        - Scan intensity (speed and breadth)
        - Number of open/responsive ports
        - Number of filtered ports (defensive)
        - Detection rules triggered
        """
        
        score = 0
        factors = {}
        
        try:
            # Factor 1: Unique destination ports (0-30 points)
            unique_ports = len(pcap_data.get('unique_dest_ports', []))
            port_score = min(30, (unique_ports / 50 * 30))
            factors['unique_ports'] = {
                'value': unique_ports,
                'score': port_score,
                'weight': 30
            }
            score += port_score
            
            # Factor 2: SYN packet volume (0-25 points)
            syn_packets = pcap_data.get('syn_packets', 0)
            syn_score = min(25, (syn_packets / 150 * 25))
            factors['syn_volume'] = {
                'value': syn_packets,
                'score': syn_score,
                'weight': 25
            }
            score += syn_score
            
            # Factor 3: Scan intensity (0-20 points)
            # Combine unique ports and syn packet count
            intensity_score = self.calculate_intensity_score(unique_ports, syn_packets)
            factors['intensity'] = {
                'value': f'{unique_ports} ports, {syn_packets} packets',
                'score': intensity_score,
                'weight': 20
            }
            score += intensity_score
            
            # Factor 4: Detection confidence (0-15 points)
            detection_confidence = detection_result.get('confidence', 0) if detection_result else 0
            conf_score = (detection_confidence / 100) * 15
            factors['detection_confidence'] = {
                'value': f'{detection_confidence}%',
                'score': conf_score,
                'weight': 15
            }
            score += conf_score
            
            # Factor 5: Open services (0-10 points, but reduces risk if none exposed)
            open_ports = len(nmap_data.get('open_ports', []))
            open_score = min(10, (open_ports / 10 * 10))
            factors['open_services'] = {
                'value': open_ports,
                'score': open_score,
                'weight': 10
            }
            score += open_score
            
            # Normalize score to 0-100
            score = min(100, max(0, score))
            
            # Determine risk level
            risk_level = self.get_risk_level(score)
            
            return {
                'overall_score': int(score),
                'risk_level': risk_level,
                'factors': factors,
                'recommendation': self.get_recommendation(score, risk_level),
                'methodology': 'NetSentry heuristic risk score (project-specific)',
                'disclaimer': 'This score is for prioritizing investigation within this lab environment and is not a replacement for CVSS or enterprise risk frameworks.'
            }
        
        except Exception as e:
            print(f"Risk calculation error: {e}")
            return {
                'overall_score': 0,
                'risk_level': 'Unknown',
                'factors': {},
                'recommendation': 'Unable to calculate risk score',
                'methodology': 'Error',
                'disclaimer': 'Risk calculation failed'
            }
    
    def calculate_intensity_score(self, unique_ports, syn_packets):
        """Calculate scan intensity score (0-20)"""
        if unique_ports < 3 or syn_packets < 5:
            return 0
        elif unique_ports < 10 and syn_packets < 20:
            return 5
        elif unique_ports < 20 and syn_packets < 50:
            return 10
        elif unique_ports < 50 and syn_packets < 150:
            return 15
        else:
            return 20
    
    def get_risk_level(self, score):
        """Map score to risk level"""
        if score >= 80:
            return 'Critical'
        elif score >= 60:
            return 'High'
        elif score >= 40:
            return 'Medium'
        elif score >= 20:
            return 'Low-Medium'
        else:
            return 'Low'
    
    def get_recommendation(self, score, risk_level):
        """Get recommendation based on risk level"""
        recommendations = {
            'Critical': (
                'Immediate investigation required. Implement emergency response procedures. '
                'Isolate affected systems if necessary. Escalate to security operations center. '
                'Preserve all evidence for forensic analysis.'
            ),
            'High': (
                'High priority investigation required. Review source IP reputation and historical activity. '
                'Check for lateral movement indicators. Implement enhanced monitoring on the target system. '
                'Correlate with other security alerts.'
            ),
            'Medium': (
                'Standard investigation warranted. Document the scanning activity. '
                'Review firewall and IDS logs. Verify if scanning is authorized. '
                'Establish baseline for future anomaly detection.'
            ),
            'Low-Medium': (
                'Low-priority monitoring recommended. Track for patterns over time. '
                'Verify if related to scheduled security assessments. '
                'Update network baseline with this observation.'
            ),
            'Low': (
                'Minimal risk. Continued monitoring recommended as best practice. '
                'Record for historical reference and trend analysis.'
            )
        }
        return recommendations.get(risk_level, 'Unable to determine recommendation')
