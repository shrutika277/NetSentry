"""
Detection engine for network reconnaissance patterns
"""


class DetectionEngine:
    """Detect TCP port scanning and reconnaissance patterns"""
    
    # Configurable thresholds
    MIN_UNIQUE_PORTS = 5      # Minimum unique destination ports to flag
    MIN_SYN_PACKETS = 10      # Minimum SYN packets to flag
    SYN_THRESHOLD_RATIO = 0.6  # At least 60% SYN packets vs total TCP
    
    def __init__(self):
        self.detections = []
    
    def detect(self, nmap_data, pcap_data):
        """
        Run detection on combined Nmap and PCAP data
        Returns detection result dict
        """
        result = {
            'detected': False,
            'severity': 'None',
            'confidence': 0,
            'rules_triggered': [],
            'analysis': '',
            'evidence': []
        }
        
        if not nmap_data or not pcap_data:
            return result
        
        try:
            # Rule 1: Multiple unique destination ports + SYN traffic
            rule1 = self.check_port_scan_pattern(nmap_data, pcap_data)
            if rule1['triggered']:
                result['detected'] = True
                result['rules_triggered'].append(rule1)
                result['evidence'].append(rule1['description'])
            
            # Rule 2: Correlation between Nmap ports and PCAP traffic
            rule2 = self.check_nmap_pcap_correlation(nmap_data, pcap_data)
            if rule2['triggered']:
                result['rules_triggered'].append(rule2)
                result['evidence'].append(rule2['description'])
            
            # Rule 3: Scan intensity check
            rule3 = self.check_scan_intensity(nmap_data, pcap_data)
            if rule3['triggered']:
                result['rules_triggered'].append(rule3)
                result['evidence'].append(rule3['description'])
            
            # Calculate confidence and severity
            if result['detected']:
                result['confidence'] = min(100, len(result['rules_triggered']) * 40)
                result['severity'] = self.calculate_severity(pcap_data, len(result['rules_triggered']))
                result['analysis'] = self.generate_analysis(result['rules_triggered'], nmap_data, pcap_data)
            
            return result
        
        except Exception as e:
            result['analysis'] = f'Detection error: {str(e)}'
            return result
    
    def check_port_scan_pattern(self, nmap_data, pcap_data):
        """
        Detect port scanning based on unique port probes and SYN traffic
        """
        rule = {
            'name': 'TCP Port Scan Detection',
            'triggered': False,
            'description': '',
            'confidence': 0,
            'evidence': {}
        }
        
        try:
            unique_ports = len(pcap_data.get('unique_dest_ports', []))
            syn_packets = pcap_data.get('syn_packets', 0)
            tcp_packets = pcap_data.get('tcp_packets', 0)
            
            # Check thresholds
            ports_threshold_met = unique_ports >= self.MIN_UNIQUE_PORTS
            syn_threshold_met = syn_packets >= self.MIN_SYN_PACKETS
            
            # Calculate SYN ratio
            syn_ratio = 0
            if tcp_packets > 0:
                syn_ratio = syn_packets / tcp_packets
            
            syn_ratio_threshold_met = syn_ratio >= self.SYN_THRESHOLD_RATIO
            
            # Rule triggering logic
            if (ports_threshold_met and syn_threshold_met) or (syn_ratio_threshold_met and unique_ports >= 3):
                rule['triggered'] = True
                rule['confidence'] = int(
                    (min(unique_ports, 30) / 30 * 50) +
                    (min(syn_packets, 100) / 100 * 30) +
                    (syn_ratio * 20)
                )
            
            rule['evidence'] = {
                'unique_destination_ports': unique_ports,
                'tcp_syn_packets': syn_packets,
                'tcp_total_packets': tcp_packets,
                'syn_ratio': f'{syn_ratio:.2%}',
                'source_ip': pcap_data.get('source_ip'),
                'target_ip': pcap_data.get('dest_ip')
            }
            
            rule['description'] = (
                f"Detected {unique_ports} unique destination ports with {syn_packets} "
                f"TCP SYN packets (SYN ratio: {syn_ratio:.1%}) from {pcap_data.get('source_ip')} "
                f"to {pcap_data.get('dest_ip')}"
            )
        
        except Exception as e:
            print(f"Port scan detection error: {e}")
        
        return rule
    
    def check_nmap_pcap_correlation(self, nmap_data, pcap_data):
        """
        Correlate Nmap probed ports with PCAP packet destinations
        """
        rule = {
            'name': 'Nmap-PCAP Correlation',
            'triggered': False,
            'description': '',
            'confidence': 0,
            'evidence': {}
        }
        
        try:
            # Get ports from Nmap
            nmap_ports = set(p['port'] for p in nmap_data.get('ports', []))
            
            # Get ports from PCAP
            pcap_ports = set(pcap_data.get('unique_dest_ports', []))
            
            if nmap_ports and pcap_ports:
                # Calculate overlap
                overlap = nmap_ports & pcap_ports
                overlap_ratio = len(overlap) / max(len(nmap_ports), len(pcap_ports))
                
                # If significant overlap, ports in Nmap were actively probed
                if overlap_ratio > 0.3 and len(overlap) >= 3:
                    rule['triggered'] = True
                    rule['confidence'] = int(overlap_ratio * 100)
                
                rule['evidence'] = {
                    'nmap_ports_scanned': len(nmap_ports),
                    'pcap_destination_ports': len(pcap_ports),
                    'ports_in_both': len(overlap),
                    'overlap_percentage': f'{overlap_ratio:.1%}'
                }
                
                rule['description'] = (
                    f"Nmap scanning activity correlates with packet capture evidence: "
                    f"{len(overlap)} ports probed in both datasets"
                )
        
        except Exception as e:
            print(f"Correlation check error: {e}")
        
        return rule
    
    def check_scan_intensity(self, nmap_data, pcap_data):
        """
        Assess scanning intensity and speed
        """
        rule = {
            'name': 'Scan Intensity Assessment',
            'triggered': False,
            'description': '',
            'confidence': 0,
            'evidence': {}
        }
        
        try:
            syn_packets = pcap_data.get('syn_packets', 0)
            unique_ports = len(pcap_data.get('unique_dest_ports', []))
            
            # High intensity: many probes to many ports
            if syn_packets >= 20 and unique_ports >= 10:
                rule['triggered'] = True
                rule['confidence'] = min(95, int((syn_packets / 100 + unique_ports / 30) * 50))
                intensity_level = 'High'
            elif syn_packets >= 10 and unique_ports >= 5:
                rule['triggered'] = True
                rule['confidence'] = int((syn_packets / 50 + unique_ports / 20) * 40)
                intensity_level = 'Medium'
            else:
                intensity_level = 'Low'
            
            rule['evidence'] = {
                'syn_packet_count': syn_packets,
                'unique_ports_probed': unique_ports,
                'intensity_level': intensity_level
            }
            
            rule['description'] = (
                f"Scan intensity assessment: {intensity_level} - "
                f"{syn_packets} SYN packets across {unique_ports} unique destination ports"
            )
        
        except Exception as e:
            print(f"Intensity check error: {e}")
        
        return rule
    
    def calculate_severity(self, pcap_data, rules_triggered_count):
        """
        Calculate overall severity based on multiple factors
        """
        syn_packets = pcap_data.get('syn_packets', 0)
        unique_ports = len(pcap_data.get('unique_dest_ports', []))
        
        # Base severity on rules triggered
        if rules_triggered_count >= 3:
            base_severity = 'High'
        elif rules_triggered_count == 2:
            base_severity = 'Medium-High'
        else:
            base_severity = 'Medium'
        
        # Adjust based on intensity
        if syn_packets > 100 and unique_ports > 50:
            base_severity = 'High'
        elif syn_packets < 5 or unique_ports < 3:
            base_severity = 'Low-Medium'
        
        return base_severity
    
    def generate_analysis(self, rules_triggered, nmap_data, pcap_data):
        """
        Generate human-readable analysis explanation
        """
        analysis_parts = []
        
        analysis_parts.append(
            "Network reconnaissance activity detected based on the correlation of "
            "Nmap scanning results and live network traffic capture."
        )
        
        if rules_triggered:
            analysis_parts.append(f"\n{len(rules_triggered)} detection rule(s) triggered:")
            for rule in rules_triggered:
                analysis_parts.append(f"  • {rule['name']}: {rule['description']}")
        
        analysis_parts.append(
            "\nThis activity is consistent with network reconnaissance, commonly performed during "
            "the initial intelligence-gathering phase of security assessments or adversarial activity."
        )
        
        nmap_filtered = len([p for p in nmap_data.get('ports', []) if p['state'] == 'filtered'])
        if nmap_filtered > 0:
            analysis_parts.append(
                f"\nThe presence of {nmap_filtered} filtered/no-response ports indicates "
                "active firewall or rate-limiting protection on the target."
            )
        
        analysis_parts.append(
            "\nNote: Port scanning alone does not indicate malicious intent. Legitimate security "
            "assessments, network administration, and vulnerability testing routinely use port "
            "scanning techniques. Context is required for attribution."
        )
        
        return '\n'.join(analysis_parts)
