#!/usr/bin/env python3
"""
NetSentry - Network Reconnaissance & Traffic Analysis Platform
Main Flask application
"""

import os
import json
from datetime import datetime
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, jsonify, send_file
from io import BytesIO

from analyzer.nmap_parser import NmapParser
from analyzer.pcap_analyzer import PcapAnalyzer
from analyzer.detection_engine import DetectionEngine
from analyzer.risk_engine import RiskEngine

# Initialize Flask app
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'xml', 'txt', 'pcap', 'pcapng', 'csv'}

# Global analysis state
analysis_state = {
    'nmap_data': None,
    'pcap_data': None,
    'detection_result': None,
    'risk_score': None,
    'analysis_time': None,
    'nmap_file': None,
    'pcap_file': None
}

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    """Homepage"""
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    """Main dashboard"""
    # Load sample data if no analysis yet
    if not analysis_state['nmap_data']:
        load_sample_data()
    
    return render_template('dashboard.html', state=analysis_state)

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Handle file uploads"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': f'File type not allowed. Allowed: {", ".join(ALLOWED_EXTENSIONS)}'}), 400
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        file_type = request.form.get('type', 'unknown')
        
        # Parse based on type
        if file_type == 'nmap':
            result = parse_nmap(filepath, filename)
        elif file_type == 'pcap':
            result = parse_pcap(filepath, filename)
        else:
            return jsonify({'error': 'Unknown file type'}), 400
        
        if 'error' in result:
            return jsonify(result), 400
        
        return jsonify(result), 200
    
    except Exception as e:
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

def parse_nmap(filepath, filename):
    """Parse Nmap file"""
    try:
        parser = NmapParser(filepath)
        nmap_data = parser.parse()
        
        if not nmap_data:
            return {'error': 'Failed to parse Nmap file'}
        
        analysis_state['nmap_data'] = nmap_data
        analysis_state['nmap_file'] = filename
        analysis_state['analysis_time'] = datetime.now().isoformat()
        
        # Run detection if we have both Nmap and PCAP
        run_detection()
        
        return {
            'success': True,
            'message': 'Nmap file parsed successfully',
            'ports_count': len(nmap_data.get('ports', [])),
            'open_ports': len([p for p in nmap_data.get('ports', []) if p['state'] == 'open']),
            'filtered_ports': len([p for p in nmap_data.get('ports', []) if p['state'] == 'filtered'])
        }
    except Exception as e:
        return {'error': f'Nmap parsing failed: {str(e)}'}

def parse_pcap(filepath, filename):
    """Parse PCAP/CSV file"""
    try:
        analyzer = PcapAnalyzer(filepath)
        pcap_data = analyzer.analyze()
        
        if not pcap_data:
            return {'error': 'Failed to parse PCAP file'}
        
        analysis_state['pcap_data'] = pcap_data
        analysis_state['pcap_file'] = filename
        analysis_state['analysis_time'] = datetime.now().isoformat()
        
        # Run detection if we have both Nmap and PCAP
        run_detection()
        
        return {
            'success': True,
            'message': 'PCAP file analyzed successfully',
            'total_packets': pcap_data.get('total_packets', 0),
            'syn_packets': pcap_data.get('syn_packets', 0),
            'unique_dest_ports': len(pcap_data.get('unique_dest_ports', []))
        }
    except Exception as e:
        return {'error': f'PCAP parsing failed: {str(e)}'}

def run_detection():
    """Run detection engine if both data sources are available"""
    if not analysis_state['nmap_data'] or not analysis_state['pcap_data']:
        return
    
    try:
        detector = DetectionEngine()
        detection = detector.detect(
            analysis_state['nmap_data'],
            analysis_state['pcap_data']
        )
        
        analysis_state['detection_result'] = detection
        
        # Calculate risk score
        risk_engine = RiskEngine()
        risk_score = risk_engine.calculate(
            analysis_state['nmap_data'],
            analysis_state['pcap_data'],
            detection
        )
        
        analysis_state['risk_score'] = risk_score
    except Exception as e:
        print(f"Detection error: {e}")

@app.route('/api/state')
def get_state():
    """Get current analysis state (for dashboard updates)"""
    return jsonify(analysis_state)

@app.route('/api/findings')
def get_findings():
    """Get security findings based on current analysis"""
    if not analysis_state['detection_result']:
        return jsonify({'findings': []})
    
    findings = generate_findings()
    return jsonify({'findings': findings})

def generate_findings():
    """Generate security findings"""
    findings = []
    detection = analysis_state['detection_result']
    nmap_data = analysis_state['nmap_data']
    pcap_data = analysis_state['pcap_data']
    
    if not detection or not detection.get('detected'):
        return findings
    
    # Finding 1: TCP Port Scan Detection
    findings.append({
        'title': 'Potential TCP Port Scanning Activity',
        'severity': detection.get('severity', 'Medium'),
        'source': pcap_data.get('source_ip', 'Unknown'),
        'target': pcap_data.get('dest_ip', 'Unknown'),
        'evidence': f"{pcap_data.get('syn_packets', 0)} TCP SYN packets to {len(pcap_data.get('unique_dest_ports', []))} unique destination ports",
        'analysis': 'The observed pattern is consistent with TCP-based network reconnaissance activity.',
        'relevance': 'Port scanning is commonly used during the reconnaissance phase to identify accessible services and determine attack surface.'
    })
    
    # Finding 2: Scan Intensity
    if pcap_data.get('syn_packets', 0) > 50:
        findings.append({
            'title': 'High Volume of Reconnaissance Probes',
            'severity': 'Medium-High',
            'source': pcap_data.get('source_ip', 'Unknown'),
            'target': pcap_data.get('dest_ip', 'Unknown'),
            'evidence': f"{pcap_data.get('syn_packets', 0)} SYN packets observed",
            'analysis': 'The volume of probes indicates systematic reconnaissance rather than isolated connection attempts.',
            'relevance': 'High-volume scanning patterns may indicate advanced reconnaissance or vulnerability assessment activity.'
        })
    
    # Finding 3: Port Response Analysis
    if nmap_data:
        filtered = len([p for p in nmap_data.get('ports', []) if p['state'] == 'filtered'])
        if filtered > 0:
            findings.append({
                'title': 'Filtered Ports - Firewall Protection Detected',
                'severity': 'Informational',
                'source': nmap_data.get('target_ip', 'Unknown'),
                'target': 'Network Perimeter',
                'evidence': f"{filtered} filtered/no-response ports observed",
                'analysis': 'The target appears to have firewall rules in place that prevent or filter port scanning attempts.',
                'relevance': 'Firewall filtering is a defensive control that limits information disclosure during reconnaissance.'
            })
    
    return findings

@app.route('/api/recommendations')
def get_recommendations():
    """Get security recommendations"""
    recommendations = [
        {
            'priority': 'High',
            'title': 'Monitor Port Scanning Activity',
            'description': 'Implement IDS/IPS rules to detect and alert on TCP SYN scanning patterns from unauthorized sources.',
            'control_type': 'Detection'
        },
        {
            'priority': 'High',
            'title': 'Implement Firewall Rules',
            'description': 'Use firewall rules to restrict unnecessary exposed services and limit access to critical ports.',
            'control_type': 'Prevention'
        },
        {
            'priority': 'Medium',
            'title': 'Network Segmentation',
            'description': 'Segment sensitive systems using appropriate network controls to limit lateral movement from compromised systems.',
            'control_type': 'Prevention'
        },
        {
            'priority': 'Medium',
            'title': 'Establish Network Baseline',
            'description': 'Capture baseline network behavior to quickly identify anomalous reconnaissance patterns.',
            'control_type': 'Detection'
        },
        {
            'priority': 'Medium',
            'title': 'Investigate Repeated Scanning',
            'description': 'Correlate network telemetry with security logs to investigate sources of repeated scanning activity.',
            'control_type': 'Investigation'
        }
    ]
    
    return jsonify({'recommendations': recommendations})

@app.route('/api/correlation')
def get_correlation():
    """Get Nmap ↔ PCAP correlation analysis"""
    if not analysis_state['nmap_data'] or not analysis_state['pcap_data']:
        return jsonify({'correlation': None})
    
    nmap = analysis_state['nmap_data']
    pcap = analysis_state['pcap_data']
    
    correlation = {
        'nmap_summary': {
            'target': nmap.get('target_ip'),
            'host_state': nmap.get('host_state'),
            'total_ports_scanned': len(nmap.get('ports', [])),
            'open_ports': len([p for p in nmap.get('ports', []) if p['state'] == 'open']),
            'filtered_ports': len([p for p in nmap.get('ports', []) if p['state'] == 'filtered']),
            'closed_ports': len([p for p in nmap.get('ports', []) if p['state'] == 'closed'])
        },
        'pcap_summary': {
            'source': pcap.get('source_ip'),
            'destination': pcap.get('dest_ip'),
            'total_packets': pcap.get('total_packets'),
            'syn_packets': pcap.get('syn_packets'),
            'unique_dest_ports': len(pcap.get('unique_dest_ports', [])),
            'packet_timestamp': pcap.get('first_packet_time')
        },
        'correlation_analysis': "Nmap reconnaissance results show the scanned ports and their response states. Wireshark traffic provides packet-level evidence of the network activity that produced these results. The TCP SYN packets in the capture correspond to individual Nmap probes, while filtered port responses indicate firewall filtering rather than open services.",
        'interpretation': "The correlation demonstrates that Nmap's filtered/no-response classification aligns with the observation of SYN packets without corresponding SYN-ACK responses, indicating active firewall filtering rather than closed ports."
    }
    
    return jsonify(correlation)

def load_sample_data():
    """Load sample data for demo"""
    try:
        sample_nmap_path = os.path.join(os.path.dirname(__file__), 'sample_data', 'sample_nmap.xml')
        sample_pcap_path = os.path.join(os.path.dirname(__file__), 'sample_data', 'sample_packets.csv')
        
        if os.path.exists(sample_nmap_path):
            parser = NmapParser(sample_nmap_path)
            analysis_state['nmap_data'] = parser.parse()
            analysis_state['nmap_file'] = 'sample_nmap.xml (Demo)'
        
        if os.path.exists(sample_pcap_path):
            analyzer = PcapAnalyzer(sample_pcap_path)
            analysis_state['pcap_data'] = analyzer.analyze()
            analysis_state['pcap_file'] = 'sample_packets.csv (Demo)'
        
        if analysis_state['nmap_data'] and analysis_state['pcap_data']:
            run_detection()
            analysis_state['analysis_time'] = datetime.now().isoformat()
    
    except Exception as e:
        print(f"Sample data loading error: {e}")

@app.errorhandler(413)
def file_too_large(e):
    return jsonify({'error': 'File too large. Maximum size: 16MB'}), 413

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
