# NetSentry — Network Reconnaissance & Traffic Analysis Platform

**A cybersecurity analytics platform for detecting and analyzing network reconnaissance patterns.**

## Overview

NetSentry is an educational network-security analytics platform developed for controlled cybersecurity experimentation. It combines Nmap reconnaissance data with live Wireshark packet captures to identify, visualize, and assess network scanning patterns.

The platform demonstrates:
- Network security data analysis
- Real-time reconnaissance detection
- Risk scoring and prioritization
- Security findings generation
- Evidence correlation and forensic capability

## Problem Statement

Manual analysis of network reconnaissance data requires:
- Parsing multiple output formats (Nmap XML, text, PCAP)
- Correlating reconnaissance evidence across tools
- Identifying patterns consistent with port scanning
- Generating structured security findings
- Assessing risk and recommending controls

NetSentry automates this workflow, providing SOC-like analysis in a lightweight package.

## Objectives

1. **Parse reconnaissance data** from Nmap and Wireshark
2. **Detect TCP port scanning patterns** using rule-based engine
3. **Correlate evidence** between Nmap results and packet captures
4. **Visualize findings** with professional dashboard and charts
5. **Generate structured findings** with severity and recommendations
6. **Score risk** using multi-factor heuristic assessment

## Architecture

### Backend
- **Python** - Core analysis logic
- **Flask** - Web framework
- **XML parsing** - Nmap result extraction
- **CSV parsing** - Wireshark export handling

### Frontend
- **HTML5** - Semantic markup
- **CSS3** - Dark-themed professional UI
- **JavaScript** - Dashboard interactivity
- **Chart.js** - Data visualization

### Analysis Modules
- **nmap_parser.py** - Parse Nmap XML/text output
- **pcap_analyzer.py** - Analyze PCAP/CSV packet data
- **detection_engine.py** - Rule-based reconnaissance detection
- **risk_engine.py** - Multi-factor risk scoring

## Technology Stack

```
Frontend:
- HTML5, CSS3, JavaScript
- Chart.js (CDN)

Backend:
- Python 3.7+
- Flask 2.3+

Database:
- None (in-memory analysis)

Deployment:
- Local Flask development server
```

## Features

### 1. **Nmap Analysis**
- Parse Nmap XML and text output
- Extract port state, service, and version information
- Display summary statistics and port tables
- Detect host status and response patterns

### 2. **PCAP/Wireshark Analysis**
- Support CSV export from Wireshark
- Analyze packet-level TCP SYN patterns
- Calculate unique destination ports and probe volume
- Extract source/destination traffic metadata

### 3. **Detection Engine**
**Rule 1: TCP Port Scan Pattern Detection**
- Triggers when unique destination ports ≥ 5 AND SYN packets ≥ 10
- OR when SYN ratio ≥ 60% across multiple ports
- Confidence calculation based on probe characteristics

**Rule 2: Nmap-PCAP Correlation**
- Identify ports in both Nmap results and packet capture
- Calculate overlap ratio to confirm active probing
- Triggers at 30%+ overlap with ≥3 common ports

**Rule 3: Scan Intensity Assessment**
- Evaluate systematic scanning behavior
- Rate as Low/Medium/High based on SYN volume and port breadth

### 4. **Risk Scoring**
Multi-factor risk engine (0-100 scale):
- **30%** - Unique destination ports
- **25%** - SYN packet volume
- **20%** - Scan intensity (breadth × speed)
- **15%** - Detection confidence
- **10%** - Open service exposure

Risk Levels:
- **80-100**: Critical
- **60-79**: High
- **40-59**: Medium
- **20-39**: Low-Medium
- **0-19**: Low

### 5. **Visualization**
- Dashboard metrics cards
- Destination port distribution bar chart
- Risk score breakdown doughnut chart
- Evidence summary tables
- Professional dark-themed UI

### 6. **Security Findings & Recommendations**
- Structured findings with severity ratings
- Evidence-based analysis
- Security relevance explanations
- Actionable defense recommendations (7 baseline controls)

### 7. **Evidence Correlation**
- Nmap scanning results ↔ packet capture alignment
- Explanation of port state classifications
- Interpretation of firewall filtering behavior

## Detection Methodology

### Evidence Correlation Approach

**Nmap Perspective:**
- Shows probed ports and response states
- Filtered/no-response indicates firewall filtering
- Open ports indicate responsive services

**PCAP Perspective:**
- Shows packet-level activity during scan
- TCP SYN packets represent initial probes
- Absence of SYN-ACK indicates filtered/no-response

**Correlation:**
```
Nmap filtered port
    ↓
Matches with PCAP TCP SYN probe
    ↓
No SYN-ACK response observed
    ↓
Confirms: Firewall filtering active
```

### Heuristic Thresholds

```python
MIN_UNIQUE_PORTS = 5          # Unique destination ports
MIN_SYN_PACKETS = 10          # Minimum SYN probes
SYN_THRESHOLD_RATIO = 0.6     # 60% of TCP traffic is SYN
```

These values are **configurable** in `analyzer/detection_engine.py`.

## Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package manager)
- Web browser (Chrome, Firefox, Safari, Edge)

### Steps

**1. Clone/Download NetSentry**
```bash
git clone https://github.com/yourusername/netsentry.git
cd netsentry
```

**2. Create virtual environment (recommended)**
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

**4. Create upload directories**
```bash
mkdir -p uploads sample_data
```

**5. Run application**
```bash
python app.py
```

**6. Open in browser**
```
http://127.0.0.1:5000
```

## Usage

### Quick Start (Using Sample Data)

1. Navigate to `http://127.0.0.1:5000`
2. Click **"Dashboard"**
3. Sample data loads automatically
4. View metrics, charts, findings

### Uploading Your Own Evidence

#### Step 1: Export Nmap Results

**As XML (Recommended):**
```bash
nmap -Pn -T4 -oX nmap_results.xml 192.168.71.1
```

**As Text:**
```bash
nmap -Pn -T4 192.168.71.1 > nmap_results.txt
```

#### Step 2: Capture Traffic with Wireshark

**Filter for TCP SYN:**
```
ip.addr == 192.168.71.1 && tcp.flags.syn == 1
```

**Export as CSV:**
1. File → Export Specified Packets
2. Select "Comma Separated Values" format
3. Save as `packets.csv`

#### Step 3: Upload to NetSentry

1. Go to Dashboard
2. Click "Upload Nmap Results" → Select your `.xml` or `.txt` file
3. Click "Upload PCAP/Wireshark Data" → Select your `.csv` file
4. Analysis runs automatically
5. View findings, visualizations, recommendations

### Lab Environment Reference

```
Kali Linux Scanner:
  IP: 192.168.71.128
  Interface: eth0
  Subnet: 192.168.71.0/24

Windows Host (Target):
  VMware VMnet1: 192.168.71.1
  Subnet Mask: 255.255.255.0
  Network: Host-only (VMnet1)
```

## Example Workflow

### Scenario: Detecting TCP Port Scan

**1. Perform Nmap scan:**
```bash
kali@kali:~$ nmap -Pn -T4 --top-ports 100 192.168.71.1 -oX scan.xml
Nmap scan report for 192.168.71.1
Host is up (0.0025s latency).

Not shown: 1000 filtered tcp ports (no-response)
```

**2. Capture traffic:**
```bash
Wireshark filter:
  ip.addr == 192.168.71.1 && tcp.flags.syn == 1

Observed:
  192.168.71.128 → 192.168.71.1
  TCP SYN packets to ports: 22, 80, 139, 443, 445, 3306, 8080, ...
  19 unique destination ports
```

**3. Upload to NetSentry:**
- Upload scan.xml (Nmap results)
- Upload packets.csv (Wireshark export)

**4. Detection Result:**
```
✓ Potential TCP Port Scanning Detected

Severity: Medium-High
Confidence: 78%

Evidence:
- 19 unique destination ports probed
- 19 TCP SYN packets observed
- 100% SYN ratio (all TCP traffic was SYN)
- Source: 192.168.71.128 → Target: 192.168.71.1

Risk Score: 65/High

Findings:
1. TCP Port Scan Detection
2. Nmap-PCAP Correlation
3. Scan Intensity Assessment (High)

Recommendations:
- Monitor for repeated SYN requests
- Review firewall logs
- Segment sensitive systems
- Implement IDS rules
```

## Security Considerations

### What This Application Is

✓ Educational network security analysis tool  
✓ Designed for controlled lab environments  
✓ Demonstrates reconnaissance detection  
✓ Shows evidence correlation techniques  
✓ Portfolio/interview project material  

### What This Application Is NOT

✗ Production IDS/IPS system  
✗ Real-time network monitoring solution  
✗ Commercial vulnerability scanner  
✗ Network access control system  
✗ Incident response platform  

### Design Safeguards

- **No scanning capability** - Analysis only, does not send packets
- **File upload restrictions** - Only `.xml`, `.txt`, `.csv`, `.pcap` allowed
- **No command execution** - All input is parsed, not executed
- **No network access** - Runs locally, no external communications
- **Local deployment only** - Not designed for public internet

## Limitations

1. **Scope**: Focuses on TCP port scanning; does not detect other reconnaissance methods
2. **Accuracy**: Detection based on heuristics, not signatures or machine learning
3. **Scale**: Optimized for smaller scans; performance degrades with massive datasets
4. **Data**: Requires properly formatted Nmap and PCAP input
5. **Attribution**: Cannot determine if scanning is authorized or malicious
6. **Live Scanning**: Does not perform active scans (analysis-only tool)

## Future Scope

### Phase 2 - Enhanced Analysis
- Direct PCAP file parsing (Scapy/PyShark)
- Real-time packet capture integration
- SYN-ACK response analysis
- TCP connection completion detection

### Phase 3 - Advanced Detections
- Nmap fingerprinting pattern recognition
- Service enumeration detection (banner grabbing)
- OS fingerprinting activity detection
- Timing analysis for scan speed classification
- UDP scanning detection

### Phase 4 - Integration & Enrichment
- MITRE ATT&CK framework mapping
- Threat intelligence IP reputation lookup
- Shodan integration for service identification
- CVE database correlation
- Historical scan trending

### Phase 5 - Incident Response
- Alerting and notifications
- Investigation workflow templates
- Playbook-driven response recommendations
- Automated evidence preservation
- Report generation with PDF export

### Phase 6 - Scaling
- Multi-user support with authentication
- Database backend (SQLite→PostgreSQL)
- Role-based access control
- Audit logging
- Cloud deployment (AWS/Azure)
- Splunk/Wazuh integration

## Example Screenshots

### Dashboard
```
╔════════════════════════════════════════╗
║  NetSentry Analysis Dashboard          ║
║  192.168.71.128 → 192.168.71.1         ║
╠════════════════════════════════════════╣
║                                        ║
║  📊 Ports Scanned: 1000                ║
║  ✅ Open Ports: 0                       ║
║  🚫 Filtered Ports: 1000                ║
║  📡 TCP SYN Packets: 19                 ║
║  🎯 Unique Dest Ports: 19               ║
║  ⚠️  Risk Score: 65/High                ║
║                                        ║
║  ⚡ Potential TCP Port Scan Detected    ║
║     Severity: Medium-High              ║
║     Confidence: 78%                    ║
║                                        ║
╚════════════════════════════════════════╝
```

### Findings
```
Finding #1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Title: Potential TCP Port Scanning Activity
Severity: Medium
Source: 192.168.71.128
Target: 192.168.71.1
Evidence: 19 TCP SYN packets to 19 unique ports
Analysis: Pattern consistent with TCP reconnaissance
Relevance: Port scanning used during reconnaissance phase
```

## Contributing

This is an educational project. Feedback and improvements welcome:

1. **Bug Reports**: Use GitHub Issues
2. **Feature Requests**: Describe use case and expected behavior
3. **Pull Requests**: Fork and submit for review

## Author

**Developed for**: Cybersecurity coursework - Network Analysis & Threat Detection

**Reference Environment**: VMware VMnet1 host-only network with Kali Linux and Windows target

## Disclaimer

**NetSentry** is provided as an educational tool for authorized security assessments in controlled environments only.

- Do not use against systems you don't own or have permission to test
- Port scanning without authorization may be illegal in your jurisdiction
- This tool is not suitable for production security monitoring
- No warranties or guarantees of accuracy are provided
- Users are responsible for all applicable laws and regulations

## License

Educational use permitted. Commercial use requires permission.

---

**Questions? Issues?** Refer to the documentation or consult your security instructor.

**Ready to run:** `python app.py` → http://127.0.0.1:5000
