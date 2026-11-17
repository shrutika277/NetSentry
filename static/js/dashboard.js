// NetSentry Dashboard JavaScript

let charts = {};
let analysisState = {};

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    setupFileUploadHandlers();
    loadInitialState();
});

// Setup file upload handlers
function setupFileUploadHandlers() {
    const nmapInput = document.getElementById('nmap-input');
    const pcapInput = document.getElementById('pcap-input');
    
    if (nmapInput) {
        nmapInput.addEventListener('change', function(e) {
            handleFileUpload(e.target.files[0], 'nmap');
        });
    }
    
    if (pcapInput) {
        pcapInput.addEventListener('change', function(e) {
            handleFileUpload(e.target.files[0], 'pcap');
        });
    }
}

// Handle file upload
function handleFileUpload(file, type) {
    if (!file) return;
    
    const formData = new FormData();
    formData.append('file', file);
    formData.append('type', type);
    
    showLoading(`Uploading ${type.toUpperCase()} file...`);
    
    fetch('/api/upload', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            showAlert(`Error: ${data.error}`, 'danger');
        } else {
            showAlert(`${type.toUpperCase()} file processed successfully!`, 'success');
            loadAnalysisState();
        }
    })
    .catch(error => {
        showAlert(`Upload failed: ${error}`, 'danger');
    });
}

// Load analysis state from server
function loadAnalysisState() {
    fetch('/api/state')
        .then(response => response.json())
        .then(data => {
            analysisState = data;
            updateDashboard();
        })
        .catch(error => console.error('Error loading state:', error));
}

// Load initial state (includes sample data)
function loadInitialState() {
    loadAnalysisState();
}

// Update entire dashboard
function updateDashboard() {
    updateMetrics();
    updateDetectionAlert();
    updateCharts();
    updateAnalysisSections();
    updateFindings();
    updateRecommendations();
    updateEvidenceSummary();
}

// Update metric cards
function updateMetrics() {
    const nmap = analysisState.nmap_data || {};
    const pcap = analysisState.pcap_data || {};
    const risk = analysisState.risk_score || {};
    
    updateMetric('metric-ports', nmap.statistics?.total_scanned || 0);
    updateMetric('metric-open', nmap.statistics?.open || 0);
    updateMetric('metric-filtered', nmap.statistics?.filtered || 0);
    updateMetric('metric-syn', pcap.syn_packets || 0);
    updateMetric('metric-unique-ports', pcap.unique_dest_ports_count || 0);
    
    const riskElement = document.getElementById('metric-risk');
    if (riskElement) {
        if (risk.overall_score !== undefined) {
            riskElement.textContent = `${risk.overall_score}/${risk.risk_level || 'Unknown'}`;
            riskElement.style.color = getRiskColor(risk.overall_score);
        } else {
            riskElement.textContent = '--';
        }
    }
}

function updateMetric(elementId, value) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = value;
    }
}

function getRiskColor(score) {
    if (score >= 80) return '#ff6b6b';      // Critical - red
    if (score >= 60) return '#ffd43b';      // High - orange
    if (score >= 40) return '#ffa94d';      // Medium - amber
    return '#51cf66';                        // Low - green
}

// Update detection alert
function updateDetectionAlert() {
    const detection = analysisState.detection_result;
    const alertContainer = document.getElementById('detection-alert');
    
    if (!alertContainer) return;
    
    if (!detection) {
        alertContainer.innerHTML = `
            <div class="alert-box alert-info">
                <div class="alert-icon">ℹ️</div>
                <div class="alert-content">
                    <h3>Analysis Status</h3>
                    <p>Upload evidence files to begin analysis and detection.</p>
                </div>
            </div>
        `;
        return;
    }
    
    if (!detection.detected) {
        alertContainer.innerHTML = `
            <div class="alert-box alert-info">
                <div class="alert-icon">✓</div>
                <div class="alert-content">
                    <h3>No Significant Reconnaissance Pattern Detected</h3>
                    <p>Current evidence does not meet detection thresholds for TCP port scanning activity.</p>
                </div>
            </div>
        `;
    } else {
        const severityClass = detection.severity.toLowerCase().includes('high') ? 'danger' : 'warning';
        const icon = detection.severity.includes('Critical') ? '⚠️' : '⚡';
        
        alertContainer.innerHTML = `
            <div class="alert-box alert-${severityClass}">
                <div class="alert-icon">${icon}</div>
                <div class="alert-content">
                    <h3>⚠️ Potential TCP Port Scanning Detected</h3>
                    <p><strong>Severity:</strong> ${detection.severity}</p>
                    <p><strong>Confidence:</strong> ${detection.confidence}%</p>
                    <p>${detection.analysis}</p>
                </div>
            </div>
        `;
    }
}

// Update charts
function updateCharts() {
    updatePortChart();
    updateRiskChart();
}

function updatePortChart() {
    const pcap = analysisState.pcap_data || {};
    const ctx = document.getElementById('portChart');
    
    if (!ctx) return;
    
    const portDist = pcap.port_distribution || {};
    const ports = Object.keys(portDist).slice(0, 15).map(p => `Port ${p}`);
    const counts = Object.values(portDist).slice(0, 15);
    
    // Destroy previous chart if exists
    if (charts.portChart) {
        charts.portChart.destroy();
    }
    
    charts.portChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ports,
            datasets: [{
                label: 'SYN Probes',
                data: counts,
                backgroundColor: 'rgba(0, 212, 255, 0.6)',
                borderColor: 'rgba(0, 212, 255, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    labels: { color: '#e0e0e0' }
                }
            },
            scales: {
                y: {
                    ticks: { color: '#a0a0a0' },
                    grid: { color: '#2d3748' }
                },
                x: {
                    ticks: { color: '#a0a0a0' },
                    grid: { color: '#2d3748' }
                }
            }
        }
    });
}

function updateRiskChart() {
    const risk = analysisState.risk_score || {};
    const ctx = document.getElementById('riskChart');
    
    if (!ctx || !risk.factors) return;
    
    const factors = risk.factors;
    const labels = [];
    const scores = [];
    
    for (const [key, value] of Object.entries(factors)) {
        labels.push(value.weight ? `${key} (${value.weight}%)` : key);
        scores.push(value.score || 0);
    }
    
    // Destroy previous chart if exists
    if (charts.riskChart) {
        charts.riskChart.destroy();
    }
    
    charts.riskChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: scores,
                backgroundColor: [
                    'rgba(0, 212, 255, 0.8)',
                    'rgba(255, 107, 107, 0.8)',
                    'rgba(255, 212, 59, 0.8)',
                    'rgba(81, 207, 102, 0.8)',
                    'rgba(147, 112, 219, 0.8)'
                ],
                borderColor: '#1a1e2e',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    labels: { color: '#e0e0e0' }
                }
            }
        }
    });
}

// Update analysis sections
function updateAnalysisSections() {
    updateNmapAnalysis();
    updatePcapAnalysis();
    updateCorrelationAnalysis();
}

function updateNmapAnalysis() {
    const nmap = analysisState.nmap_data;
    const container = document.getElementById('nmap-analysis');
    
    if (!nmap) {
        if (container) container.innerHTML = '<p class="placeholder">No Nmap data loaded.</p>';
        return;
    }
    
    let html = '<table>';
    html += '<tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Version</th></tr>';
    
    for (const port of nmap.ports.slice(0, 20)) {
        const stateClass = port.state === 'open' ? 'open' : port.state === 'filtered' ? 'filtered' : 'closed';
        html += `<tr>
            <td>${port.port}</td>
            <td>${port.protocol}</td>
            <td><span class="state-${stateClass}">${port.state}</span></td>
            <td>${port.service || 'N/A'}</td>
            <td>${port.version || 'N/A'}</td>
        </tr>`;
    }
    
    html += '</table>';
    html += `<p style="margin-top: 1rem; color: #a0a0a0;">
        Host Status: <strong>${nmap.host_state}</strong><br/>
        Total Ports Scanned: <strong>${nmap.statistics.total_scanned}</strong>
    </p>`;
    
    if (container) container.innerHTML = html;
}

function updatePcapAnalysis() {
    const pcap = analysisState.pcap_data;
    const container = document.getElementById('pcap-analysis');
    
    if (!pcap) {
        if (container) container.innerHTML = '<p class="placeholder">No PCAP data loaded.</p>';
        return;
    }
    
    let html = `<table>
        <tr><td><strong>Total Packets:</strong></td><td>${pcap.total_packets}</td></tr>
        <tr><td><strong>TCP Packets:</strong></td><td>${pcap.tcp_packets}</td></tr>
        <tr><td><strong>SYN Packets:</strong></td><td>${pcap.syn_packets}</td></tr>
        <tr><td><strong>Source IP:</strong></td><td><code>${pcap.source_ip}</code></td></tr>
        <tr><td><strong>Destination IP:</strong></td><td><code>${pcap.dest_ip}</code></td></tr>
        <tr><td><strong>Unique Destination Ports:</strong></td><td>${pcap.unique_dest_ports_count}</td></tr>
    </table>`;
    
    if (pcap.unique_dest_ports && pcap.unique_dest_ports.length > 0) {
        html += `<p style="margin-top: 1rem;"><strong>Ports Probed:</strong> ${pcap.unique_dest_ports.slice(0, 20).join(', ')}${pcap.unique_dest_ports.length > 20 ? '...' : ''}</p>`;
    }
    
    if (container) container.innerHTML = html;
}

function updateCorrelationAnalysis() {
    const container = document.getElementById('correlation-analysis');
    
    if (!analysisState.nmap_data || !analysisState.pcap_data) {
        if (container) container.innerHTML = '<p class="placeholder">Upload both Nmap and PCAP evidence to see correlation analysis.</p>';
        return;
    }
    
    fetch('/api/correlation')
        .then(response => response.json())
        .then(data => {
            if (data.correlation && container) {
                const corr = data.correlation;
                let html = `
                    <table>
                        <tr><td colspan="2"><strong>Nmap Summary</strong></td></tr>
                        <tr><td>Target:</td><td><code>${corr.nmap_summary.target}</code></td></tr>
                        <tr><td>Host State:</td><td>${corr.nmap_summary.host_state}</td></tr>
                        <tr><td>Total Ports Scanned:</td><td>${corr.nmap_summary.total_ports_scanned}</td></tr>
                        <tr><td>Open Ports:</td><td>${corr.nmap_summary.open_ports}</td></tr>
                        <tr><td>Filtered Ports:</td><td>${corr.nmap_summary.filtered_ports}</td></tr>
                        <tr><td colspan="2"><strong>PCAP Summary</strong></td></tr>
                        <tr><td>Source IP:</td><td><code>${corr.pcap_summary.source}</code></td></tr>
                        <tr><td>Destination IP:</td><td><code>${corr.pcap_summary.destination}</code></td></tr>
                        <tr><td>Total Packets:</td><td>${corr.pcap_summary.total_packets}</td></tr>
                        <tr><td>SYN Packets:</td><td>${corr.pcap_summary.syn_packets}</td></tr>
                        <tr><td>Unique Destination Ports:</td><td>${corr.pcap_summary.unique_dest_ports}</td></tr>
                    </table>
                    <p style="margin-top: 1rem; color: #a0a0a0;">
                        <strong>Analysis:</strong> ${corr.correlation_analysis}
                    </p>
                    <p style="color: #51cf66; margin-top: 0.5rem;">
                        <strong>Interpretation:</strong> ${corr.interpretation}
                    </p>
                `;
                container.innerHTML = html;
            }
        })
        .catch(error => console.error('Error loading correlation:', error));
}

// Update findings
function updateFindings() {
    const container = document.getElementById('findings-list');
    
    if (!container) return;
    
    fetch('/api/findings')
        .then(response => response.json())
        .then(data => {
            const findings = data.findings || [];
            
            if (findings.length === 0) {
                container.innerHTML = '<p class="placeholder">No findings at this time.</p>';
                return;
            }
            
            let html = '';
            for (const finding of findings) {
                const severityClass = `severity-${finding.severity.toLowerCase().replace('-', '')}`;
                html += `
                    <div class="finding-card">
                        <h3>${finding.title}</h3>
                        <span class="severity ${severityClass}">${finding.severity}</span>
                        <p><strong>Source:</strong> ${finding.source}</p>
                        <p><strong>Target:</strong> ${finding.target}</p>
                        <p><strong>Evidence:</strong> ${finding.evidence}</p>
                        <p style="color: #51cf66;"><strong>Analysis:</strong> ${finding.analysis}</p>
                        <p><strong>Security Relevance:</strong> ${finding.relevance}</p>
                    </div>
                `;
            }
            
            container.innerHTML = html;
        })
        .catch(error => console.error('Error loading findings:', error));
}

// Update recommendations
function updateRecommendations() {
    const container = document.getElementById('recommendations-list');
    
    if (!container) return;
    
    fetch('/api/recommendations')
        .then(response => response.json())
        .then(data => {
            const recommendations = data.recommendations || [];
            
            let html = '';
            for (const rec of recommendations) {
                const priorityClass = `priority-${rec.priority.toLowerCase()}`;
                html += `
                    <div class="recommendation-card">
                        <span class="priority ${priorityClass}">${rec.priority}</span>
                        <h4>${rec.title}</h4>
                        <p>${rec.description}</p>
                        <p style="color: #a0a0a0; font-size: 0.9rem;"><strong>Type:</strong> ${rec.control_type}</p>
                    </div>
                `;
            }
            
            container.innerHTML = html;
        })
        .catch(error => console.error('Error loading recommendations:', error));
}

// Update evidence summary
function updateEvidenceSummary() {
    const nmap = analysisState.nmap_file || '--';
    const pcap = analysisState.pcap_file || '--';
    const detection = analysisState.detection_result?.detected ? 'Detected' : 'Not detected';
    const time = analysisState.analysis_time ? new Date(analysisState.analysis_time).toLocaleString() : '--';
    
    const timeEl = document.getElementById('evidence-time');
    const nmapEl = document.getElementById('evidence-nmap');
    const pcapEl = document.getElementById('evidence-pcap');
    const detectionEl = document.getElementById('evidence-detection');
    
    if (timeEl) timeEl.textContent = time;
    if (nmapEl) nmapEl.textContent = nmap;
    if (pcapEl) pcapEl.textContent = pcap;
    if (detectionEl) detectionEl.textContent = detection;
}

// Utility functions
function showAlert(message, type = 'info') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert-box alert-${type}`;
    alertDiv.innerHTML = `
        <div class="alert-icon">${type === 'success' ? '✓' : type === 'danger' ? '✕' : 'ℹ️'}</div>
        <div class="alert-content">
            <p>${message}</p>
        </div>
    `;
    
    const container = document.querySelector('.dashboard') || document.querySelector('.container');
    if (container) {
        container.insertBefore(alertDiv, container.firstChild);
        
        setTimeout(() => {
            alertDiv.remove();
        }, 5000);
    }
}

function showLoading(message) {
    showAlert(`<span class="loading"></span> ${message}`, 'info');
}
