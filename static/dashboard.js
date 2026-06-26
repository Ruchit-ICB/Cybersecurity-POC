let attackChart;
let currentTimeRange = 30; 

const chartTooltipState = {
    activeIndex: null,
    pinned: false,
    caretX: 0,
    caretY: 0
};

function getOrCreateChartTooltip(chart) {
    let tooltipEl = chart.canvas.parentNode.querySelector('.chart-tooltip');
    if (!tooltipEl) {
        tooltipEl = document.createElement('div');
        tooltipEl.className = 'chart-tooltip';
        chart.canvas.parentNode.appendChild(tooltipEl);

        tooltipEl.addEventListener('mouseenter', () => {
            chartTooltipState.pinned = true;
        });
        tooltipEl.addEventListener('mouseleave', () => {
            setTimeout(() => tryDismissChartTooltip(chart), 120);
        });
    }
    return tooltipEl;
}

function dismissChartTooltip(chart) {
    chartTooltipState.activeIndex = null;
    chartTooltipState.pinned = false;
    const tooltipEl = chart?.canvas?.parentNode?.querySelector('.chart-tooltip');
    if (tooltipEl) {
        tooltipEl.style.opacity = '0';
    }
}

function tryDismissChartTooltip(chart) {
    if (chartTooltipState.pinned) {
        return;
    }
    const tooltipEl = chart.canvas.parentNode.querySelector('.chart-tooltip');
    const overTooltip = tooltipEl && tooltipEl.matches(':hover');
    const overCanvas = chart.canvas.matches(':hover');
    if (!overTooltip && !overCanvas) {
        dismissChartTooltip(chart);
    }
}

function buildChartTooltipHtml(chart, dataIndex, tooltip) {
    const threatDetails = chart.data.datasets[0].threatDetails || [];
    const threats = threatDetails[dataIndex] || [];
    const label = chart.data.labels[dataIndex];
    const count = chart.data.datasets[0].data[dataIndex];

    let html = `<div class="chart-tooltip-header">
        <div class="chart-tooltip-title">${label || 'Unknown time'}</div>
        <button type="button" class="chart-tooltip-close" aria-label="Close">&times;</button>
    </div>`;
    html += `<div class="chart-tooltip-line">Threat Alerts: ${count ?? 0}</div>`;

    if (threats.length > 0) {
        html += '<div class="chart-tooltip-section">Threat Details:</div>';
        threats.forEach(threat => {
            html += `<div class="chart-tooltip-threat">• ${threat.type} (${threat.severity})</div>`;
            html += `<div class="chart-tooltip-meta">Source: ${threat.source_ip}</div>`;
            html += `<div class="chart-tooltip-meta">MITRE: ${threat.mitre || 'N/A'}</div>`;
        });
    } else {
        html += '<div class="chart-tooltip-line" style="margin-top: 8px;">No detailed threat data</div>';
    }

    return html;
}

function renderChartTooltip(chart, dataIndex, tooltip) {
    const tooltipEl = getOrCreateChartTooltip(chart);
    tooltipEl.innerHTML = buildChartTooltipHtml(chart, dataIndex, tooltip);

    const closeBtn = tooltipEl.querySelector('.chart-tooltip-close');
    if (closeBtn) {
        closeBtn.onclick = (event) => {
            event.stopPropagation();
            dismissChartTooltip(chart);
        };
    }

    const { offsetLeft: positionX, offsetTop: positionY } = chart.canvas;
    const caretX = tooltip?.caretX ?? chartTooltipState.caretX;
    const caretY = tooltip?.caretY ?? chartTooltipState.caretY;
    chartTooltipState.caretX = caretX;
    chartTooltipState.caretY = caretY;

    tooltipEl.style.opacity = '1';
    tooltipEl.style.left = positionX + caretX + 'px';
    tooltipEl.style.top = positionY + caretY + 'px';
}

function externalChartTooltip(context) {
    const { chart, tooltip } = context;
    const tooltipEl = getOrCreateChartTooltip(chart);

    if (tooltip.opacity === 1 && tooltip.dataPoints?.length) {
        chartTooltipState.activeIndex = tooltip.dataPoints[0].dataIndex;
        renderChartTooltip(chart, chartTooltipState.activeIndex, tooltip);
        return;
    }

    if (chartTooltipState.activeIndex !== null) {
        renderChartTooltip(chart, chartTooltipState.activeIndex, tooltip);
        return;
    }

    tooltipEl.style.opacity = '0';
}

function setupChartTooltipInteractions(chart) {
    const container = chart.canvas.parentNode;

    chart.options.onClick = (_event, elements) => {
        if (elements.length > 0) {
            chartTooltipState.activeIndex = elements[0].index;
            chartTooltipState.pinned = true;
            const meta = chart.getDatasetMeta(0);
            const point = meta.data[elements[0].index];
            if (point) {
                chartTooltipState.caretX = point.x;
                chartTooltipState.caretY = point.y;
            }
            renderChartTooltip(chart, chartTooltipState.activeIndex, null);
            return;
        }
        dismissChartTooltip(chart);
    };

    container.addEventListener('mouseleave', () => {
        setTimeout(() => tryDismissChartTooltip(chart), 120);
    });
}

function initChart() {
    const ctx = document.getElementById('attackChart').getContext('2d');
    
    
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.font.family = "'Inter', sans-serif";
    
    attackChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Threat Alerts',
                data: [],
                borderColor: '#ef4444',
                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                borderWidth: 2,
                pointBackgroundColor: '#ef4444',
                pointBorderColor: '#fff',
                pointHoverBackgroundColor: '#fff',
                pointHoverBorderColor: '#ef4444',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: '#334155', drawBorder: false },
                    ticks: { precision: 0 }
                },
                x: {
                    grid: { display: false, drawBorder: false }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    enabled: false,
                    external: externalChartTooltip
                }
            }
        }
    });

    setupChartTooltipInteractions(attackChart);
}

async function fetchDashboardData() {
    try {
        const response = await fetch(`/api/dashboard?time_range=${currentTimeRange}`);
        const data = await response.json();
        
        
        document.getElementById('health-cpu').textContent = Math.round(data.system_health.cpu_usage || 0) + '%';
        document.getElementById('health-mem').textContent = Math.round(data.system_health.memory_usage || 0) + '%';
        document.getElementById('health-conn').textContent = data.system_health.active_connections || 0;
        
        
        document.getElementById('predictive-likelihood').textContent = data.predictive_risk?.forecasted_likelihood || 'Low';
        document.getElementById('predictive-category').textContent = data.predictive_risk?.predicted_attack_category || 'Monitoring...';
        

        const timeline = data.attack_timeline || [];
        attackChart.data.labels = timeline.map(t => {
            const d = new Date(t.time);
            return `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
        });
        attackChart.data.datasets[0].data = timeline.map(t => t.count);

        // Store detailed threat data for tooltips
        attackChart.data.datasets[0].threatDetails = timeline.map(t => t.threats || []);

        attackChart.update();

        if (chartTooltipState.activeIndex !== null && chartTooltipState.activeIndex < timeline.length) {
            renderChartTooltip(attackChart, chartTooltipState.activeIndex, null);
        } else if (chartTooltipState.activeIndex !== null) {
            dismissChartTooltip(attackChart);
        }
        
        
        const threatTbody = document.querySelector('#threat-table tbody');
        threatTbody.innerHTML = '';
        const threats = data.live_threats || [];
        
        if (threats.length === 0) {
            threatTbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding:20px;">No active threats detected.</td></tr>';
        } else {
            threats.forEach(t => {
                const tr = document.createElement('tr');
                const aiHtml = t.ai_summary ? `<br><div style="margin-top:8px; padding:8px; background: rgba(16, 185, 129, 0.1); border-left: 3px solid #10b981; border-radius: 4px; color: #cbd5e1; font-size: 0.85em;"><strong>🛡️ ML Threat Analysis:</strong> ${t.ai_summary}</div>` : '';
                tr.innerHTML = `
                    <td style="vertical-align: top;">${new Date(t.timestamp).toLocaleTimeString()}</td>
                    <td style="vertical-align: top;"><strong>${t.type}</strong>${aiHtml}</td>
                    <td style="vertical-align: top;"><span class="badge ${t.severity.toLowerCase()}">${t.severity}</span></td>
                    <td style="vertical-align: top;">${t.source_ip}</td>
                    <td style="vertical-align: top;"><span style="color:#64748b; font-family:monospace;">${t.mitre || 'N/A'}</span></td>
                `;
                threatTbody.appendChild(tr);
            });
        }
        
        
        const vulnTbody = document.querySelector('#vuln-table tbody');
        vulnTbody.innerHTML = '';
        const vulns = data.vulnerability_summary?.findings || [];
        
        if (vulns.length === 0) {
            vulnTbody.innerHTML = '<tr><td colspan="3" style="text-align:center; padding:20px;">No vulnerabilities found.</td></tr>';
        } else {
            vulns.forEach(v => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td style="font-family:monospace; color:#3b82f6;">${v.cve_id || 'N/A'}</td>
                    <td>${v.title}</td>
                    <td><span class="badge ${v.severity.toLowerCase()}">${v.severity}</span></td>
                `;
                vulnTbody.appendChild(tr);
            });
        }
        
    } catch (e) {
        console.error("Failed to fetch dashboard data", e);
    }
}


function setTimeRange(minutes) {
    currentTimeRange = minutes;

    // Update button states
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.remove('active');
        if (parseInt(btn.dataset.range) === minutes) {
            btn.classList.add('active');
        }
    });

    // Fetch new data with the updated time range
    fetchDashboardData();
}


async function runManualScan() {
    const logText = document.getElementById('log-input').value.trim();
    if (!logText) return;
    
    const btn = document.getElementById('btn-scan');
    btn.textContent = 'Scanning...';
    btn.disabled = true;
    
    document.getElementById('scan-results').style.display = 'block';
    document.getElementById('ai-prob').textContent = 'Analyzing...';
    document.getElementById('ai-prob').style.color = '#cbd5e1';
    document.getElementById('ai-reason').textContent = 'Analyzing log patterns...';
    document.getElementById('scan-raw-output').textContent = 'Running ML models...';
    
    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ log_text: logText })
        });
        const data = await response.json();
        
        if (data.llama_analysis) {
            const prob = data.llama_analysis.probability;
            document.getElementById('ai-prob').textContent = prob + '%';
            document.getElementById('ai-reason').textContent = data.llama_analysis.reason;
            
            let probColor = '#10b981';
            if (prob > 75) probColor = '#ef4444';
            else if (prob > 40) probColor = '#f59e0b';
            document.getElementById('ai-prob').style.color = probColor;
        }

        const incidentsContainer = document.getElementById('scan-incidents-container');
        incidentsContainer.innerHTML = '';
        const detections = data.detections || [];
        
        if (detections.length === 0) {
            incidentsContainer.innerHTML = `
                <div class="card incident-card" style="padding: 16px; background: rgba(16, 185, 129, 0.05); border-left: 4px solid #10b981; border-radius: 8px; border: 1px solid var(--border-color);">
                    <h4 style="margin: 0; color: #10b981; font-size: 1rem;">🛡️ No Threats Detected</h4>
                    <p style="margin: 8px 0 0 0; font-size: 0.85rem; color: #94a3b8;">The log entries do not match any known attack signatures or anomaly thresholds.</p>
                </div>
            `;
        } else {
            detections.forEach(d => {
                const severity = (d.severity || 'medium').toLowerCase();
                let severityColor = '#3b82f6';
                if (severity === 'critical') severityColor = '#ef4444';
                else if (severity === 'high') severityColor = '#f59e0b';
                else if (severity === 'medium') severityColor = '#eab308';
                
                const cveHtml = d.cve_id && d.cve_id !== 'N/A' ? ` | <span>CVE ID: <strong>${d.cve_id}</strong></span>` : '';
                const card = document.createElement('div');
                card.className = 'card incident-card';
                card.style.cssText = `border-left: 4px solid ${severityColor}; padding: 16px; background: rgba(30, 41, 59, 0.4); border-radius: 8px; border: 1px solid var(--border-color); margin-bottom: 12px;`;
                card.innerHTML = `
                    <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 12px;">
                        <div>
                            <h4 style="margin: 0; font-size: 1.1rem; color: #f8fafc;">Threat: ${d.threat_type}</h4>
                            <div style="margin-top: 4px; font-size: 0.85rem; color: #94a3b8;">
                                <span>MITRE ATT&CK: <strong>${d.mitre_tactics ? d.mitre_tactics.join(', ') : 'N/A'}</strong></span>${cveHtml}
                            </div>
                        </div>
                        <div style="display: flex; gap: 8px;">
                            <span class="badge ${severity}">${severity.toUpperCase()}</span>
                            <span class="badge info" style="background: rgba(16, 185, 129, 0.1); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.2);">Confidence: ${(d.confidence * 100).toFixed(1)}%</span>
                        </div>
                    </div>
                    <div style="font-size: 0.9rem; color: #cbd5e1; margin-bottom: 12px;">
                        <strong>Explanation:</strong> ${d.explanation || d.raw_message}
                    </div>
                    <div style="padding: 12px; background: rgba(15, 23, 42, 0.5); border-radius: 6px; font-size: 0.85rem; border: 1px solid rgba(51, 65, 85, 0.3);">
                        <div style="color: #f87171; margin-bottom: 6px;"><strong>Potential Impact:</strong> ${d.impact || 'N/A'}</div>
                        <div style="color: #34d399;"><strong>Recommended Mitigation:</strong> ${d.mitigation || 'N/A'}</div>
                    </div>
                `;
                incidentsContainer.appendChild(card);
            });
        }
        
        document.getElementById('scan-raw-output').textContent = JSON.stringify(data, null, 2);
        
    } catch (e) {
        console.error("Scan failed", e);
        document.getElementById('ai-reason').textContent = "Failed to communicate with server.";
    } finally {
        btn.textContent = 'Scan with ML Engine';
        btn.disabled = false;
    }
}

async function runCodeUploadAnalysis() {
    const fileInput = document.getElementById('code-file-input');
    const file = fileInput?.files?.[0];
    if (!file) {
        return;
    }

    const btn = document.getElementById('btn-code-scan');
    btn.textContent = 'Analyzing...';
    btn.disabled = true;

    const resultsEl = document.getElementById('code-scan-results');
    const tbody = document.querySelector('#code-scan-table tbody');
    tbody.innerHTML = '';

    const formData = new FormData();
    formData.append('code_file', file);

    try {
        const response = await fetch('/api/upload-code', {
            method: 'POST',
            body: formData
        });
        const data = await response.json();

        if (response.ok) {
            document.getElementById('code-bug-count').textContent = data.summary.bugs;
            document.getElementById('code-vuln-count').textContent = data.summary.vulnerabilities;
            document.getElementById('code-maintain-count').textContent = data.summary.maintainability_issues;

            data.issues.forEach(issue => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${issue.line}</td>
                    <td>${issue.category}</td>
                    <td>${issue.severity}</td>
                    <td>${issue.description}</td>
                `;
                tbody.appendChild(tr);
            });
            resultsEl.style.display = 'block';
        } else {
            tbody.innerHTML = `<tr><td colspan="4" style="text-align:center; padding:20px; color:#f87171;">${data.error || 'Failed to analyze code.'}</td></tr>`;
            resultsEl.style.display = 'block';
        }
    } catch (e) {
        console.error('Code analysis failed', e);
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:20px; color:#f87171;">Code analysis request failed.</td></tr>';
        resultsEl.style.display = 'block';
    } finally {
        btn.textContent = 'Analyze Code';
        btn.disabled = false;
    }
}


document.addEventListener('DOMContentLoaded', () => {
    initChart();
    fetchDashboardData();
    setInterval(fetchDashboardData, 3000);
});
