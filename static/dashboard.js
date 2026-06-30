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
    document.getElementById('scan-status-bar').innerHTML = '<div style="grid-column:span 3;color:#94a3b8;font-size:0.9rem;padding:12px 0;">Analyzing log patterns...</div>';
    document.getElementById('scan-incidents-container').innerHTML = '';
    document.getElementById('scan-raw-output').textContent = 'Running ML models...';
    
    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ log_text: logText })
        });
        const data = await response.json();
        
        const detections = data.detections || [];
        const conditions = data.conditions || [];

        // ── Status bar ─────────────────────────────────────────────────────────
        const securityStatus = detections.length > 0
            ? (detections.some(d => (d.threat_status||'').toUpperCase() === 'CONFIRMED') ? 'CONFIRMED' : 'SUSPICIOUS')
            : 'NORMAL';
        const networkStatus = conditions.length > 0 ? 'DEGRADED' : 'NORMAL';
        const serviceStatus = detections.some(d => ['critical','high'].includes((d.severity||'').toLowerCase())) ? 'IMPACTED' : 'OPERATIONAL';

        const statusColors = {
            CONFIRMED:   { bg: 'rgba(239,68,68,0.12)',   border: '#ef4444', text: '#f87171' },
            SUSPICIOUS:  { bg: 'rgba(245,158,11,0.12)',  border: '#f59e0b', text: '#fbbf24' },
            NORMAL:      { bg: 'rgba(16,185,129,0.10)',  border: '#10b981', text: '#34d399' },
            DEGRADED:    { bg: 'rgba(59,130,246,0.12)',  border: '#3b82f6', text: '#60a5fa' },
            OPERATIONAL: { bg: 'rgba(16,185,129,0.10)',  border: '#10b981', text: '#34d399' },
            IMPACTED:    { bg: 'rgba(239,68,68,0.12)',   border: '#ef4444', text: '#f87171' },
        };

        function statusPill(label, value) {
            const c = statusColors[value] || statusColors.NORMAL;
            return `<div style="background:${c.bg}; border:1px solid ${c.border}; border-radius:8px; padding:14px 16px;">
                <div style="font-size:0.72rem; text-transform:uppercase; letter-spacing:0.08em; color:#64748b; margin-bottom:4px;">${label}</div>
                <div style="font-size:1rem; font-weight:700; color:${c.text};">${value}</div>
            </div>`;
        }

        document.getElementById('scan-status-bar').innerHTML =
            statusPill('Security Status', securityStatus) +
            statusPill('Network Status', networkStatus) +
            statusPill('Service Status', serviceStatus);

        // ── Incident cards ─────────────────────────────────────────────────────
        const incidentsContainer = document.getElementById('scan-incidents-container');
        incidentsContainer.innerHTML = '';

        if (detections.length === 0 && conditions.length === 0) {
            incidentsContainer.innerHTML = `
                <div style="padding:20px 24px; background:rgba(16,185,129,0.05); border-left:4px solid #10b981; border-radius:8px; border:1px solid var(--border-color);">
                    <div style="font-weight:600; color:#10b981; margin-bottom:4px;">🛡️ No Threats Detected</div>
                    <div style="font-size:0.85rem; color:#94a3b8;">The ISP log entries do not match any known attack signatures or anomaly thresholds.</div>
                </div>`;
        }

        // Security threat cards
        detections.forEach(d => {
            const status    = (d.threat_status || 'CONFIRMED').toUpperCase();
            const severity  = (d.severity || 'medium').toLowerCase();
            const conf      = Math.round((d.confidence || 0) * 100);
            const mitre     = d.mitre_tactics?.join(', ') || 'N/A';
            const cve       = d.cve_id && d.cve_id !== 'N/A' ? `<span style="font-size:0.8rem;color:#64748b;">CVE: <strong style="color:#94a3b8;">${d.cve_id}</strong></span>` : '';

            const sevColor  = { critical:'#ef4444', high:'#f59e0b', medium:'#eab308', low:'#3b82f6' }[severity] || '#3b82f6';
            const statColor = status === 'CONFIRMED' ? '#10b981' : status === 'SUSPICIOUS' ? '#f59e0b' : '#60a5fa';
            const confColor = conf >= 85 ? '#ef4444' : conf >= 70 ? '#f59e0b' : '#60a5fa';

            const evidenceHtml = Array.isArray(d.evidence) && d.evidence.length
                ? d.evidence.map(e => `<li style="margin:2px 0;">${e}</li>`).join('')
                : '';

            const card = document.createElement('div');
            card.style.cssText = `border-left:4px solid ${sevColor}; padding:20px 24px; background:rgba(15,23,42,0.6); border-radius:8px; border:1px solid var(--border-color); margin-bottom:4px; font-size:0.88rem;`;
            card.innerHTML = `
                <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:16px; flex-wrap:wrap; gap:8px;">
                    <div>
                        <div style="display:flex; align-items:center; gap:8px; margin-bottom:4px;">
                            <span style="font-size:0.7rem; font-weight:700; text-transform:uppercase; letter-spacing:0.1em; background:rgba(239,68,68,0.15); color:#f87171; padding:2px 8px; border-radius:3px; border:1px solid rgba(239,68,68,0.3);">SECURITY_STATUS</span>
                            <span style="font-weight:700; color:${statColor}; font-size:0.95rem;">${status}</span>
                        </div>
                        <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
                            <span style="font-size:0.7rem; font-weight:700; text-transform:uppercase; letter-spacing:0.1em; background:rgba(16,185,129,0.1); color:#34d399; padding:2px 8px; border-radius:3px; border:1px solid rgba(16,185,129,0.2);">NETWORK_STATUS</span>
                            <span style="font-weight:600; color:#34d399; font-size:0.9rem;">${networkStatus}</span>
                            <span style="font-size:0.7rem; font-weight:700; text-transform:uppercase; letter-spacing:0.1em; background:rgba(16,185,129,0.1); color:#34d399; padding:2px 8px; border-radius:3px; border:1px solid rgba(16,185,129,0.2);">SERVICE_STATUS</span>
                            <span style="font-weight:600; color:${serviceStatus === 'OPERATIONAL' ? '#34d399' : '#f87171'}; font-size:0.9rem;">${serviceStatus}</span>
                        </div>
                    </div>
                    <div style="display:flex; gap:6px; flex-wrap:wrap; justify-content:flex-end;">
                        <span class="badge ${severity}">${severity.toUpperCase()}</span>
                    </div>
                </div>

                <div style="border-top:1px solid rgba(51,65,85,0.5); padding-top:14px;">
                    <div style="margin-bottom:10px;">
                        <span style="color:#64748b; font-size:0.75rem; text-transform:uppercase; letter-spacing:0.06em;">Threat</span>
                        <div style="font-size:1.05rem; font-weight:700; color:#f8fafc; margin-top:2px;">${d.threat_type}</div>
                    </div>
                    <div style="display:flex; gap:24px; flex-wrap:wrap; margin-bottom:14px;">
                        <div>
                            <span style="color:#64748b; font-size:0.75rem; text-transform:uppercase; letter-spacing:0.06em;">MITRE ATT&amp;CK</span>
                            <div style="font-family:monospace; color:#60a5fa; margin-top:2px;">${mitre}</div>
                        </div>
                        <div>
                            <span style="color:#64748b; font-size:0.75rem; text-transform:uppercase; letter-spacing:0.06em;">Confidence</span>
                            <div style="font-weight:700; color:${confColor}; font-size:1.1rem; margin-top:2px;">${conf}%</div>
                        </div>
                        ${cve ? `<div>${cve}</div>` : ''}
                    </div>

                    <div style="margin-bottom:10px;">
                        <div style="color:#64748b; font-size:0.75rem; text-transform:uppercase; letter-spacing:0.06em; margin-bottom:4px;">Explanation</div>
                        <div style="color:#cbd5e1; line-height:1.6;">${d.explanation || d.raw_message}</div>
                    </div>

                    ${evidenceHtml ? `<div style="margin-bottom:10px; padding:10px 12px; background:rgba(15,23,42,0.5); border-radius:5px; border:1px solid rgba(51,65,85,0.4);">
                        <div style="color:#64748b; font-size:0.72rem; text-transform:uppercase; letter-spacing:0.06em; margin-bottom:5px;">Evidence Fired</div>
                        <ul style="margin:0; padding-left:16px; color:#94a3b8; line-height:1.7;">${evidenceHtml}</ul>
                    </div>` : ''}

                    <div style="padding:12px 14px; background:rgba(15,23,42,0.5); border-radius:6px; border:1px solid rgba(51,65,85,0.3);">
                        <div style="margin-bottom:8px;">
                            <span style="color:#64748b; font-size:0.75rem; text-transform:uppercase; letter-spacing:0.06em;">Potential Impact</span>
                            <div style="color:#f87171; margin-top:3px; line-height:1.5;">${d.impact || 'N/A'}</div>
                        </div>
                        <div>
                            <span style="color:#64748b; font-size:0.75rem; text-transform:uppercase; letter-spacing:0.06em;">Recommended Mitigation</span>
                            <div style="color:#34d399; margin-top:3px; line-height:1.5;">${d.mitigation || 'N/A'}</div>
                        </div>
                    </div>
                </div>
            `;
            incidentsContainer.appendChild(card);
        });

        // Network condition cards
        if (conditions.length > 0) {
            const hdr = document.createElement('div');
            hdr.style.cssText = 'margin:20px 0 12px; padding-bottom:8px; border-bottom:1px solid var(--border-color);';
            hdr.innerHTML = `<span style="color:#60a5fa; font-size:0.9rem; font-weight:600;">🔵 Network Conditions / Monitor (${conditions.length})</span>`;
            incidentsContainer.appendChild(hdr);

            conditions.forEach(c => {
                const sev = (c.severity || 'low').toLowerCase();
                const card = document.createElement('div');
                card.style.cssText = 'border-left:4px solid #3b82f6; padding:14px 18px; background:rgba(30,41,59,0.2); border-radius:8px; border:1px solid var(--border-color); margin-bottom:6px; font-size:0.85rem;';
                card.innerHTML = `
                    <div style="display:flex; justify-content:space-between; align-items:center; gap:8px;">
                        <div style="flex:1;">
                            <div style="display:flex; align-items:center; gap:8px; margin-bottom:3px;">
                                <span style="font-weight:600; color:#cbd5e1;">${c.threat_type}</span>
                                <span style="background:rgba(59,130,246,0.15); color:#60a5fa; border:1px solid rgba(59,130,246,0.3); padding:1px 6px; border-radius:3px; font-size:0.7rem; font-weight:600;">MONITOR</span>
                            </div>
                            <div style="color:#94a3b8; line-height:1.5;">${c.explanation || c.raw_message || ''}</div>
                        </div>
                        <span class="badge ${sev}" style="flex-shrink:0;">${sev.toUpperCase()}</span>
                    </div>`;
                incidentsContainer.appendChild(card);
            });
        }

        document.getElementById('scan-raw-output').textContent = JSON.stringify(data, null, 2);

        // Show debug summary at top of raw output
        const dbg = data.debug || {};
        const debugSummary = `// API returned: detections=${data.detections?.length ?? 0}  conditions=${data.conditions?.length ?? 0}  lines_parsed=${dbg.lines_parsed ?? '?'}  first_fmt=${dbg.first_fmt ?? '?'}  all_detections_raw=${dbg.all_detections_raw ?? '?'}  probability=${data.llama_analysis?.probability ?? '?'}%\n\n`;
        document.getElementById('scan-raw-output').textContent = debugSummary + JSON.stringify(data, null, 2);
        
    } catch (e) {
        console.error("Scan failed", e);
        document.getElementById('scan-status-bar').innerHTML = '<div style="color:#f87171;grid-column:span 3;">Failed to communicate with server.</div>';
    } finally {
        btn.textContent = 'Scan with ML Engine';
        btn.disabled = false;
    }
}

function loadLogFile(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    const nameEl = document.getElementById('log-file-name');
    nameEl.textContent = file.name;
    const reader = new FileReader();
    reader.onload = e => {
        document.getElementById('log-input').value = e.target.result;
    };
    reader.readAsText(file);
    // Reset input so the same file can be re-attached
    event.target.value = '';
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
