let attackChart;

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
                    backgroundColor: '#1e293b',
                    titleColor: '#f8fafc',
                    bodyColor: '#cbd5e1',
                    borderColor: '#334155',
                    borderWidth: 1
                }
            }
        }
    });
}

async function fetchDashboardData() {
    try {
        const response = await fetch('/api/dashboard');
        const data = await response.json();
        
        
        const riskScore = data.vulnerability_summary?.overall_risk_score || 0;
        const riskEl = document.getElementById('overall-risk-score');
        riskEl.textContent = riskScore;
        
        
        let riskColor = '#10b981'; // Green
        if (riskScore > 80) riskColor = '#ef4444'; // Red
        else if (riskScore > 40) riskColor = '#f59e0b'; // Yellow
        riskEl.style.borderColor = riskColor;
        riskEl.style.color = riskColor;
        
        
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
        attackChart.update();
        
        
        const threatTbody = document.querySelector('#threat-table tbody');
        threatTbody.innerHTML = '';
        const threats = data.live_threats || [];
        
        if (threats.length === 0) {
            threatTbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding:20px;">No active threats detected.</td></tr>';
        } else {
            threats.forEach(t => {
                const tr = document.createElement('tr');
                const geminiHtml = t.gemini_summary ? `<br><div style="margin-top:8px; padding:8px; background: rgba(59, 130, 246, 0.1); border-left: 3px solid #3b82f6; border-radius: 4px; color: #cbd5e1; font-size: 0.85em;"><strong>✨ Gemini AI Analysis:</strong> ${t.gemini_summary}</div>` : '';
                tr.innerHTML = `
                    <td style="vertical-align: top;">${new Date(t.timestamp).toLocaleTimeString()}</td>
                    <td style="vertical-align: top;"><strong>${t.type}</strong>${geminiHtml}</td>
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

async function toggleIngestion(action) {
    try {
        await fetch(`/api/${action}-ingestion`, { method: 'POST' });
        const startBtn = document.getElementById('btn-start');
        const stopBtn = document.getElementById('btn-stop');
        
        if (action === 'start') {
            startBtn.classList.add('active');
            stopBtn.classList.remove('active');
        } else {
            startBtn.classList.remove('active');
            stopBtn.classList.add('active');
        }
    } catch (e) {
        console.error("Failed to toggle ingestion", e);
    }
}


document.querySelectorAll('#sidebar-nav a').forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        
        document.querySelectorAll('#sidebar-nav li').forEach(li => li.classList.remove('active'));
        e.target.parentElement.classList.add('active');
        
        document.querySelectorAll('.tab-content').forEach(tab => tab.style.display = 'none');
        
        const targetId = e.target.getAttribute('data-target');
        if(targetId) document.getElementById(targetId).style.display = 'block';
    });
});


async function runManualScan() {
    const logText = document.getElementById('log-input').value.trim();
    if (!logText) return;
    
    const btn = document.getElementById('btn-scan');
    btn.textContent = 'Scanning...';
    btn.disabled = true;
    
    document.getElementById('scan-results').style.display = 'block';
    document.getElementById('gemini-prob').textContent = 'Analyzing...';
    document.getElementById('gemini-prob').style.color = '#cbd5e1';
    document.getElementById('gemini-reason').textContent = 'Sending data to Gemini AI...';
    document.getElementById('scan-raw-output').textContent = 'Running ML models...';
    
    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ log_text: logText })
        });
        const data = await response.json();
        
        if (data.gemini_analysis) {
            const prob = data.gemini_analysis.probability;
            document.getElementById('gemini-prob').textContent = prob + '%';
            document.getElementById('gemini-reason').textContent = data.gemini_analysis.reason;
            
            let probColor = '#10b981';
            if (prob > 75) probColor = '#ef4444';
            else if (prob > 40) probColor = '#f59e0b';
            document.getElementById('gemini-prob').style.color = probColor;
        }
        
        document.getElementById('scan-raw-output').textContent = JSON.stringify(data, null, 2);
        
    } catch (e) {
        console.error("Scan failed", e);
        document.getElementById('gemini-reason').textContent = "Failed to communicate with server.";
    } finally {
        btn.textContent = 'Scan with Gemini AI';
        btn.disabled = false;
    }
}


document.addEventListener('DOMContentLoaded', () => {
    initChart();
    toggleIngestion('start');
    fetchDashboardData();
    setInterval(fetchDashboardData, 3000);
});
