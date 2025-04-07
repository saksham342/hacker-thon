// static/apt.js
document.addEventListener('DOMContentLoaded', () => {
    populateIpDropdowns();
    document.querySelectorAll('select[id$="-ip"]').forEach(select => {
        select.addEventListener('change', (e) => {
            const agentType = e.target.id.replace('-ip', '');
            const targetIp = e.target.value;
            if (targetIp) {
                fetchAgentResults(targetIp, agentType);
            }
        });
    });
});

function populateIpDropdowns() {
    const scanData = JSON.parse(localStorage.getItem('scanData')) || { nmaprun: { host: [] } };
    let hosts = scanData.nmaprun.host;
    if (!Array.isArray(hosts)) {
        hosts = [hosts];
    }
    const ips = hosts.map(host => host.address['@addr']).filter(ip => ip);
    const dropdowns = document.querySelectorAll('select[id$="-ip"]');
    dropdowns.forEach(dropdown => {
        dropdown.innerHTML = '<option value="">Select an IP</option>' + 
            ips.map(ip => `<option value="${ip}">${ip}</option>`).join('');
    });
}

function fetchAgentResults(targetIp, agentType) {
    const resultsDiv = document.getElementById(`${agentType}-results`);
    resultsDiv.innerHTML = '<p>Checking for results...</p>';
    
    fetch(`/api/get-agent-results?target_ip=${targetIp}&agent_type=${agentType}`)
        .then(response => response.json())
        .then(data => {
            if (!data.error) {
                if (agentType === 'ssh-intrusion' && Array.isArray(data) && data.length > 0) {
                    let html = '<h3>SSH Intrusion Alerts</h3>';
                    html += '<div class="table-wrapper"><table><thead><tr><th>Attacker IP</th><th>Timestamp</th><th>Hostname</th></tr></thead><tbody>';
                    data.forEach(alert => {
                        html += `<tr><td>${alert.attacker_ip}</td><td>${alert.timestamp}</td><td>${alert.hostname}</td></tr>`;
                    });
                    html += '</tbody></table></div>';
                    resultsDiv.innerHTML = html;
                } else {
                    resultsDiv.innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
                }
            } else {
                resultsDiv.innerHTML = '<p>No results available yet. Ensure the agent is running on the target.</p>';
            }
        })
        .catch(error => {
            console.error('Error fetching results:', error);
            resultsDiv.innerHTML = '<p>Error fetching results. Check console for details.</p>';
        });
}