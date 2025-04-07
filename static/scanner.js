// static/scanning.js
document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('nuclei-scan-form');
    const ipSelect = document.getElementById('ip-select');
    const templateSelect = document.getElementById('template-select');
    const intensitySelect = document.getElementById('intensity-select');
    const customTemplateInput = document.getElementById('custom-template');
    const activityLog = document.getElementById('activity-log');
    const nucleiResult = document.getElementById('nuclei-result');

    // Function to populate IP dropdown from localStorage
    function populateIpDropdown() {
        // Retrieve IPs from localStorage
        const scanData = JSON.parse(localStorage.getItem('scanData')) || { nmaprun: { host: [] } };
        let hosts = scanData.nmaprun.host;
        if (!Array.isArray(hosts)) {
            hosts = [hosts];
        }

        // Clear existing options
        ipSelect.innerHTML = '<option value="">Select an IP</option>';

        // Populate dropdown with IPs
        hosts.forEach(host => {
            if (host.address && host.address['@addr']) {
                const ip = host.address['@addr'];
                const option = document.createElement('option');
                option.value = ip;
                option.textContent = ip;
                ipSelect.appendChild(option);
            }
        });

        // If no IPs are found, show an error
        if (ipSelect.options.length === 1) {
            ipSelect.innerHTML = '<option value="">No IPs found. Run an Nmap scan first.</option>';
        }
    }

    // Populate IP dropdown on page load
    populateIpDropdown();

    // Handle form submission
    form.addEventListener('submit', (event) => {
        event.preventDefault();

        const selectedIp = ipSelect.value;
        const selectedTemplate = templateSelect.value;
        const selectedIntensity = intensitySelect.value;
        const customTemplate = customTemplateInput.files[0];

        if (!selectedIp) {
            alert('Please select a target IP to scan.');
            return;
        }

        const formData = new FormData();
        formData.append('target', selectedIp);
        formData.append('template', selectedTemplate);
        formData.append('intensity', selectedIntensity);
        if (customTemplate) {
            formData.append('custom-template', customTemplate);
        }

        // Initiate Nuclei scan
        fetch('/api/run-nuclei', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                alert(data.error);
                return;
            }
            console.log('Nuclei scan initiated:', data);
            // Results will be populated via activity log streaming
        })
        .catch(error => {
            console.error('Error initiating Nuclei scan:', error);
            alert('Error initiating Nuclei scan.');
        });
    });

    // Stream activity log
    const eventSource = new EventSource('/api/activity-log');
    eventSource.onmessage = (event) => {
        activityLog.textContent += event.data + '\n';
        activityLog.scrollTop = activityLog.scrollHeight;

        // Check for Nuclei scan completion and fetch results
        if (event.data.includes('Nuclei scan completed')) {
            fetch('/api/nuclei-results')
                .then(response => response.json())
                .then(data => {
                    if (data.results && data.results.length > 0) {
                        let html = '<h2>Nuclei Scan Results</h2><table><thead><tr><th>Port</th><th>Vulnerability</th><th>Severity</th><th>Description</th></tr></thead><tbody>';
                        data.results.forEach(result => {
                            result.result.forEach(vuln => {
                                html += `
                                    <tr>
                                        <td>${result.port}</td>
                                        <td>${vuln.info.name}</td>
                                        <td>${vuln.info.severity}</td>
                                        <td>${vuln.info.description || 'No description available'}</td>
                                    </tr>
                                `;
                            });
                        });
                        html += '</tbody></table>';
                        nucleiResult.innerHTML = html;
                    } else {
                        nucleiResult.innerHTML = '<h2>Nuclei Scan Results</h2><p>No vulnerabilities found.</p>';
                    }
                })
                .catch(error => {
                    console.error('Error fetching Nuclei results:', error);
                    nucleiResult.innerHTML = '<h2>Nuclei Scan Results</h2><p>Error fetching results.</p>';
                });
        }
    };

    eventSource.onerror = () => {
        activityLog.textContent += 'Error streaming activity log.\n';
        eventSource.close();
    };
});