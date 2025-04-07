// static/insider_threats.js
document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM fully loaded, initializing...');
    setupTabs();
    populateIpDropdowns();
    loadFromLocalStorage();
    setupReloadButton();
});

function setupTabs() {
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabPanes = document.querySelectorAll('.tab-pane');

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            // Remove active class from all buttons and panes
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabPanes.forEach(pane => pane.classList.remove('active'));

            // Add active class to clicked button and corresponding pane
            button.classList.add('active');
            const tabId = button.getAttribute('data-tab');
            document.getElementById(`${tabId}-tab`).classList.add('active');

            // Load data for the selected tab
            const select = document.getElementById(`${tabId}-ip`);
            if (select.value) {
                loadTabData(tabId, select.value);
            }
        });
    });
}

function populateIpDropdowns() {
    console.log('Populating IP dropdowns...');
    const dropdowns = document.querySelectorAll('select[id$="-ip"]');
    if (dropdowns.length === 0) {
        console.warn('No dropdowns found with IDs ending in "-ip"');
        return;
    }

    // Fetch IPs only once
    fetch('/api/get-agent-ips', {
        method: 'GET',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' }
    })
    .then(response => {
        if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
        return response.json();
    })
    .then(data => {
        const ips = data.ips || [];
        console.log('Available IPs from /api/get-agent-ips:', ips);

        if (ips.length === 0) {
            dropdowns.forEach(dropdown => {
                dropdown.innerHTML = '<option value="">No IPs available</option>';
            });
            return;
        }

        dropdowns.forEach(dropdown => {
            const currentValue = dropdown.value;
            dropdown.innerHTML = '<option value="">Select an IP</option>' + 
                ips.map(ip => `<option value="${ip}">${ip}</option>`).join('');
            
            if (currentValue && ips.includes(currentValue)) {
                dropdown.value = currentValue;
            }
            console.log(`Populated dropdown ${dropdown.id} with ${ips.length} IPs`);

            dropdown.removeEventListener('change', handleIpChange);
            dropdown.addEventListener('change', handleIpChange);
        });

        // Load data for the active tab if an IP is selected
        const activeTab = document.querySelector('.tab-button.active').getAttribute('data-tab');
        const activeSelect = document.getElementById(`${activeTab}-ip`);
        if (activeSelect.value) {
            loadTabData(activeTab, activeSelect.value);
        }
    })
    .catch(error => {
        console.error('Error fetching agent IPs:', error);
        dropdowns.forEach(dropdown => {
            dropdown.innerHTML = '<option value="">Error loading IPs</option>';
        });
    });
}

function handleIpChange(event) {
    const select = event.target;
    const targetIp = select.value;
    if (!targetIp) return;

    const category = select.id.replace('-ip', '');
    loadTabData(category, targetIp);
}

function setupReloadButton() {
    const reloadButton = document.getElementById('reload-button');
    reloadButton.addEventListener('click', () => {
        const activeTab = document.querySelector('.tab-button.active').getAttribute('data-tab');
        const select = document.getElementById(`${activeTab}-ip`);
        if (select.value) {
            fetchTabData(activeTab, select.value, true); // Force fetch from API
        }
    });
}

function loadTabData(category, targetIp) {
    const storedData = localStorage.getItem(category);
    const resultsDiv = document.getElementById(`${category}-results`);

    if (storedData) {
        const data = JSON.parse(storedData);
        if (data[targetIp]) {
            console.log(`Loading ${category} data for ${targetIp} from localStorage`);
            displayTabData(resultsDiv, data[targetIp], targetIp, category);
            return;
        }
    }

    // If no data in localStorage, fetch from API
    fetchTabData(category, targetIp);
}

function fetchTabData(category, targetIp, forceFetch = false) {
    const endpoints = {
        'backdoor': ['service-changes', 'user-account-backdoor-detection', 'backdoor-reg-tamper'],
        'cve-details': ['cve-detection'],
        'privilege-escalation': ['privilege-escalation'],
        'credentials-theft': ['scanned-credentials']
    };

    const relevantEndpoints = endpoints[category];
    const resultsDiv = document.getElementById(`${category}-results`);

    resultsDiv.innerHTML = '<p>Loading...</p>';
    let allData = {};

    Promise.all(relevantEndpoints.map(endpoint => 
        fetch(`/api/${endpoint}?target_ip=${targetIp}`)
            .then(response => response.json())
            .then(data => {
                allData[endpoint] = data;
                console.log(`Fetched data for ${endpoint}:`, data);
            })
            .catch(error => {
                console.error(`Error fetching ${endpoint} data:`, error);
                allData[endpoint] = { error: 'Failed to fetch data' };
            })
    ))
    .then(() => {
        // Store data in localStorage under the IP
        let storedData = JSON.parse(localStorage.getItem(category) || '{}');
        storedData[targetIp] = allData;
        localStorage.setItem(category, JSON.stringify(storedData));
        displayTabData(resultsDiv, allData, targetIp, category);
    });
}

function displayTabData(container, allData, targetIp, category) {
    if (Object.keys(allData).length === 0 || Object.values(allData).every(data => Object.keys(data).length === 0)) {
        container.innerHTML = '<p>No results yet...</p>';
        return;
    }

    container.innerHTML = ''; // Clear existing content

    if (category === 'backdoor') {
        if (allData['service-changes']) {
            displayServiceChanges(container, allData['service-changes'], targetIp);
        }
        if (allData['user-account-backdoor-detection']) {
            displayUserAccountBackdoor(container, allData['user-account-backdoor-detection'], targetIp);
        }
        if (allData['backdoor-reg-tamper']) {
            displayBackdoorRegTamper(container, allData['backdoor-reg-tamper'], targetIp);
        }
    } else if (category === 'cve-details' && allData['cve-detection']) {
        displayCveDetection(container, allData['cve-detection'], targetIp);
    } else if (category === 'privilege-escalation' && allData['privilege-escalation']) {
        displayPrivilegeEscalation(container, allData['privilege-escalation'], targetIp);
    } else if (category === 'credentials-theft' && allData['scanned-credentials']) {
        displayScannedCredentials(container, allData['scanned-credentials'], targetIp);
    }
}

// Display functions for each endpoint
function displayServiceChanges(container, data, targetIp) {
    const timestamp = data.timestamp || new Date().toISOString();
    const section = document.createElement('div');
    section.className = 'details-section';

    let html = `<h3>Service Changes - ${targetIp}</h3>`;
    html += `<p><strong>Timestamp:</strong> ${timestamp}</p>`;
    html += `<pre>${JSON.stringify(data, null, 2)}</pre>`;

    section.innerHTML = html;
    container.appendChild(section);
}

function displayUserAccountBackdoor(container, data, targetIp) {
    const timestamp = data.timestamp || new Date().toISOString();
    const section = document.createElement('div');
    section.className = 'details-section';

    let html = `<h3>User Account Backdoor Detection - ${targetIp}</h3>`;
    html += `<p><strong>Timestamp:</strong> ${timestamp}</p>`;
    html += `<pre>${JSON.stringify(data, null, 2)}</pre>`;

    section.innerHTML = html;
    container.appendChild(section);
}

function displayBackdoorRegTamper(container, data, targetIp) {
    const timestamp = data.timestamp || new Date().toISOString();
    const section = document.createElement('div');
    section.className = 'details-section';

    let html = `<h3>Backdoor Registry Tamper - ${targetIp}</h3>`;
    html += `<p><strong>Timestamp:</strong> ${timestamp}</p>`;
    html += `<pre>${JSON.stringify(data, null, 2)}</pre>`;

    section.innerHTML = html;
    container.appendChild(section);
}


function displayCveDetection(container, data, targetIp) {
    const timestamp = data.timestamp || new Date().toISOString();
    const results = data.results || {};
    const section = document.createElement('div');
    section.className = 'details-section';

    let html = `<h3>CVE Detection - ${targetIp}</h3>`;
    html += `<p><strong>Timestamp:</strong> ${timestamp}</p>`;

    // Check if there's an error in the results
    if (results.error) {
        html += `<p><strong>Error:</strong> ${results.error}</p>`;
    } else if (results.summary && results.vulnerabilities) {
        // Display Summary
        html += `<h3>Summary</h3>`;
        html += `<p><strong>Total CVEs Checked:</strong> ${results.summary.total_cves_checked || 'N/A'}</p>`;
        html += `<p><strong>Vulnerable:</strong> ${results.summary.vulnerable || 'N/A'}</p>`;
        html += `<p><strong>Not Vulnerable:</strong> ${results.summary.not_vulnerable || 'N/A'}</p>`;
        html += `<p><strong>Message:</strong> ${results.summary.message || 'No message'}</p>`;

        // Display Vulnerabilities in a Table
        if (results.vulnerabilities.length > 0) {
            html += `<h3>Vulnerabilities</h3>`;
            html += `<table class="data-table">
                        <thead>
                            <tr>
                                <th>CVE ID</th>
                                <th>Description</th>
                                <th>Command</th>
                                <th>Output</th>
                                <th>Vulnerability Condition</th>
                                <th>Patch Status</th>
                            </tr>
                        </thead>
                        <tbody>`;
            results.vulnerabilities.forEach((vuln, index) => {
                const patchStatus = vuln.patch_status ? (vuln.patch_status.patch_check_failed || 'N/A') : 'N/A';
                const outputId = `output-${index}`; // Unique ID for each output
                html += `<tr>
                            <td>${vuln.cve_id || 'N/A'}</td>
                            <td>${vuln.description || 'N/A'}</td>
                            <td>${vuln.command || 'N/A'}</td>
                            <td>
                                <button class="toggle-output-button" data-target="${outputId}">Show</button>
                                <pre id="${outputId}" class="output-content" style="display: none;">${vuln.output || 'No output'}</pre>
                            </td>
                            <td>${vuln.vulnerability_condition || 'N/A'}</td>
                            <td>${patchStatus}</td>
                        </tr>`;
            });
            html += `</tbody></table>`;
        } else {
            html += `<p>No vulnerabilities found.</p>`;
        }
    } else {
        html += `<p>No CVE detection data available.</p>`;
    }

    section.innerHTML = html;
    container.appendChild(section);

    // Add event listeners for toggle buttons
    const toggleButtons = section.querySelectorAll('.toggle-output-button');
    toggleButtons.forEach(button => {
        button.addEventListener('click', () => {
            const targetId = button.getAttribute('data-target');
            const outputElement = document.getElementById(targetId);
            if (outputElement.style.display === 'none') {
                outputElement.style.display = 'block';
                button.textContent = 'Hide';
            } else {
                outputElement.style.display = 'none';
                button.textContent = 'Show';
            }
        });
    });
}

function displayPrivilegeEscalation(container, data, targetIp) {
    const timestamp = data.timestamp || new Date().toISOString();
    const results = data.results || {};
    const section = document.createElement('div');
    section.className = 'details-section';

    let html = `<h3>Privilege Escalation Vectors - ${targetIp}</h3>`;
    html += `<p><strong>Timestamp:</strong> ${timestamp}</p>`;

    // CVE Vulnerabilities Table
    if (results.cve_vulnerabilities && results.cve_vulnerabilities.length > 0) {
        html += `<h3>CVE Vulnerabilities</h3>`;
        html += `<table class="data-table">
                    <thead>
                        <tr>
                            <th>CVE</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>`;
        results.cve_vulnerabilities.forEach(vuln => {
            html += `<tr>
                        <td>${vuln.cve || 'N/A'}</td>
                        <td>${vuln.description || 'N/A'}</td>
                    </tr>`;
        });
        html += `</tbody></table>`;
    }

    // Group Membership
    if (results.group_membership) {
        html += `<h3>Group Membership</h3>`;
        html += `<p><strong>Status:</strong> ${results.group_membership.status || 'N/A'}</p>`;
        html += `<pre>${results.group_membership.details || 'No details available'}</pre>`;
    }

    // Service Restart Permissions Table
    if (results.service_restart_permissions && results.service_restart_permissions.length > 0) {
        html += `<h3>Service Restart Permissions</h3>`;
        html += `<table class="data-table">
                    <thead>
                        <tr>
                            <th>Service</th>
                            <th>DACL</th>
                        </tr>
                    </thead>
                    <tbody>`;
        results.service_restart_permissions.forEach(perm => {
            html += `<tr>
                        <td>${perm.service || 'N/A'}</td>
                        <td>${perm.dacl || 'N/A'}</td>
                    </tr>`;
        });
        html += `</tbody></table>`;
    }

    // Stored Credentials
    if (results.stored_credentials) {
        html += `<h3>Stored Credentials</h3>`;
        html += `<pre>${results.stored_credentials.details || 'No credentials found'}</pre>`;
    }

    // Unquoted Service Paths Table
    if (results.unquoted_service_paths && results.unquoted_service_paths.length > 0) {
        html += `<h3>Unquoted Service Paths</h3>`;
        html += `<table class="data-table">
                    <thead>
                        <tr>
                            <th>Service</th>
                            <th>Path</th>
                        </tr>
                    </thead>
                    <tbody>`;
        results.unquoted_service_paths.forEach(path => {
            html += `<tr>
                        <td>${path.service || 'N/A'}</td>
                        <td>${path.path || 'N/A'}</td>
                    </tr>`;
        });
        html += `</tbody></table>`;
    }

    // Weak Service Accounts Table
    if (results.weak_service_accounts && results.weak_service_accounts.length > 0) {
        html += `<h3>Weak Service Accounts</h3>`;
        html += `<table class="data-table">
                    <thead>
                        <tr>
                            <th>Service</th>
                            <th>Runs As</th>
                        </tr>
                    </thead>
                    <tbody>`;
        results.weak_service_accounts.forEach(account => {
            html += `<tr>
                        <td>${account.service || 'N/A'}</td>
                        <td>${account.runs_as || 'N/A'}</td>
                    </tr>`;
        });
        html += `</tbody></table>`;
    }

    // Scan Initiated By
    if (results.scan_initiated_by) {
        html += `<h3>Scan Initiated By</h3>`;
        html += `<p>${results.scan_initiated_by}</p>`;
    }

    section.innerHTML = html;
    container.appendChild(section);
}

function displayScannedCredentials(container, data, targetIp) {
    const timestamp = data.timestamp || new Date().toISOString();
    const results = data.results || {};

    const section = document.createElement('div');
    section.className = 'details-section';

    let html = `<h3>Credentials Theft Details - ${targetIp}</h3>`;
    html += `<p><strong>Timestamp:</strong> ${timestamp}</p>`;

    html += `<h3>Putty Credentials</h3>`;
    html += `<pre>${results.putty_credentials || 'No data available'}</pre>`;

    html += `<h3>Saved Credentials</h3>`;
    html += `<pre>${results.saved_credentials || 'No data available'}</pre>`;

    if (results.credential_manager) {
        html += `<h3>Credential Manager</h3>`;
        html += `<p><strong>Directory:</strong> ${results.credential_manager.directory || 'N/A'}</p>`;
        html += `<p><strong>Files:</strong></p><pre>${results.credential_manager.files || 'N/A'}</pre>`;
        html += `<p><strong>Note:</strong> ${results.credential_manager.note || 'N/A'}</p>`;
    }

    if (results.iis_config && results.iis_config.length > 0) {
        html += `<h3>IIS Configuration</h3>`;
        html += `<ul>`;
        results.iis_config.forEach(config => {
            html += `<li>`;
            html += `<p><strong>File:</strong> ${config.file || 'N/A'}</p>`;
            html += `<p><strong>Connection Strings:</strong></p><pre>${config.connection_strings || 'N/A'}</pre>`;
            html += `</li>`;
        });
        html += `</ul>`;
    }

    if (results.powershell_history) {
        html += `<h3>PowerShell History</h3>`;
        html += `<p><strong>File:</strong> ${results.powershell_history.file || 'N/A'}</p>`;
        html += `<p><strong>Content:</strong></p><pre>${results.powershell_history.content || 'N/A'}</pre>`;
    }

    if (results.sam_hashes) {
        html += `<h3>SAM Hashes</h3>`;
        html += `<p><strong>Export:</strong> ${results.sam_hashes.export || 'N/A'}</p>`;
        html += `<p><strong>Hashes:</strong></p><pre>${JSON.stringify(results.sam_hashes.hashes, null, 2) || 'N/A'}</pre>`;
    }

    html += `<h3>Scan Initiated By</h3>`;
    html += `<p>${results.scan_initiated_by || 'Unknown'}</p>`;

    html += `<h3>Unattend Files</h3>`;
    html += `<p>${results.unattend_files && results.unattend_files.length > 0 ? JSON.stringify(results.unattend_files, null, 2) : 'None found'}</p>`;

    section.innerHTML = html;
    container.appendChild(section);
}

function loadFromLocalStorage() {
    const categories = ['backdoor', 'cve-details', 'privilege-escalation', 'credentials-theft'];
    const activeTab = document.querySelector('.tab-button.active').getAttribute('data-tab');
    const activeSelect = document.getElementById(`${activeTab}-ip`);

    if (activeSelect.value) {
        const storedData = localStorage.getItem(activeTab);
        if (storedData) {
            const data = JSON.parse(storedData);
            if (data[activeSelect.value]) {
                const resultsDiv = document.getElementById(`${activeTab}-results`);
                displayTabData(resultsDiv, data[activeSelect.value], activeSelect.value, activeTab);
            } else {
                fetchTabData(activeTab, activeSelect.value);
            }
        } else {
            fetchTabData(activeTab, activeSelect.value);
        }
    }
}