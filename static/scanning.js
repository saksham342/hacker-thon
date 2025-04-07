// static/scanning.js
document.addEventListener('DOMContentLoaded', () => {
    console.log('Scanning page loaded, initializing...');
    populateIpDropdown();
    populateTemplateChecklist();
    populateTemplateList();
    setupUploadTemplateForm();
    setupNucleiScanForm();
});

function populateIpDropdown() {
    const ipSelect = document.getElementById('target-ip');
    const customIpContainer = document.getElementById('custom-ip-container');
    const customIpInput = document.getElementById('custom-ip-input');
    const scanInfo = JSON.parse(localStorage.getItem('scanInfo')) || {};

    // Populate IPs and ports from Nmap results
    if (scanInfo.ipAddress) {
        // Add the IP without a port (to scan all ports)
        const ipOption = document.createElement('option');
        ipOption.value = `http://${scanInfo.ipAddress}`;  // Include protocol
        ipOption.textContent = scanInfo.ipAddress;
        ipSelect.appendChild(ipOption);

        // Add IP:port options for each port
        if (scanInfo.ports && scanInfo.ports.length > 0) {
            scanInfo.ports.forEach(portInfo => {
                if (portInfo.state === 'open' || portInfo.state === 'filtered') {
                    const option = document.createElement('option');
                    const protocol = portInfo.port === '443' ? 'https' : 'http';
                    option.value = `${protocol}://${scanInfo.ipAddress}:${portInfo.port}`;
                    option.textContent = `${scanInfo.ipAddress}:${portInfo.port}`;
                    ipSelect.appendChild(option);
                }
            });
        }
    }

    // Add event listener to show/hide custom IP input
    ipSelect.addEventListener('change', () => {
        if (ipSelect.value === 'custom') {
            customIpContainer.style.display = 'block';
            customIpInput.required = true;
        } else {
            customIpContainer.style.display = 'none';
            customIpInput.required = false;
            customIpInput.value = '';
        }
    });
}

function populateTemplateChecklist() {
    const checklistDiv = document.getElementById('template-checklist');

    fetch('/api/get-template-categories')
        .then(response => response.json())
        .then(data => {
            let html = '';

            if (data.custom && data.custom.length > 0) {
                // Sort templates alphabetically by name
                data.custom.sort((a, b) => a.name.localeCompare(b.name));

                html += `
                    <div class="checklist-section">
                        <div class="checklist-header">
                            <h4>Custom Templates</h4>
                            <div class="checklist-item select-all">
                                <input type="checkbox" id="select-all-custom">
                                <label for="select-all-custom">Select All</label>
                            </div>
                        </div>
                        <div class="checklist-list" id="custom-list">
                `;
                data.custom.forEach(template => {
                    const templateName = template.name.replace('.yaml', '');
                    html += `
                        <div class="checklist-item" style="display: flex; align-items: center; margin-bottom: 10px;">
                            <input type="checkbox" id="template-${templateName}" name="templates" value="${template.name}" style="margin-right: 10px;">
                            <label for="template-${templateName}">${template.name}</label>
                        </div>
                    `;
                });
                html += '</div></div>';
            } else {
                html = '<p>No custom templates available. Please upload a template to proceed.</p>';
            }

            checklistDiv.innerHTML = html;

            const selectAllCustom = document.getElementById('select-all-custom');

            if (selectAllCustom) {
                selectAllCustom.addEventListener('change', (event) => {
                    const checkboxes = document.querySelectorAll('#custom-list input[name="templates"]');
                    checkboxes.forEach(checkbox => {
                        checkbox.checked = event.target.checked;
                    });
                });
            }

            const updateSelectAllState = (sectionId, selectAllId) => {
                const checkboxes = document.querySelectorAll(`#${sectionId} input[name="templates"]`);
                const selectAllCheckbox = document.getElementById(selectAllId);
                if (checkboxes.length === 0) return;

                const allChecked = Array.from(checkboxes).every(checkbox => checkbox.checked);
                const someChecked = Array.from(checkboxes).some(checkbox => checkbox.checked);
                selectAllCheckbox.checked = allChecked;
                selectAllCheckbox.indeterminate = someChecked && !allChecked;
            };

            document.querySelectorAll('#custom-list input[name="templates"]').forEach(checkbox => {
                checkbox.addEventListener('change', () => updateSelectAllState('custom-list', 'select-all-custom'));
            });
        })
        .catch(error => {
            console.error('Error fetching template categories:', error);
            checklistDiv.innerHTML = '<p>Error loading templates.</p>';
        });
}

function populateTemplateList() {
    const templateListBody = document.getElementById('template-list-body');

    fetch('/api/get-template-categories')
        .then(response => response.json())
        .then(data => {
            let html = '';
            if (data.custom && data.custom.length > 0) {
                data.custom.forEach(template => {
                    html += `
                        <tr>
                            <td>${template.name}</td>
                            <td>${template.date}</td>
                            <td>
                                <button class="delete-template-btn" data-template="${template.name}">Delete</button>
                            </td>
                        </tr>
                    `;
                });
            } else {
                html = '<tr><td colspan="3">No custom templates uploaded.</td></tr>';
            }
            templateListBody.innerHTML = html;

            document.querySelectorAll('.delete-template-btn').forEach(button => {
                button.addEventListener('click', () => {
                    const templateName = button.getAttribute('data-template');
                    if (confirm(`Are you sure you want to delete the template "${templateName}"?`)) {
                        fetch('/api/delete-template', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({ template_name: templateName }),
                        })
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                alert(data.message);
                                populateTemplateChecklist();
                                populateTemplateList();
                            } else {
                                alert(`Error: ${data.error}`);
                            }
                        })
                        .catch(error => {
                            console.error('Error deleting template:', error);
                            alert(`Error deleting template: ${error.message}`);
                        });
                    }
                });
            });
        })
        .catch(error => {
            console.error('Error fetching template list:', error);
            templateListBody.innerHTML = '<tr><td colspan="3">Error loading template list.</td></tr>';
        });
}

function setupUploadTemplateForm() {
    const form = document.getElementById('upload-template-form');
    const statusDiv = document.getElementById('upload-status');

    form.addEventListener('submit', (event) => {
        event.preventDefault();

        const formData = new FormData(form);
        statusDiv.innerHTML = '<p>Uploading...</p>';

        fetch('/api/upload-template', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                statusDiv.innerHTML = `<p style="color: #4caf50;">${data.message}</p>`;
                populateTemplateChecklist();
                populateTemplateList();
                form.reset();
            } else {
                statusDiv.innerHTML = `<p style="color: #f44336;">Error: ${data.error}</p>`;
            }
        })
        .catch(error => {
            statusDiv.innerHTML = `<p style="color: #f44336;">Error uploading template: ${error.message}</p>`;
            console.error('Error uploading template:', error);
        });
    });
}

function setupNucleiScanForm() {
    const form = document.getElementById('nuclei-scan-form');
    const statusDiv = document.getElementById('scan-status');
    const loadingSpinner = document.getElementById('loading-spinner');
    const resultsTableDiv = document.getElementById('results-table');
    const filterInput = document.getElementById('filter-input');
    const sortSelect = document.getElementById('sort-select');
    const genericScanButton = document.getElementById('run-generic-scan');

    let allResults = [];

    // Existing form submission handler for custom template scans
    form.addEventListener('submit', (event) => {
        event.preventDefault();

        const ipSelect = document.getElementById('target-ip');
        const customIpInput = document.getElementById('custom-ip-input');
        let ipPort = ipSelect.value;

        if (ipPort === 'custom') {
            ipPort = customIpInput.value.trim();
            if (!ipPort) {
                statusDiv.innerHTML = '<p style="color: #f44336;"><strong>Error:</strong> Please enter a valid IP or domain with protocol (e.g., http://192.168.1.1 or https://example.com).</p>';
                return;
            }
            // Ensure the custom input includes a protocol
            if (!ipPort.startsWith('http://') && !ipPort.startsWith('https://')) {
                statusDiv.innerHTML = '<p style="color: #f44336;"><strong>Error:</strong> Please include the protocol (http:// or https://) in the custom IP/domain.</p>';
                return;
            }
        }

        if (!ipPort) {
            statusDiv.innerHTML = '<p style="color: #f44336;"><strong>Error:</strong> Please select an IP or enter a custom IP/domain with protocol.</p>';
            return;
        }

        const selectedTemplates = Array.from(document.querySelectorAll('input[name="templates"]:checked'))
            .map(checkbox => checkbox.value);

        if (selectedTemplates.length === 0) {
            statusDiv.innerHTML = '<p style="color: #f44336;"><strong>Error:</strong> Please select at least one template.</p>';
            return;
        }

        let ip = ipPort;
        let ports = [];

        // Check if the selected value contains a port (e.g., "http://45.33.32.156:22")
        if (ipPort.includes(':')) {
            const parts = ipPort.split(':');
            if (parts.length === 3) {  // e.g., http://45.33.32.156:22
                ip = `${parts[0]}:${parts[1]}`;  // http://45.33.32.156
                ports = [parts[2]];  // 22
            }
        }

        console.log('Sending request to backend:', { ip, ports, templates: selectedTemplates });

        // Show loading spinner
        statusDiv.innerHTML = '';
        loadingSpinner.style.display = 'flex';
        resultsTableDiv.innerHTML = '';

        fetch('/api/run-nuclei-scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                ip: ip,
                ports: ports,
                templates: selectedTemplates
            }),
            credentials: 'same-origin'
        })
        .then(response => {
            console.log('Response status:', response.status);
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('Scan data:', data);
            loadingSpinner.style.display = 'none';
            if (data.success) {
                allResults = data.results || [];
                if (allResults.length === 0) {
                    statusDiv.innerHTML = `<p style="color: #4caf50;"><strong>Scan Completed:</strong> No vulnerabilities found for ${ip} using the selected templates.</p>`;
                    resultsTableDiv.innerHTML = '<p>No vulnerabilities found.</p>';
                } else {
                    statusDiv.innerHTML = `<p style="color: #4caf50;"><strong>Success:</strong> Scan completed for ${ip}. Found ${allResults.length} vulnerabilities.</p>`;
                    displayScanResults(allResults);
                }
            } else {
                statusDiv.innerHTML = `<p style="color: #f44336;"><strong>Error:</strong> ${data.error}</p>`;
                resultsTableDiv.innerHTML = '<p>Failed to display results due to an error.</p>';
            }
        })
        .catch(error => {
            console.error('Error running Nuclei scan:', error);
            loadingSpinner.style.display = 'none';
            statusDiv.innerHTML = `<p style="color: #f44336;"><strong>Error:</strong> Failed to run Nuclei scan: ${error.message}</p>`;
            resultsTableDiv.innerHTML = '<p>Failed to display results due to a network error. Please check the console for details.</p>';
        });
    });

    // Event listener for the generic Nuclei scan button
    genericScanButton.addEventListener('click', () => {
        const ipSelect = document.getElementById('target-ip');
        const customIpInput = document.getElementById('custom-ip-input');
        let ipPort = ipSelect.value;

        if (ipPort === 'custom') {
            ipPort = customIpInput.value.trim();
            if (!ipPort) {
                statusDiv.innerHTML = '<p style="color: #f44336;"><strong>Error:</strong> Please enter a valid IP or domain with protocol (e.g., http://192.168.1.1 or https://example.com).</p>';
                return;
            }
            // Ensure the custom input includes a protocol
            if (!ipPort.startsWith('http://') && !ipPort.startsWith('https://')) {
                statusDiv.innerHTML = '<p style="color: #f44336;"><strong>Error:</strong> Please include the protocol (http:// or https://) in the custom IP/domain.</p>';
                return;
            }
        }

        if (!ipPort) {
            statusDiv.innerHTML = '<p style="color: #f44336;"><strong>Error:</strong> Please select an IP or enter a custom IP/domain with protocol.</p>';
            return;
        }

        let ip = ipPort;
        let ports = [];

        // Check if the selected value contains a port (e.g., "http://45.33.32.156:22")
        if (ipPort.includes(':')) {
            const parts = ipPort.split(':');
            if (parts.length === 3) {  // e.g., http://45.33.32.156:22
                ip = `${parts[0]}:${parts[1]}`;  // http://45.33.32.156
                ports = [parts[2]];  // 22
            }
        }

        console.log('Sending request for generic Nuclei scan:', { ip, ports });

        // Show loading spinner
        statusDiv.innerHTML = '';
        loadingSpinner.style.display = 'flex';
        resultsTableDiv.innerHTML = '';

        fetch('/api/run-generic-nuclei-scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                ip: ip,
                ports: ports
            }),
            credentials: 'same-origin'
        })
        .then(response => {
            console.log('Response status:', response.status);
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('Generic scan data:', data);
            loadingSpinner.style.display = 'none';
            if (data.success) {
                allResults = data.results || [];
                if (allResults.length === 0) {
                    statusDiv.innerHTML = `<p style="color: #4caf50;"><strong>Scan Completed:</strong> No vulnerabilities found for ${ip} using generic Nuclei scan.</p>`;
                    resultsTableDiv.innerHTML = '<p>No vulnerabilities found.</p>';
                } else {
                    statusDiv.innerHTML = `<p style="color: #4caf50;padding-top: 18px;"><strong>Success:</strong> Generic Nuclei scan completed for ${ip}. Found ${allResults.length} vulnerabilities.</p>`;
                    displayScanResults(allResults);
                }
            } else {
                statusDiv.innerHTML = `<p style="color: #f44336;"><strong>Error:</strong> ${data.error}</p>`;
                resultsTableDiv.innerHTML = '<p>Failed to display results due to an error.</p>';
            }
        })
        .catch(error => {
            console.error('Error running generic Nuclei scan:', error);
            loadingSpinner.style.display = 'none';
            statusDiv.innerHTML = `<p style="color: #f44336;"><strong>Error:</strong> Failed to run generic Nuclei scan: ${error.message}</p>`;
            resultsTableDiv.innerHTML = '<p>Failed to display results due to a network error. Please check the console for details.</p>';
        });
    });

    filterInput.addEventListener('input', () => {
        const filterText = filterInput.value.toLowerCase();
        const filteredResults = allResults.filter(result =>
            result.vulnerability.toLowerCase().includes(filterText) ||
            result.description.toLowerCase().includes(filterText) ||
            result.template.toLowerCase().includes(filterText) ||
            result.matched.toString().toLowerCase().includes(filterText)
        );
        displayScanResults(filteredResults);
    });

    sortSelect.addEventListener('change', () => {
        const sortValue = sortSelect.value;
        let sortedResults = [...allResults];
        if (sortValue === 'severity-desc') {
            sortedResults.sort((a, b) => {
                const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
                return (severityOrder[b.severity.toLowerCase()] || 0) - (severityOrder[a.severity.toLowerCase()] || 0);
            });
        } else if (sortValue === 'severity-asc') {
            sortedResults.sort((a, b) => {
                const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
                return (severityOrder[a.severity.toLowerCase()] || 0) - (severityOrder[b.severity.toLowerCase()] || 0);
            });
        } else if (sortValue === 'port-asc') {
            sortedResults.sort((a, b) => parseInt(a.port) - parseInt(b.port));
        } else if (sortValue === 'port-desc') {
            sortedResults.sort((a, b) => parseInt(b.port) - parseInt(a.port));
        }
        displayScanResults(sortedResults);
    });

    function displayScanResults(results) {
        console.log('Displaying results:', results);
        if (!results || results.length === 0) {
            resultsTableDiv.innerHTML = '<p>No results to display after filtering.</p>';
            return;
        }

        let html = '<table class="data-table" role="grid">';
        html += '<thead><tr><th>Target</th><th>Port</th><th>Template</th><th>Vulnerability</th><th>Severity</th><th>Description</th><th>Matched</th></tr></thead>';
        html += '<tbody>';

        results.forEach(result => {
            const severityClass = result.severity.toLowerCase();
            html += `<tr>
                        <td>${result.target || 'N/A'}</td>
                        <td>${result.port || 'N/A'}</td>
                        <td>${result.template || 'N/A'}</td>
                        <td>${result.vulnerability || 'N/A'}</td>
                        <td class="severity-${severityClass}">${result.severity || 'N/A'}</td>
                        <td>${result.description || 'N/A'}</td>
                        <td>${result.matched || 'N/A'}</td>
                    </tr>`;
        });

        html += '</tbody></table>';
        resultsTableDiv.innerHTML = html;
    }
}