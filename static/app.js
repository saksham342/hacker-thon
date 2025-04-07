// static/app.js (updated)
document.addEventListener('DOMContentLoaded', () => {
    loadScanData();
    const scanForm = document.getElementById('scan-form');
    if (scanForm) {
        scanForm.addEventListener('submit', (e) => {
            e.preventDefault();
            runScan();
        });
    }

    const clearButton = document.getElementById('clear-button');
    if (clearButton) {
        clearButton.addEventListener('click', () => {
            localStorage.removeItem('scanInfo');
            localStorage.removeItem('scanData');
            const hostDetails = document.getElementById('host-details');
            const portsTable = document.getElementById('ports-table');
            const networkContainer = document.getElementById('network-visualization');
            if (hostDetails) hostDetails.innerHTML = '<p>No scan data available. Run a new scan.</p>';
            if (portsTable) portsTable.innerHTML = '<p>No scan data available. Run a new scan.</p>';
            if (networkContainer) networkContainer.innerHTML = '';
            alert('Scan data cleared. You can now run a new scan.');
        });
    }

    const nucleiForm = document.getElementById('nuclei-form');
    if (nucleiForm) {
        nucleiForm.addEventListener('submit', (e) => {
            e.preventDefault();
            runNucleiScan();
        });
    }
});

function runScan() {
    const target = document.getElementById('scan-target').value;
    if (!target) {
        alert('Please enter a target to scan.');
        return;
    }

    const hostDetails = document.getElementById('host-details');
    const portsTable = document.getElementById('ports-table');
    if (hostDetails) hostDetails.innerHTML = '<div class="loading-spinner"><div class="spinner"></div><p>Scanning...</p></div>';
    if (portsTable) portsTable.innerHTML = '<div class="loading-spinner"><div class="spinner"></div><p>Scanning...</p></div>';

    fetch('/api/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ target }),
    })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('Scan response:', data);
            if (data.status === 'Scan completed') {
                loadScanData();
            } else {
                alert('Scan failed: ' + (data.error || 'Unknown error'));
                if (hostDetails) hostDetails.innerHTML = '<p>Scan failed. Please try again.</p>';
                if (portsTable) portsTable.innerHTML = '<p>Scan failed. Please try again.</p>';
            }
        })
        .catch(error => {
            console.error('Error running scan:', error);
            alert('Error running scan: ' + error.message);
            if (hostDetails) hostDetails.innerHTML = '<p>Error occurred during scan. Check console for details.</p>';
            if (portsTable) portsTable.innerHTML = '<p>Error occurred during scan. Check console for details.</p>';
        });
}

function runNucleiScan() {
    const target = document.getElementById('nuclei-target')?.value;
    const template = document.getElementById('nuclei-template')?.value || 'cves';
    const intensity = document.getElementById('nuclei-intensity')?.value || 'medium';
    const scanInfo = JSON.parse(localStorage.getItem('scanInfo') || '{}');
    const ports = scanInfo.ports ? scanInfo.ports.map(p => p.port) : [];

    if (!target) {
        alert('Please select a target IP to scan.');
        return;
    }

    const resultsDiv = document.getElementById('nuclei-results');
    resultsDiv.innerHTML = '<div class="loading-spinner"><div class="spinner"></div><p>Running Nuclei scan...</p></div>';

    fetch('/api/run-nuclei-scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ip: target, ports, templates: [template] }),
    })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('Nuclei scan response:', data);
            if (data.success) {
                resultsDiv.innerHTML = '<h4>Scan Results</h4>';
                data.results.forEach(result => {
                    resultsDiv.innerHTML += `
                        <h5>Port ${result.port}</h5>
                        <pre>${JSON.stringify(result, null, 2)}</pre>
                    `;
                });
            } else {
                resultsDiv.innerHTML = `<p>Error: ${data.error}</p>`;
            }
        })
        .catch(error => {
            console.error('Error running Nuclei scan:', error);
            resultsDiv.innerHTML = `<p>Error: ${error.message}</p>`;
        });
}

function loadScanData() {
    fetch('/api/scan-data')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(scanData => {
            console.log('Fetched scan data:', scanData);
            localStorage.setItem('scanData', JSON.stringify(scanData));

            if (!scanData || !scanData.nmaprun || !scanData.nmaprun.host) {
                throw new Error('No host data available. Please run a scan first.');
            }

            let hosts = scanData.nmaprun.host;
            if (!Array.isArray(hosts)) {
                hosts = [hosts];
            }

            // Update Host Summary to show all hosts
            const hostDetails = document.getElementById('host-details');
            if (hostDetails) {
                hostDetails.innerHTML = hosts.map(host => {
                    const ipAddress = host.address && host.address['@addr'] ? host.address['@addr'] : 'Unknown IP';
                    let osInfo = 'No OS detection data available.';
                    if (host.os && host.os.osmatch && host.os.osmatch.length > 0) {
                        const topOS = host.os.osmatch[0];
                        osInfo = `
                            <p><strong>OS:</strong> ${topOS['@name'] || 'Unknown'}</p>
                            <p><strong>Accuracy:</strong> ${topOS['@accuracy'] || 'Unknown'}%</p>
                            <p><strong>Family:</strong> ${topOS.osclass && topOS.osclass['@osfamily'] ? topOS.osclass['@osfamily'] : 'Unknown'}</p>
                            <p><strong>Generation:</strong> ${topOS.osclass && topOS.osclass['@osgen'] ? topOS.osclass['@osgen'] : 'Unknown'}</p>
                        `;
                    }
                    return `
                        <div class="host-summary-item">
                            <p><strong>IP:</strong> ${ipAddress}</p>
                            <p><strong>Status:</strong> ${host.status && host.status['@state'] ? host.status['@state'] : 'Unknown'}</p>
                            <p><strong>Uptime:</strong> ${host.uptime && host.uptime['@seconds'] ? Math.round(host.uptime['@seconds'] / 3600) : 'Unknown'} hours</p>
                            <p><strong>Last Boot:</strong> ${host.uptime && host.uptime['@lastboot'] ? host.uptime['@lastboot'] : 'Unknown'}</p>
                            ${osInfo}
                        </div>
                    `;
                }).join('');
            }

            // Update Open Ports & Services to show all hosts
            const portsTable = document.getElementById('ports-table');
            if (portsTable) {
                let allPorts = [];
                hosts.forEach(host => {
                    const ipAddress = host.address && host.address['@addr'] ? host.address['@addr'] : 'Unknown IP';
                    if (host.ports && host.ports.port) {
                        const ports = Array.isArray(host.ports.port) ? host.ports.port : [host.ports.port];
                        ports.forEach(port => {
                            allPorts.push({ ipAddress, port });
                        });
                    }
                });
                if (allPorts.length > 0) {
                    portsTable.innerHTML = `
                        <div class="table-wrapper">
                            <table>
                                <thead>
                                    <tr>
                                        <th>IP Address</th>
                                        <th>Port</th>
                                        <th>State</th>
                                        <th>Service</th>
                                        <th>Version</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${allPorts.map(({ ipAddress, port }) => `
                                        <tr>
                                            <td>${ipAddress}</td>
                                            <td>${port['@portid'] || 'Unknown'}/${port['@protocol'] || 'Unknown'}</td>
                                            <td>${port.state && port.state['@state'] ? port.state['@state'] : 'Unknown'}</td>
                                            <td>${port.service && port.service['@name'] ? port.service['@name'] : 'Unknown'}</td>
                                            <td>${port.service && (port.service['@product'] || port.service['@version']) ? `${port.service['@product'] || ''} ${port.service['@version'] || ''}` : 'Unknown'}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    `;
                } else {
                    portsTable.innerHTML = '<p>No ports data available.</p>';
                }
            }

            // Update Network Visualization to show all hosts connected to a central network node
            const networkContainer = document.getElementById('network-visualization');
            if (networkContainer) {
                const nodes = [];
                const edges = [];
                const serviceMap = new Map(); // Map services to IPs for connecting devices

                // Add a central "Network" node to represent the subnet
                const networkNodeId = 'network';
                nodes.push({
                    id: networkNodeId,
                    label: 'Network',
                    shape: 'image',
                    image: 'https://img.icons8.com/ios-filled/50/000000/network.png', // Icon for network device
                    size: 30,
                    color: { border: '#ecf0f1', highlight: { border: '#ecf0f1' } },
                    font: { size: 16, color: '#ffffff', face: 'Roboto' },
                    margin: 10
                });

                // Add all hosts and connect them to the central network node
                hosts.forEach(host => {
                    const ipAddress = host.address && host.address['@addr'] ? host.address['@addr'] : 'Unknown IP';
                    nodes.push({
                        id: ipAddress,
                        label: `Host\n${ipAddress}`,
                        group: 'host',
                        shape: 'box',
                        color: { background: '#e0172d', border: '#ecf0f1', highlight: { background: '#ff4d4d', border: '#ecf0f1' } },
                        font: { size: 16, color: '#000000', face: 'Roboto' },
                        margin: 10
                    });

                    // Connect each host to the central network node
                    edges.push({
                        from: networkNodeId,
                        to: ipAddress,
                        color: { color: '#7f8c8d', highlight: '#3498db' },
                        width: 2
                    });

                    if (host.ports && host.ports.port) {
                        const ports = Array.isArray(host.ports.port) ? host.ports.port : [host.ports.port];
                        ports.forEach(port => {
                            const portId = `${ipAddress}:${port['@portid']}`;
                            const serviceName = port.service && port.service['@name'] ? port.service['@name'] : 'Unknown';
                            const version = port.service && (port.service['@product'] || port.service['@version']) ? `${port.service['@product'] || ''} ${port.service['@version'] || ''}` : '';
                            nodes.push({
                                id: portId,
                                label: `Port ${port['@portid']}\n${serviceName}`,
                                title: `Service: ${serviceName}\nVersion: ${version}\nState: ${port.state && port.state['@state'] ? port.state['@state'] : 'Unknown'}`,
                                group: 'port',
                                shape: 'ellipse',
                                color: { background: '#1e90ff', border: '#ecf0f1', highlight: { background: '#5dade2', border: '#ecf0f1' } },
                                font: { size: 14, color: '#000000', face: 'Roboto' },
                                margin: 8
                            });
                            edges.push({
                                from: ipAddress,
                                to: portId,
                                color: { color: '#7f8c8d', highlight: '#3498db' },
                                width: 2
                            });

                            // Track services for connecting devices
                            if (serviceName !== 'Unknown') {
                                if (!serviceMap.has(serviceName)) {
                                    serviceMap.set(serviceName, []);
                                }
                                serviceMap.get(serviceName).push({ ip: ipAddress, portId });
                            }
                        });
                    }

                    if (host.os && host.os.osmatch && host.os.osmatch.length > 0) {
                        const topOS = host.os.osmatch[0];
                        const osId = `${ipAddress}:os`;
                        nodes.push({
                            id: osId,
                            label: `OS\n${topOS['@name'] || 'Unknown'}`,
                            title: `OS: ${topOS['@name'] || 'Unknown'}\nAccuracy: ${topOS['@accuracy'] || 'Unknown'}%\nFamily: ${topOS.osclass && topOS.osclass['@osfamily'] ? topOS.osclass['@osfamily'] : 'Unknown'}`,
                            group: 'os',
                            shape: 'diamond',
                            color: { background: '#2ecc71', border: '#ecf0f1', highlight: { background: '#27ae60', border: '#ecf0f1' } },
                            font: { size: 14, color: '#000000', face: 'Roboto' },
                            margin: 8
                        });
                        edges.push({
                            from: ipAddress,
                            to: osId,
                            color: { color: '#7f8c8d', highlight: '#2ecc71' },
                            width: 2
                        });
                    }
                });

                // Connect hosts that share the same services
                serviceMap.forEach((devices, serviceName) => {
                    if (devices.length > 1) {
                        for (let i = 0; i < devices.length - 1; i++) {
                            for (let j = i + 1; j < devices.length; j++) {
                                const device1 = devices[i];
                                const device2 = devices[j];
                                edges.push({
                                    from: device1.ip,
                                    to: device2.ip,
                                    color: { color: '#ff0000', highlight: '#ff0000' },
                                    width: 2,
                                    label: `Shared Service: ${serviceName}`,
                                    font: { size: 12, color: '#ff0000' }
                                });
                            }
                        }
                    }
                });

                const data = { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) };
                const options = {
                    nodes: { font: { multi: 'html', size: 14, color: '#000000' }, borderWidth: 2, shadow: true },
                    edges: { width: 2, shadow: true, smooth: { type: 'curvedCW', roundness: 0.3 } },
                    physics: {
                        enabled: true,
                        barnesHut: {
                            gravitationalConstant: -8000, // Increased to pull nodes closer
                            centralGravity: 0.3,
                            springLength: 150, // Reduced to make connections tighter
                            springConstant: 0.05,
                            avoidOverlap: 1.5
                        },
                        stabilization: { enabled: true, iterations: 2000, updateInterval: 50 },
                        minVelocity: 0.75,
                        solver: 'barnesHut'
                    },
                    interaction: { hover: true, zoomView: true, dragView: true, tooltipDelay: 200 },
                    layout: { improvedLayout: true, randomSeed: 2 }
                };
                const network = new vis.Network(networkContainer, data, options);
                network.on('stabilized', () => network.fit());
            }

            // Update scanInfo to include all hosts
            const scanInfo = {
                hosts: hosts.map(host => ({
                    ipAddress: host.address && host.address['@addr'] ? host.address['@addr'] : 'Unknown IP',
                    ports: host.ports && host.ports.port ? (Array.isArray(host.ports.port) ? host.ports.port : [host.ports.port]).map(port => ({
                        port: port['@portid'],
                        protocol: port['@protocol'],
                        state: port.state && port.state['@state'] ? port.state['@state'] : 'Unknown',
                        service: port.service && port.service['@name'] ? port.service['@name'] : 'Unknown',
                        version: port.service && (port.service['@product'] || port.service['@version']) ? `${port.service['@product'] || ''} ${port.service['@version'] || ''}` : 'Unknown'
                    })) : [],
                    os: host.os && host.os.osmatch && host.os.osmatch.length > 0 ? {
                        name: host.os.osmatch[0]['@name'] || 'Unknown',
                        accuracy: host.os.osmatch[0]['@accuracy'] || 'Unknown',
                        family: host.os.osmatch[0].osclass && host.os.osmatch[0].osclass['@osfamily'] ? host.os.osmatch[0].osclass['@osfamily'] : 'Unknown'
                    } : null
                }))
            };
            localStorage.setItem('scanInfo', JSON.stringify(scanInfo));
        })
        .catch(error => {
            console.error('Error processing scan data:', error);
            document.querySelectorAll('.card').forEach(card => {
                card.innerHTML += `<p style="color: red;">Error: ${error.message}</p>`;
            });
        });
}