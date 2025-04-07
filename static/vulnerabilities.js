// static/vulnerabilities.js (updated with color coding)
document.addEventListener('DOMContentLoaded', () => {
    loadVulnerabilities();
});

function loadVulnerabilities() {
    fetch('/api/scan-data')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(scanData => {
            // Log the raw scan data for debugging
            console.log('Raw scan data from /api/scan-data:', JSON.stringify(scanData, null, 2));

            if (!scanData || !scanData.nmaprun || !scanData.nmaprun.host) {
                throw new Error('No host data available. Please run a scan first.');
            }

            let hosts = scanData.nmaprun.host;
            if (!Array.isArray(hosts)) {
                hosts = [hosts];
            }

            const cveTableBody = document.getElementById('cve-table-body');
            let allVulnerabilities = [];

            hosts.forEach(host => {
                console.log(`Processing host: ${host.address['@addr']}`);
                if (host.vulnerabilities && Array.isArray(host.vulnerabilities) && host.vulnerabilities.length > 0) {
                    console.log(`Found ${host.vulnerabilities.length} vulnerabilities for host ${host.address['@addr']}:`, host.vulnerabilities);
                    allVulnerabilities = allVulnerabilities.concat(host.vulnerabilities);
                } else {
                    console.log(`No vulnerabilities for host ${host.address['@addr']}`);
                }
            });

            console.log(`Total vulnerabilities found: ${allVulnerabilities.length}`);
            if (allVulnerabilities.length > 0) {
                // Sort vulnerabilities by severity (descending)
                allVulnerabilities.sort((a, b) => {
                    const severityA = parseFloat(a.severity) || 0;
                    const severityB = parseFloat(b.severity) || 0;
                    return severityB - severityA;
                });

                cveTableBody.innerHTML = allVulnerabilities.map(vuln => {
                    const cveLink = `https://nvd.nist.gov/vuln/detail/${vuln.cve}`;
                    // Determine the severity class for color coding
                    let severityClass = '';
                    if (vuln.severity === 'Unknown') {
                        severityClass = 'severity-unknown';
                    } else {
                        const severityValue = parseFloat(vuln.severity) || 0;
                        if (severityValue >= 9.0) {
                            severityClass = 'severity-critical';
                        } else if (severityValue >= 7.0) {
                            severityClass = 'severity-high';
                        } else if (severityValue >= 4.0) {
                            severityClass = 'severity-medium';
                        } else {
                            severityClass = 'severity-low';
                        }
                    }
                    return `
                        <tr>
                            <td>${vuln.port}</td>
                            <td>${vuln.service}</td>
                            <td>${vuln.cve}</td>
                            <td class="${severityClass}">${vuln.severity}</td>
                            <td>${vuln.description}</td>
                            <td><a href="${cveLink}" target="_blank">Details</a></td>
                        </tr>
                    `;
                }).join('');
            } else {
                cveTableBody.innerHTML = '<tr><td colspan="6">No vulnerabilities detected.</td></tr>';
            }
        })
        .catch(error => {
            console.error('Error loading vulnerabilities:', error);
            document.getElementById('cve-table-body').innerHTML = `<tr><td colspan="6">Error: ${error.message}</td></tr>`;
        });
}