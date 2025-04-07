// static/manage_cve.js
document.addEventListener('DOMContentLoaded', () => {
    console.log('Manage CVE page loaded, initializing...');
    setupCveForm();
});

function setupCveForm() {
    const form = document.getElementById('cve-form');
    const resultDiv = document.getElementById('cve-result');

    form.addEventListener('submit', (event) => {
        event.preventDefault(); // Prevent default form submission

        const formData = new FormData(form);
        const cveData = {
            cve_id: formData.get('cve_id'),
            command: formData.get('command'),
            output_match_word: formData.get('output_match_word'),
            patch_check: formData.get('patch_check') || '',
            patch_missing_match: formData.get('patch_missing_match') || '',
            description: formData.get('description'),
            requires_admin: formData.get('requires_admin') === 'on'
        };

        resultDiv.innerHTML = '<p>Adding CVE...</p>';

        fetch('/api/add-cve', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify(cveData)
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                resultDiv.innerHTML = `<p style="color: #4caf50;"><strong>Success:</strong> CVE ${cveData.cve_id} added successfully!</p>`;
                form.reset(); // Clear the form
            } else {
                resultDiv.innerHTML = `<p style="color: #f44336;"><strong>Error:</strong> ${data.error}</p>`;
            }
        })
        .catch(error => {
            console.error('Error adding CVE:', error);
            resultDiv.innerHTML = `<p style="color: #f44336;"><strong>Error:</strong> Failed to add CVE: ${error.message}</p>`;
        });
    });
}