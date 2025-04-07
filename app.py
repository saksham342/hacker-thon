from flask import Flask, render_template, jsonify, request, Response, url_for, flash, redirect, send_from_directory
import json
import subprocess
import os
import logging
import time
import ipaddress
from queue import Queue
import smtplib
import hashlib
import csv
import socket
from werkzeug.utils import secure_filename
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import sys
import zipfile
import re
import threading
import base64
from flask_socketio import SocketIO, emit

app = Flask(__name__)
socketio = SocketIO(app)

latest_scan_target = None
latest_nmap_command = None
latest_nuclei_command = None

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
CVE_JSON_PATH = os.path.join('static', 'cve_checks.json')

# Directory for custom templates
CUSTOM_TEMPLATES_DIR = 'custom_templates'
if not os.path.exists(CUSTOM_TEMPLATES_DIR):
    os.makedirs(CUSTOM_TEMPLATES_DIR)

# Predefined Nuclei template categories
PREDEFINED_CATEGORIES = [
    'cloud', 'code', 'dast', 'dns', 'file', 'headless', 'helpers',
    'http', 'javascript', 'network', 'passive', 'profiles', 'ssl', 'workflows'
]

# Initialize global variables
nmap_data = {"nmaprun": {"host": {}}}
scanned_ip = "Unknown IP"
log_messages = []
completed_processes = 0
agent_results = {}

# Storage for agent data
agent_data = {
    "privilege_escalation": {},
    "backdoor_reg_tamper": {},
    "scanned_credentials": {},
    "cve_detection": {},
    "service_changes": {},
    "user_account_backdoor_detection": {}
}

# Queue to store updates for SSE
update_queue = Queue()

# List to store unique IPs from agent POST requests
agent_ips = set()

# Function to check if a target is reachable on a specific port
def is_target_reachable(ip, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, int(port)))
        sock.close()
        return result == 0
    except Exception as e:
        logger.error(f"Error checking reachability for {ip}:{port}: {str(e)}")
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/manage-cve')
def manage_cve():
    return render_template('manage-cve.html')

@app.route('/ports')
def ports():
    return render_template('ports.html')

@app.route('/scanning')
def scanning():
    return render_template('scanning.html')

@app.route('/vulnerabilities')
def vulnerabilities():
    return render_template('vulnerabilities.html')

@app.route('/activity-log')
def activity_log():
    return render_template('activity-log.html')

@app.route('/apt')
def apt():
    return render_template('apt.html')

@app.route('/insider-threats')
def insider_threats():
    return render_template('insider_threats.html')

@app.route('/social-engineering-toolkit')
def social_engineering_toolkit_render():
    return render_template('social-engineering-toolkit.html')

@app.route('/zero-day')
def zero_days():
    return render_template('zero-day'
    '.html')

@app.route('/help')
def help():
    return send_from_directory('static', 'User_Guidelines.pdf')

@app.route('/api_docs')
def api_docs():
    return render_template('api_docs.html', byte=123)  # or any value
@app.route('/api/scan-data')
def get_scan_data():
    global scanned_ip
    logger.debug("Fetching scan data from latest JSON file")
    try:
        json_files = [f for f in os.listdir() if f.endswith('_output.json')]
        if not json_files:
            logger.warning("No JSON files found")
            return jsonify({"nmaprun": {"host": {}}})

        latest_json = max(json_files, key=os.path.getmtime)
        logger.debug(f"Loading data from {latest_json}")
        with open(latest_json, 'r') as f:
            nmap_data_local = json.load(f)

        if 'host' not in nmap_data_local['nmaprun']:
            return jsonify({"nmaprun": {"host": {}}})

        hosts = nmap_data_local['nmaprun']['host']
        if not isinstance(hosts, list):
            hosts = [hosts]

        for host in hosts:
            if 'address' in host:
                if isinstance(host['address'], list):
                    host['address'] = host['address'][0]
                scanned_ip = host['address']['@addr']
            else:
                host['address'] = {'@addr': scanned_ip}

            vulnerabilities = []
            if 'ports' in host and host['ports'] and 'port' in host['ports']:
                ports = host['ports']['port'] if isinstance(host['ports']['port'], list) else [host['ports']['port']]
                for port in ports:
                    if 'script' not in port:
                        continue

                    scripts = port['script'] if isinstance(port['script'], list) else [port['script']]
                    for script in scripts:
                        if script.get('@id') == 'vulners':
                            if 'table' in script:
                                cpe_tables = script['table'] if isinstance(script['table'], list) else [script['table']]
                                for cpe_table in cpe_tables:
                                    if 'table' in cpe_table:
                                        vuln_entries = cpe_table['table'] if isinstance(cpe_table['table'], list) else [cpe_table['table']]
                                        for vuln_entry in vuln_entries:
                                            if 'elem' not in vuln_entry:
                                                continue
                                            vuln_info = {elem['@key']: elem['#text'] for elem in vuln_entry['elem'] if '#text' in elem}
                                            cve_id = vuln_info.get('id', 'Unknown CVE')
                                            if not cve_id.startswith('CVE-'):
                                                continue
                                            severity = vuln_info.get('cvss', 'Unknown')
                                            description = f"Vulnerability {cve_id} detected by vulners script"
                                            vulnerabilities.append({
                                                'port': port['@portid'],
                                                'service': port['service']['@name'] if 'service' in port else 'Unknown',
                                                'cve': cve_id,
                                                'severity': severity,
                                                'description': description,
                                                'recommendation': 'Review the CVE details and apply patches or mitigations as needed.'
                                            })
                        elif 'elem' in script:
                            script_elems = script['elem'] if isinstance(script['elem'], list) else [script['elem']]
                            for elem in script_elems:
                                if isinstance(elem, dict) and elem.get('@key') == 'id' and elem.get('#text', '').startswith('CVE-'):
                                    cve_id = elem['#text']
                                    severity = 'Unknown'
                                    description = script.get('@output', 'No details available')
                                    vulnerabilities.append({
                                        'port': port['@portid'],
                                        'service': port['service']['@name'] if 'service' in port else 'Unknown',
                                        'cve': cve_id,
                                        'severity': severity,
                                        'description': description,
                                        'recommendation': 'Review the CVE details and apply patches or mitigations as needed.'
                                    })

            logger.debug(f"Total vulnerabilities for host {scanned_ip}: {len(vulnerabilities)}")
            host['vulnerabilities'] = vulnerabilities

        nmap_data_local['nmaprun']['host'] = hosts
        return jsonify(nmap_data_local)
    except Exception as e:
        logger.error(f"Error loading scan data: {str(e)}")
        return jsonify({"nmaprun": {"host": {}}}), 500


def is_yaml_template(template):
    return template.endswith('.yaml') or template.endswith('.yml')


@app.route('/api/scan', methods=['POST'])
def run_scan():
    global nmap_data, scanned_ip, completed_processes, latest_scan_target, latest_nmap_command, latest_nuclei_command
    data = request.json
    target = data.get('target', '')

    if not target:
        logger.error("No target provided in request")
        return jsonify({'error': 'No target provided'}), 400

    # Store the target and command for streaming
    latest_scan_target = target
    latest_nmap_command = ['nmap', '-sV','-T4', '-oX', f"{target.replace('/', '_').replace(':', '_')}_output.xml", target]
    latest_nuclei_command = None  # Reset Nuclei command

    safe_target = target.replace('/', '_').replace(':', '_')
    xml_output = f"{safe_target}_output.xml"
    json_output = f"{safe_target}_output.json"

    logger.info(f"Starting Nmap scan for target: {target}")
    try:
        for file in [xml_output, json_output]:
            if os.path.exists(file):
                logger.debug(f"Removing existing file: {file}")
                os.remove(file)

        nmap_command = latest_nmap_command
        logger.debug(f"Executing Nmap command: {' '.join(nmap_command)}")
        process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                logger.debug(f"Nmap output: {output.strip()}")
                log_messages.append(output.strip())
        stderr = process.stderr.read()
        if stderr:
            logger.error(f"Nmap stderr: {stderr.strip()}")
            log_messages.append(stderr.strip())

        return_code = process.poll()
        if return_code != 0:
            logger.error(f"Nmap failed with return code {return_code}: {stderr}")
            return jsonify({'error': f"Nmap failed with return code {return_code}: {stderr}"}), 500

        if not os.path.exists(xml_output):
            logger.error("Nmap did not generate output file")
            return jsonify({'error': 'Nmap did not generate output file'}), 500

        logger.debug(f"Converting {xml_output} to {json_output} using xml2json.py")
        result = subprocess.run(['python3', 'xml2json.py', xml_output, json_output], capture_output=True, text=True)
        if result.returncode != 0:
            logger.error(f"xml2json.py failed: {result.stderr}")
            return jsonify({'error': f"Failed to convert XML to JSON: {result.stderr}"}), 500

        if not os.path.exists(json_output):
            logger.error(f"{json_output} was not created after conversion")
            return jsonify({'error': f"Failed to convert XML to JSON: {json_output} not found"}), 500

        logger.debug(f"Loading new {json_output}")
        with open(json_output, 'r') as f:
            nmap_data = json.load(f)

        if 'host' in nmap_data['nmaprun']:
            host = nmap_data['nmaprun']['host']
            if isinstance(host, list):
                if len(host) == 0:
                    logger.warning("No hosts found in scan result")
                    return jsonify({'error': 'No hosts found in scan result'}), 404
                host = host[0]
                nmap_data['nmaprun']['host'] = host

            if 'address' in host:
                if isinstance(host['address'], list):
                    scanned_ip = host['address'][0]['@addr']
                else:
                    scanned_ip = host['address']['@addr']
            else:
                scanned_ip = target

        completed_processes += 1
        logger.info(f"Scan completed successfully for IP: {scanned_ip}")
        return jsonify({'status': 'Scan completed', 'ip': scanned_ip})
    except subprocess.CalledProcessError as e:
        logger.error(f"Subprocess error: {str(e)}")
        return jsonify({'error': f"Subprocess error: {str(e)}"}), 500
    except Exception as e:
        logger.error(f"Unexpected error during scan: {str(e)}")
        return jsonify({'error': f"Unexpected error: {str(e)}"}), 500

@app.route('/api/get-ips')
def get_ips():
    subnet = request.args.get('subnet', '')
    if not subnet:
        return jsonify({'error': 'No subnet provided'}), 400

    try:
        network = ipaddress.ip_network(subnet, strict=False)
        ips = [str(ip) for ip in network.hosts()]
        return jsonify({'ips': ips})
    except ValueError as e:
        logger.error(f"Invalid subnet: {subnet}, error: {str(e)}")
        return jsonify({'error': 'Invalid subnet format'}), 400

@app.route('/api/upload-template', methods=['POST'])
def upload_template():
    try:
        if 'template' not in request.files:
            logger.error("No file part in the request")
            return jsonify({'success': False, 'error': 'No file part in the request'}), 400

        file = request.files['template']
        if file.filename == '':
            logger.error("No file selected")
            return jsonify({'success': False, 'error': 'No file selected'}), 400

        if not (file.filename.endswith('.yaml') or file.filename.endswith('.zip')):
            logger.error("Invalid file type, only .yaml or .zip files are allowed")
            return jsonify({'success': False, 'error': 'Invalid file type, only .yaml or .zip files are allowed'}), 400

        if file.filename.endswith('.yaml'):
            filename = secure_filename(file.filename)
            file_path = os.path.join(CUSTOM_TEMPLATES_DIR, filename)
            file.save(file_path)
            logger.info(f"Custom template uploaded: {filename}")
            log_messages.append(f"Custom template uploaded: {filename}")
            return jsonify({'success': True, 'message': f'Template {filename} uploaded successfully'})
        else:  # .zip file
            zip_filename = secure_filename(file.filename)
            zip_path = os.path.join(CUSTOM_TEMPLATES_DIR, zip_filename)
            file.save(zip_path)

            # Extract the .zip file
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                extracted_files = []
                for zip_info in zip_ref.infolist():
                    if zip_info.filename.endswith('.yaml'):
                        # Extract the file with a secure name
                        extracted_filename = secure_filename(zip_info.filename)
                        extracted_path = os.path.join(CUSTOM_TEMPLATES_DIR, extracted_filename)
                        with zip_ref.open(zip_info) as source, open(extracted_path, 'wb') as target:
                            target.write(source.read())
                        extracted_files.append(extracted_filename)
                        logger.info(f"Extracted template: {extracted_filename}")
                        log_messages.append(f"Extracted template: {extracted_filename}")

            # Remove the .zip file after extraction
            os.remove(zip_path)
            logger.info(f"Removed temporary zip file: {zip_filename}")
            log_messages.append(f"Removed temporary zip file: {zip_filename}")

            if not extracted_files:
                logger.error("No .yaml files found in the uploaded .zip file")
                return jsonify({'success': False, 'error': 'No .yaml files found in the uploaded .zip file'}), 400

            return jsonify({'success': True, 'message': f'Extracted {len(extracted_files)} .yaml files from {zip_filename}'})
    except Exception as e:
        logger.error(f"Error uploading template: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/get-template-categories', methods=['GET'])
def get_template_categories():
    try:
        custom_templates = []
        for filename in os.listdir(CUSTOM_TEMPLATES_DIR):
            if filename.endswith('.yaml'):
                file_path = os.path.join(CUSTOM_TEMPLATES_DIR, filename)
                creation_time = datetime.fromtimestamp(os.path.getctime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
                custom_templates.append({
                    "name": filename,
                    "date": creation_time
                })
        return jsonify({
            'custom': custom_templates
        })
    except Exception as e:
        logger.error(f"Error fetching template categories: {str(e)}")
        return jsonify({'error': str(e)}), 500

def is_valid_ip_or_domain(target):
    try:
        ipaddress.ip_address(target)
        return True, target
    except ValueError:
        domain_pattern = re.compile(
            r'^(https?://)?(?:[a-zA-Z0-9-]{0,62}[a-zA-Z0-9]\.)+[a-zA-Z]{2,63}(?::\d+)?$'
        )
        if domain_pattern.match(target):
            try:
                # Strip http:// or https:// for resolution
                domain = target.replace('http://', '').replace('https://', '').split(':')[0]
                ip = socket.gethostbyname(domain)
                logger.info(f"Resolved domain {domain} to IP {ip}")
                return True, ip
            except socket.gaierror:
                logger.error(f"Could not resolve domain: {target}")
                return False, None
        else:
            logger.error(f"Invalid IP or domain: {target}")
            return False, None



@app.route('/api/delete-template', methods=['POST'])
def delete_template():
    try:
        data = request.get_json()
        template_name = data.get('template_name')

        if not template_name:
            logger.error("No template name provided in request")
            return jsonify({'success': False, 'error': 'Template name is required'}), 400

        template_path = os.path.join(CUSTOM_TEMPLATES_DIR, template_name)
        if not os.path.exists(template_path):
            logger.error(f"Template {template_name} not found")
            return jsonify({'success': False, 'error': 'Template not found'}), 404

        os.remove(template_path)
        logger.info(f"Template {template_name} deleted successfully")
        log_messages.append(f"Template {template_name} deleted successfully")
        return jsonify({'success': True, 'message': f'Template {template_name} deleted successfully'})
    except Exception as e:
        logger.error(f"Error deleting template: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/run-generic-nuclei-scan', methods=['POST'])
def run_generic_nuclei_scan():
    global completed_processes, latest_scan_target, latest_nmap_command, latest_nuclei_command
    try:
        data = request.get_json()
        if not data:
            logger.error("No data provided in request")
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        target = data.get('ip')
        ports = data.get('ports', [])  # List of ports to scan (can be empty)

        if not target:
            logger.error("IP/Domain missing in request")
            return jsonify({'success': False, 'error': 'IP/Domain is required'}), 400

        # Parse the target to extract the IP or domain
        cleaned_target = target
        if target.startswith('http://'):
            cleaned_target = target[len('http://'):]
        elif target.startswith('https://'):
            cleaned_target = target[len('https://'):]
        else:
            logger.error(f"Target {target} must include protocol (http:// or https://)")
            return jsonify({'success': False, 'error': 'Target must include protocol (http:// or https://)'}), 400

        # Remove trailing slashes and any port/path
        cleaned_target = cleaned_target.split('/')[0].split(':')[0]

        # Validate the cleaned IP or domain
        is_valid, resolved_ip = is_valid_ip_or_domain(cleaned_target)
        if not is_valid:
            logger.error(f"Invalid IP or domain: {cleaned_target}")
            return jsonify({'success': False, 'error': 'Invalid IP or domain'}), 400

        # Use the original target as provided for the Nuclei scan
        target_url = target.rstrip('/')  # Remove trailing slashes for consistency
        if not target_url.startswith(('http://', 'https://')):
            logger.error(f"Target {target} must include protocol (http:// or https://)")
            return jsonify({'success': False, 'error': 'Target must include protocol (http:// or https://)'}), 400

        # If ports are provided, append them to the target_url
        if ports:
            port = ports[0]  # Use the first port if multiple are provided
            # Remove any existing port in the target_url, then append the new port
            protocol_and_domain = target_url.split(':')[0] + ':' + target_url.split(':')[1]
            target_url = f"{protocol_and_domain}:{port}"

        # Check if Nuclei is installed
        result = subprocess.run(['nuclei', '-version'], capture_output=True, text=True)
        if result.returncode != 0:
            logger.error("Nuclei is not installed or not found in PATH")
            log_messages.append("Nuclei is not installed or not found in PATH")
            return jsonify({'success': False, 'error': 'Nuclei is not installed or not found in PATH'}), 500

        # Construct the generic Nuclei command
        nuclei_command = [
            'nuclei',
            '-u', target_url,
            '-jsonl',
            '-c', '20'
        ]

        # Store the target and command for streaming
        latest_scan_target = target_url
        latest_nmap_command = None
        latest_nuclei_command = nuclei_command

        logger.debug(f"Executing generic Nuclei command: {' '.join(nuclei_command)}")
        log_messages.append(f"Running generic Nuclei scan on {target_url}")
        process = subprocess.run(nuclei_command, capture_output=True, text=True)

        if process.stdout:
            logger.debug(f"Nuclei stdout: {process.stdout}")
            log_messages.append(f"Nuclei stdout: {process.stdout}")
        else:
            logger.info(f"No stdout from Nuclei for {target_url}")
            log_messages.append(f"No stdout from Nuclei for {target_url}")

        if process.stderr:
            logger.error(f"Nuclei stderr: {process.stderr}")
            log_messages.append(f"Nuclei stderr: {process.stderr}")
        else:
            logger.debug("No stderr from Nuclei")
            log_messages.append("No stderr from Nuclei")

        if process.returncode != 0:
            logger.error(f"Nuclei command failed with return code {process.returncode}")
            log_messages.append(f"Nuclei command failed with return code {process.returncode}")
            return jsonify({'success': False, 'error': f'Nuclei command failed with return code {process.returncode}'}), 500

        # Parse results from stdout
        results = []
        if process.stdout:
            lines = process.stdout.splitlines()
            for line in lines:
                if line.strip():
                    try:
                        result = json.loads(line.strip())
                        matched_at = result.get('matched-at', '')
                        detected_port = matched_at.split(':')[-1] if ':' in matched_at else (ports[0] if ports else 'N/A')
                        formatted_result = {
                            'template': result.get('template-id', 'N/A'),
                            'vulnerability': result.get('info', {}).get('name', 'N/A'),
                            'severity': result.get('info', {}).get('severity', 'info'),
                            'description': result.get('info', {}).get('description', 'No description available'),
                            'port': detected_port,
                            'target': target,
                            'matched': matched_at or 'N/A'
                        }
                        results.append(formatted_result)
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse Nuclei result line: {line}, error: {str(e)}")
                        log_messages.append(f"Failed to parse Nuclei result: {str(e)}")

        if results:
            logger.info(f"Found {len(results)} results for {target_url} with generic scan")
            log_messages.append(f"Found {len(results)} results for {target_url} with generic scan")
        else:
            logger.info(f"No results captured for {target_url} with generic scan")
            log_messages.append(f"No results captured for {target_url} with generic scan")

        completed_processes += 1
        logger.info(f"Generic Nuclei scan completed for target: {target}. Total results: {len(results)}")
        log_messages.append(f"Generic Nuclei scan completed for target: {target}. Total results: {len(results)}")
        return jsonify({'success': True, 'results': results})
    except Exception as e:
        logger.error(f"Error during generic Nuclei scan: {str(e)}")
        log_messages.append(f"Error during generic Nuclei scan: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500



@app.route('/api/run-nuclei-scan', methods=['POST'])
def run_nuclei_scan():
    global completed_processes, latest_scan_target, latest_nmap_command, latest_nuclei_command
    try:
        data = request.get_json()
        if not data:
            logger.error("No data provided in request")
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        target = data.get('ip')
        ports = data.get('ports', [])  # List of ports to scan (can be empty)
        templates = data.get('templates', [])

        if not target or not templates:
            logger.error("IP/Domain or templates missing in request")
            return jsonify({'success': False, 'error': 'IP/Domain and templates are required'}), 400

        # Parse the target to extract the IP or domain
        # Remove protocol (http:// or https://) and any trailing slashes
        cleaned_target = target
        if target.startswith('http://'):
            cleaned_target = target[len('http://'):]
        elif target.startswith('https://'):
            cleaned_target = target[len('https://'):]
        else:
            logger.error(f"Target {target} must include protocol (http:// or https://)")
            return jsonify({'success': False, 'error': 'Target must include protocol (http:// or https://)'}), 400

        # Remove trailing slashes and any port/path
        cleaned_target = cleaned_target.split('/')[0].split(':')[0]

        # Validate the cleaned IP or domain
        is_valid, resolved_ip = is_valid_ip_or_domain(cleaned_target)
        if not is_valid:
            logger.error(f"Invalid IP or domain: {cleaned_target}")
            return jsonify({'success': False, 'error': 'Invalid IP or domain'}), 400

        # Use the original target as provided for the Nuclei scan
        target_url = target.rstrip('/')  # Remove trailing slashes for consistency
        if not target_url.startswith(('http://', 'https://')):
            logger.error(f"Target {target} must include protocol (http:// or https://)")
            return jsonify({'success': False, 'error': 'Target must include protocol (http:// or https://)'}), 400

        # If ports are provided, append them to the target_url
        if ports:
            port = ports[0]  # Use the first port if multiple are provided
            # Remove any existing port in the target_url, then append the new port
            protocol_and_domain = target_url.split(':')[0] + ':' + target_url.split(':')[1]
            target_url = f"{protocol_and_domain}:{port}"

        # Check if Nuclei is installed
        result = subprocess.run(['nuclei', '-version'], capture_output=True, text=True)
        if result.returncode != 0:
            logger.error("Nuclei is not installed or not found in PATH")
            log_messages.append("Nuclei is not installed or not found in PATH")
            return jsonify({'success': False, 'error': 'Nuclei is not installed or not found in PATH'}), 500

        # Validate and prepare the list of template paths
        template_paths = []
        for template in templates:
            if not is_yaml_template(template):
                logger.error(f"Invalid template format: {template}. Only .yaml files are supported.")
                log_messages.append(f"Invalid template format: {template}. Only .yaml files are supported.")
                continue

            template_path = os.path.join(CUSTOM_TEMPLATES_DIR, template)
            if not os.path.exists(template_path):
                logger.error(f"Template {template} not found at {template_path}")
                log_messages.append(f"Template {template} not found at {template_path}")
                continue

            template_paths.append(template_path)

        if not template_paths:
            logger.error("No valid templates found to run the scan")
            return jsonify({'success': False, 'error': 'No valid templates found to run the scan'}), 400

        # Construct a single Nuclei command with all templates
        rate_limit = 50
        nuclei_command = [
            'nuclei',
            '-u', target_url,
            '-jsonl',
            '-rate-limit', str(rate_limit),
            '-v',
            '-timeout', '10',
            '-retries', '3',
            '-c', '20'
        ]

        # Add all templates to the command
        for template_path in template_paths:
            nuclei_command.extend(['-t', template_path])

        # Store the target and command for streaming
        latest_scan_target = target_url
        latest_nmap_command = None
        latest_nuclei_command = nuclei_command

        logger.info(f"Using custom templates: {', '.join(template_paths)}")
        logger.debug(f"Executing Nuclei command: {' '.join(nuclei_command)}")
        log_messages.append(f"Running Nuclei scan on {target_url} with templates {', '.join(templates)}")
        process = subprocess.run(nuclei_command, capture_output=True, text=True)

        if process.stdout:
            logger.debug(f"Nuclei stdout: {process.stdout}")
            log_messages.append(f"Nuclei stdout: {process.stdout}")
        else:
            logger.info(f"No stdout from Nuclei for {target_url} with templates {', '.join(templates)}")
            log_messages.append(f"No stdout from Nuclei for {target_url} with templates {', '.join(templates)}")

        if process.stderr:
            logger.error(f"Nuclei stderr: {process.stderr}")
            log_messages.append(f"Nuclei stderr: {process.stderr}")
        else:
            logger.debug("No stderr from Nuclei")
            log_messages.append("No stderr from Nuclei")

        if process.returncode != 0:
            logger.error(f"Nuclei command failed with return code {process.returncode}")
            log_messages.append(f"Nuclei command failed with return code {process.returncode}")
            return jsonify({'success': False, 'error': f'Nuclei command failed with return code {process.returncode}'}), 500

        # Parse results from stdout
        results = []
        if process.stdout:
            lines = process.stdout.splitlines()
            for line in lines:
                if line.strip():
                    try:
                        result = json.loads(line.strip())
                        matched_at = result.get('matched-at', '')
                        detected_port = matched_at.split(':')[-1] if ':' in matched_at else (ports[0] if ports else 'N/A')
                        formatted_result = {
                            'template': result.get('template-id', 'N/A'),
                            'vulnerability': result.get('info', {}).get('name', 'N/A'),
                            'severity': result.get('info', {}).get('severity', 'info'),
                            'description': result.get('info', {}).get('description', 'No description available'),
                            'port': detected_port,
                            'target': target,
                            'matched': matched_at or 'N/A'
                        }
                        results.append(formatted_result)
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse Nuclei result line: {line}, error: {str(e)}")
                        log_messages.append(f"Failed to parse Nuclei result: {str(e)}")

        if results:
            logger.info(f"Found {len(results)} results for {target_url} with templates {', '.join(templates)}")
            log_messages.append(f"Found {len(results)} results for {target_url} with templates {', '.join(templates)}")
        else:
            logger.info(f"No results captured for {target_url} with templates {', '.join(templates)}")
            log_messages.append(f"No results captured for {target_url} with templates {', '.join(templates)}")

        completed_processes += 1
        logger.info(f"Nuclei scan completed for target: {target}. Total results: {len(results)}")
        log_messages.append(f"Nuclei scan completed for target: {target}. Total results: {len(results)}")
        return jsonify({'success': True, 'results': results})
    except Exception as e:
        logger.error(f"Error during Nuclei scan: {str(e)}")
        log_messages.append(f"Error during Nuclei scan: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/activity-log')
def activity_log_stream():
    def generate():
        if not latest_scan_target:
            yield f"data: Waiting for a scan to start...\n\n"
            return

        if latest_nmap_command:
            yield f"data: Starting Nmap scan for {latest_scan_target}\n\n"
            process = subprocess.Popen(
                latest_nmap_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            for line in process.stdout:
                yield f"data: {line.strip()}\n\n"
            process.wait()
            if process.returncode != 0:
                yield f"data: Nmap failed with return code {process.returncode}\n\n"

        if latest_nuclei_command:
            yield f"data: Starting Nuclei scan for {latest_scan_target}\n\n"
            process = subprocess.Popen(
                latest_nuclei_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            for line in process.stdout:
                yield f"data: {line.strip()}\n\n"
            process.wait()
            if process.returncode != 0:
                yield f"data: Nuclei failed with return code {process.returncode}\n\n"

        yield f"data: Scan completed for {latest_scan_target}\n\n"

    return Response(generate(), mimetype='text/event-stream')

@app.route('/api/completed-processes')
def get_completed_processes():
    logger.debug(f"Returning completed processes: {completed_processes}")
    return jsonify({'completed_processes': completed_processes})

@app.route('/alert', methods=['POST'])
def receive_alert():
    data = request.get_json()
    service = data.get('service')
    attacker_ip = data.get('attacker_ip')
    timestamp = data.get('timestamp')
    hostname = data.get('hostname')

    if not all([service, attacker_ip, timestamp, hostname]):
        logger.error("Incomplete data in alert request")
        return jsonify({'error': 'Missing required fields'}), 400

    target_ip = request.remote_addr
    agent_type = "ssh-intrusion"

    if target_ip not in agent_results:
        agent_results[target_ip] = {}
    if agent_type not in agent_results[target_ip]:
        agent_results[target_ip][agent_type] = []

    alert_data = {
        "service": service,
        "attacker_ip": attacker_ip,
        "timestamp": timestamp,
        "hostname": hostname
    }
    agent_results[target_ip][agent_type].append(alert_data)

    logger.info(f"Received SSH intrusion alert from {target_ip} for attacker {attacker_ip}")
    log_messages.append(f"SSH intrusion alert from {target_ip} for attacker {attacker_ip}")
    global completed_processes
    completed_processes += 1 
    return jsonify({'status': 'Alert received'})

@app.route('/api/privilege-escalation', methods=['POST', 'GET'])
def privilege_escalation():
    if request.method == 'POST':
        data = request.get_json()
        target_ip = data.get('target_ip', request.remote_addr)
        logger.info(f"Received POST request to /api/privilege-escalation from {target_ip} with data: {json.dumps(data, indent=2)}")
        agent_data["privilege_escalation"][target_ip] = data
        agent_ips.add(target_ip)
        print(f"Privilege Escalation from {target_ip}: {data}")
        update_queue.put({"endpoint": "privilege-escalation", "target_ip": target_ip, "data": data})
        return jsonify({'status': 'Results received'})
    else:  # GET
        target_ip = request.args.get('target_ip', '')
        result = agent_data["privilege_escalation"].get(target_ip, {})
        logger.debug(f"GET request for /api/privilege-escalation, target_ip={target_ip}, returning: {json.dumps(result, indent=2)}")
        return jsonify(result)

@app.route('/api/backdoor-reg-tamper', methods=['POST', 'GET'])
def backdoor_reg_tamper():
    if request.method == 'POST':
        data = request.get_json()
        target_ip = data.get('target_ip', request.remote_addr)
        agent_data["backdoor_reg_tamper"][target_ip] = data
        agent_ips.add(target_ip)
        logger.info(f"Backdoor registry tamper data received from {target_ip}")
        print(f"Backdoor Registry Tamper from {target_ip}: {data}")
        update_queue.put({"endpoint": "backdoor-reg-tamper", "target_ip": target_ip, "data": data})
        return jsonify({'status': 'Results received'})
    else:  # GET
        target_ip = request.args.get('target_ip', '')
        return jsonify(agent_data["backdoor_reg_tamper"].get(target_ip, {}))

@app.route('/api/scanned-credentials', methods=['POST', 'GET'])
def scanned_credentials():
    if request.method == 'POST':
        data = request.get_json()
        target_ip = data.get('target_ip', request.remote_addr)
        agent_data["scanned_credentials"][target_ip] = data
        agent_ips.add(target_ip)
        logger.info(f"Scanned credentials data received from {target_ip}")
        print(f"Scanned Credentials from {target_ip}: {data}")
        update_queue.put({"endpoint": "scanned-credentials", "target_ip": target_ip, "data": data})
        return jsonify({'status': 'Results received'})
    else:  # GET
        target_ip = request.args.get('target_ip', '')
        return jsonify(agent_data["scanned_credentials"].get(target_ip, {}))

@app.route('/api/cve-detection', methods=['POST', 'GET'])
def cve_detection():
    if request.method == 'POST':
        data = request.get_json()
        target_ip = data.get('target_ip', request.remote_addr)
        agent_data["cve_detection"][target_ip] = data
        agent_ips.add(target_ip) 
        logger.info(f"CVE detection data received from {target_ip}")
        print(f"CVE Detection from {target_ip}: {data}")
        update_queue.put({"endpoint": "cve-detection", "target_ip": target_ip, "data": data})
        return jsonify({'status': 'Results received'})
    else:  # GET
        target_ip = request.args.get('target_ip', '')
        return jsonify(agent_data["cve_detection"].get(target_ip, {}))

@app.route('/api/service-changes', methods=['POST', 'GET'])
def service_changes():
    if request.method == 'POST':
        data = request.get_json()
        target_ip = data.get('target_ip', request.remote_addr)
        agent_data["service_changes"][target_ip] = data
        agent_ips.add(target_ip)
        logger.info(f"Service changes data received from {target_ip}")
        print(f"Service Changes from {target_ip}: {data}")
        update_queue.put({"endpoint": "service-changes", "target_ip": target_ip, "data": data})
        return jsonify({'status': 'Results received'})
    else:  # GET
        target_ip = request.args.get('target_ip', '')
        return jsonify(agent_data["service_changes"].get(target_ip, {}))

@app.route('/api/user-account-backdoor-detection', methods=['POST', 'GET'])
def user_account_backdoor_detection():
    if request.method == 'POST':
        data = request.get_json()
        target_ip = data.get('target_ip', request.remote_addr)
        agent_data["user_account_backdoor_detection"][target_ip] = data
        agent_ips.add(target_ip)
        logger.info(f"User account backdoor detection data received from {target_ip}")
        print(f"User Account Backdoor Detection from {target_ip}: {data}")
        update_queue.put({"endpoint": "user-account-backdoor-detection", "target_ip": target_ip, "data": data})
        return jsonify({'status': 'Results received'})
    else:  # GET
        target_ip = request.args.get('target_ip', '')
        return jsonify(agent_data["user_account_backdoor_detection"].get(target_ip, {}))

@app.route('/api/get-agent-ips', methods=['GET'])
def get_agent_ips():
    return jsonify({'ips': list(agent_ips)})

@app.route('/api/agent-updates')
def agent_updates():
    def stream():
        while True:
            try:
                update = update_queue.get(timeout=30)
                yield f"data: {json.dumps(update)}\n\n"
            except Queue.Empty:
                yield f"data: {json.dumps({'event': 'ping'})}\n\n"
    return Response(stream(), mimetype='text/event-stream')

@app.route('/api/get-agent-results', methods=['GET'])
def get_agent_results():
    target_ip = request.args.get('target_ip')
    agent_type = request.args.get('agent_type')

    if not target_ip or not agent_type:
        return jsonify({'error': 'Missing target_ip or agent_type'}), 400

    if target_ip in agent_results and agent_type in agent_results[target_ip]:
        return jsonify(agent_results[target_ip][agent_type])
    else:
        return jsonify({'error': 'No results found'}), 404

@app.route('/api/add-cve', methods=['POST'])
def add_cve():
    try:
        new_cve = request.get_json()
        if not new_cve:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        required_fields = ['cve_id', 'command', 'output_match_word', 'description']
        for field in required_fields:
            if field not in new_cve or not new_cve[field]:
                return jsonify({'success': False, 'error': f'Missing or empty required field: {field}'}), 400

        if not os.path.exists(CVE_JSON_PATH):
            return jsonify({'success': False, 'error': "CVE JSON file 'cve_checks.json' not found in static directory."}), 500

        with open(CVE_JSON_PATH, 'r') as f:
            cve_data = json.load(f)

        if any(cve['cve_id'] == new_cve['cve_id'] for cve in cve_data):
            return jsonify({'success': False, 'error': f"CVE ID {new_cve['cve_id']} already exists."}), 400

        backup_path = os.path.join('static', 'cve_checks_backup.json')
        with open(CVE_JSON_PATH, 'r') as f, open(backup_path, 'w') as backup:
            backup.write(f.read())

        cve_data.append(new_cve)

        with open(CVE_JSON_PATH, 'w') as f:
            json.dump(cve_data, f, indent=4)

        return jsonify({'success': True, 'message': f"CVE {new_cve['cve_id']} added successfully"})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/get-cve-checks', methods=['GET'])
def get_cve_checks():
    try:
        if not os.path.exists(CVE_JSON_PATH):
            return jsonify({'error': "CVE JSON file 'cve_checks.json' not found in static directory."}), 404

        with open(CVE_JSON_PATH, 'r') as f:
            cve_data = json.load(f)

        return jsonify(cve_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

#ruskin code from here

app.secret_key = 'replace-with-a-secret-key'
CONFIG = {
    "gmail_user": "rockthakur38@gmail.com",
    "gmail_password": "wmsp cfzo dedj rznv",
    "phishing_domain": "http://192.168.1.139:5000",
    "redirect_url": "https://www.youtube.com/watch?v=02Qigrmx3mA",
    "log_file": "phishing_logs.json",
    "employee_csv": "employees.csv",
    "tracking_db": "tracking_db.json",
    "email_body_file": "custom_email_body.txt"
}

DEFAULT_EMAIL_BODY = """Dear {name},

We noticed suspicious activity in your account.
Please verify your login details:
{phishing_url}

Best regards,
Information Security Team
"""

def load_custom_email_body():
    if os.path.exists(CONFIG["email_body_file"]):
        with open(CONFIG["email_body_file"], 'r') as f:
            return f.read()
    return DEFAULT_EMAIL_BODY

def save_custom_email_body(body):
    with open(CONFIG["email_body_file"], 'w') as f:
        f.write(body)

def read_employees_from_csv():
    try:
        with open(CONFIG["employee_csv"], 'r', newline='') as csvfile:
            return list(csv.DictReader(csvfile))
    except Exception as e:
        print(f"Error reading CSV: {str(e)}")
        return []

def write_employees_to_csv(employees):
    try:
        with open(CONFIG["employee_csv"], 'w', newline='') as csvfile:
            if employees:
                fieldnames = employees[0].keys()
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(employees)
    except Exception as e:
        print(f"Error writing CSV: {str(e)}")

def generate_tracking_id(email):
    date_part = datetime.now().strftime("%Y%m%d")
    hash_part = hashlib.sha256(email.encode()).hexdigest()[:12]
    return f"{hash_part}{date_part}"

def send_phishing_emails(employees):
    tracking_data = []
    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(CONFIG["gmail_user"], CONFIG["gmail_password"])
        custom_body = load_custom_email_body()
        for emp in employees:
            tracking_id = generate_tracking_id(emp['email'])
            phishing_url = f"{CONFIG['phishing_domain']}/api/click/{tracking_id}"
            tracking_data.append({
                "tracking_id": tracking_id,
                "name": emp['name'],
                "email": emp['email']
            })
            msg = MIMEMultipart()
            msg['From'] = f"Security Team <{CONFIG['gmail_user']}>"
            msg['To'] = emp['email']
            msg['Subject'] = "Important: Account Security Alert"
            body = custom_body.format(name=emp['name'], phishing_url=phishing_url)
            msg.attach(MIMEText(body, 'plain'))
            server.sendmail(CONFIG["gmail_user"], emp['email'], msg.as_string())
            print(f"Sent to {emp['email']}")
        with open(CONFIG["tracking_db"], 'w') as f:
            json.dump(tracking_data, f, indent=2)
        server.quit()
        return True
    except Exception as e:
        print(f"Email error: {str(e)}")
        return False

@app.route('/api/click/<tracking_id>')
def track_click(tracking_id):
    # Load tracking database
    try:
        with open(CONFIG["tracking_db"], 'r') as f:
            tracking_db = json.load(f)
    except Exception as e:
        print(f"Error loading tracking_db.json: {str(e)}")
        return redirect(CONFIG["redirect_url"])  # Still redirect even if db fails

    # Find employee by tracking_id
    employee = next((item for item in tracking_db if item['tracking_id'] == tracking_id), None)
    if not employee:
        print(f"No employee found for tracking_id: {tracking_id}")

    # Create log entry
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "tracking_id": tracking_id,
        "name": employee['name'] if employee else "Unknown",
        "email": employee['email'] if employee else "Unknown",
        "ip_address": request.remote_addr,
        "user_agent": request.headers.get('User-Agent')
    }
    print(f"Log entry created: {log_entry}")  # Debug log entry

    # Save to phishing_logs.json
    try:
        logs = []
        log_file = CONFIG["log_file"]  # e.g., "phishing_logs.json"
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                logs = json.load(f)
        logs.append(log_entry)
        with open(log_file, 'w') as f:
            json.dump(logs, f, indent=2)
        print(f"Successfully saved log to {log_file}")
    except Exception as e:
        print(f"Error saving to {log_file}: {str(e)}")

    return redirect(CONFIG["redirect_url"])

@app.route('/social-engineering-toolkit', methods=['GET'])
def social_engineering_toolkit():
    employees = read_employees_from_csv()
    print(f"Employees loaded on page load: {employees}")
    current_body = load_custom_email_body()
    try:
        with open(CONFIG["log_file"], 'r') as f:
            logs = json.load(f)
        print(f"Logs loaded on page load: {logs}")  # Debug to confirm logs
    except Exception:
        logs = []
    return render_template('social-engineering-toolkit.html', employees=employees, current_body=current_body, logs=logs)

@app.route('/social-engineering-toolkit/edit-email-body', methods=['POST'])
def edit_email_body():
    new_body = request.form.get('email_body')
    if new_body:
        save_custom_email_body(new_body)
        return jsonify({"success": True, "message": "Email body updated."})
    return jsonify({"success": False, "message": "No email body provided."}), 400

@app.route('/social-engineering-toolkit/add-employee', methods=['POST'])
def add_employee():
    name = request.form.get('name')
    email = request.form.get('email')
    if name and email:
        employees = read_employees_from_csv()
        employees.append({'name': name, 'email': email})
        write_employees_to_csv(employees)
        return jsonify({"success": True, "message": "Employee added.", "employee": {"name": name, "email": email}})
    return jsonify({"success": False, "message": "Both name and email are required."}), 400

@app.route('/social-engineering-toolkit/get-logs', methods=['GET'])
def get_logs():
    try:
        with open(CONFIG["log_file"], 'r') as f:
            logs = json.load(f)
    except Exception:
        logs = []
    return jsonify({"success": True, "logs": logs})

@app.route('/social-engineering-toolkit/get-employees', methods=['GET'])
def get_employees():
    employees = read_employees_from_csv()
    return jsonify({"success": True, "employees": employees})

@app.route('/social-engineering-toolkit/delete-employee', methods=['POST'])
def delete_employee():
    email = request.args.get('email')
    if email:
        employees = read_employees_from_csv()
        employees = [emp for emp in employees if emp['email'] != email]
        write_employees_to_csv(employees)
        return jsonify({"success": True, "message": "Employee deleted."})
    return jsonify({"success": False, "message": "Email not provided."}), 400

@app.route('/social-engineering-toolkit/start-campaign', methods=['POST'])
def start_campaign():
    employees = read_employees_from_csv()
    if not employees:
        return jsonify({"success": False, "message": "No employee data found."}), 400
    if send_phishing_emails(employees):
        try:
            with open(CONFIG["log_file"], 'r') as f:
                logs = json.load(f)
        except Exception:
            logs = []
        return jsonify({"success": True, "message": f"Phishing campaign started for {len(employees)} employees.", "logs": logs})
    return jsonify({"success": False, "message": "Failed to send phishing emails."}), 500




@app.route('/api/send-email-for-simulation-from', methods=['POST'])
def send_email_for_simulation():
    try:
        # Extract JSON data
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "No JSON data provided"}), 400
        
        from_email = data.get("from")
        to_email = data.get("to")
        subject = data.get("subject")
        body = data.get("body")
        
        # Validate required fields
        if not all([from_email, to_email, subject, body]):
            return jsonify({"success": False, "message": "Missing required fields (from, to, subject, body)"}), 400
        
        # Construct the swaks command
        swaks_cmd = [
            "swaks",
            "--to", to_email,
            "--from", from_email,
            "--server", "localhost",
            "--port", "25",
            "--header", f"Subject: {subject}",
            "--body", body
        ]
        
        # Run the swaks command
        try:
            result = subprocess.run(
                swaks_cmd,
                check=True,
                capture_output=True,
                text=True
            )
            print(f"swaks command executed successfully: {result.stdout}")
            if result.stderr:
                print(f"swaks stderr: {result.stderr}")
            
            
            return jsonify({"success": True, "message": "Email sent successfully"}), 200
        
        except subprocess.CalledProcessError as e:
            print(f"Error executing swaks command: {e.stderr}")
            return jsonify({"success": False, "message": f"Failed to send email: {e.stderr}"}), 500
        
        except Exception as e:
            print(f"Unexpected error: {str(e)}")
            return jsonify({"success": False, "message": f"Unexpected error: {str(e)}"}), 500
    
    except Exception as e:
        print(f"Error processing request: {str(e)}")
        return jsonify({"success": False, "message": "Error processing request"}), 500
    
EMAIL_LOGS_FILE="phishing_log.json"
warning_logs=[]
@app.route('/social-engineering-toolkit/get-email-logs', methods=['GET'])
def get_email_logs():
    try:
        warning_logs = []  # Initialize as a local variable
        if not os.path.exists(EMAIL_LOGS_FILE):
            print(f"Email logs file not found: {EMAIL_LOGS_FILE}")
            return jsonify({"success": True, "logs": []}), 200
        
        with open(EMAIL_LOGS_FILE, 'r') as f:
            for line in f:
                try:
                    log_entry = json.loads(line.strip())
                    warning_logs.append(log_entry)
                except json.JSONDecodeError as e:
                    print(f"Error decoding json line: {line.strip()} - {e}")

        # warning_logs is already a list of email logs, no need for .get()
        print(warning_logs)
        return jsonify({"success": True, "logs": warning_logs}), 200
    
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON in {EMAIL_LOGS_FILE}: {str(e)}")
        return jsonify({"success": False, "message": "Error decoding email logs", "logs": []}), 500
    
    except Exception as e:
        print(f"Error loading email logs: {str(e)}")
        return jsonify({"success": False, "message": "Error loading email logs", "logs": []}), 500

# Update /social-engineering-toolkit/email/<int:index> to fix the errors
@app.route('/social-engineering-toolkit/email/<int:index>', methods=['GET'])
def email_details(index):
    try:
        warning_logs = []  # Initialize as a local variable
        if not os.path.exists(EMAIL_LOGS_FILE):
            return "Email logs file not found", 404
        
        with open(EMAIL_LOGS_FILE, 'r') as f:
            for line in f:
                try:
                    log_entry = json.loads(line.strip())
                    warning_logs.append(log_entry)
                except json.JSONDecodeError as e:
                    print(f"Error decoding json line: {line.strip()} - {e}")

        # warning_logs is the list of email logs
        if 0 <= index < len(warning_logs):
            email = warning_logs[index]
            return render_template('email_details.html', email=email, logs=warning_logs)
        else:
            return "Email not found", 404
    
    except Exception as e:
        print(f"Error loading email details: {str(e)}")
        return "Error loading email details", 500


# code for insider threat

# Global variable to store logs
insider_logs = []

def decode_jwt(token):
    """Manually decode JWT payload to extract the name without validation."""
    try:
        if token.startswith("Bearer "):
            token = token.split(" ")[1]
        # Split JWT into header, payload, signature
        parts = token.split(".")
        if len(parts) != 3:
            return "Malformed Token"

        # Decode the payload (middle part) from base64
        payload = parts[1]
        # Add padding if necessary (base64 needs length multiple of 4)
        payload += "=" * (4 - len(payload) % 4) if len(payload) % 4 else ""
        decoded_bytes = base64.urlsafe_b64decode(payload)
        decoded_json = json.loads(decoded_bytes.decode("utf-8"))

        return decoded_json.get("name", "Unknown User")
    except base64.binascii.Error:
        return "Base64 Error"
    except json.JSONDecodeError:
        return "Invalid Payload"
    except Exception as e:
        print(f"Unexpected error decoding JWT: {e}")
        return "Error Decoding Token"

def is_outside_office_hours(timestamp_str):
    """Check if timestamp is outside office hours (9 PM to 5 AM)."""
    try:
        dt = datetime.fromisoformat(timestamp_str)
        hour = dt.hour
        return hour >= 21 or hour < 5
    except ValueError as e:
        print(f"Error parsing timestamp {timestamp_str}: {e}")
        return False

def check_api_logs():
    """Check api_log.json every minute and emit updates via SocketIO."""
    global insider_logs
    processed_timestamps = set()

    while True:
        if os.path.exists("api_log.json"):
            try:
                with open("api_log.json", "r") as f:
                    data = json.load(f)
                    requests = data.get("requests", [])

                new_logs = []
                for req in requests:
                    timestamp = req.get("timestamp")
                    if not timestamp or timestamp in processed_timestamps:
                        continue

                    if is_outside_office_hours(timestamp):
                        headers = req.get("headers", {})
                        auth_header = headers.get("Authorization", "")
                        user = decode_jwt(auth_header) if auth_header else "No Token"
                        api_path = req.get("url", "Unknown Path")
                        method = req.get("method", "Unknown Method")
                        status = "No Response"  # Default, update if status available

                        log_entry = {
                            "timestamp": timestamp,
                            "api_path": api_path,
                            "method": method,
                            "status": status,
                            "user": user,
                            "warning": "Out-of-Hours Access Detected"
                        }

                        if log_entry not in insider_logs:
                            new_logs.append(log_entry)
                            insider_logs.append(log_entry)
                            processed_timestamps.add(timestamp)

                # Emit new logs to connected clients
                if new_logs:
                    socketio.emit('new_logs', new_logs)
                    print(f"Emitted {len(new_logs)} new logs")
            except json.JSONDecodeError:
                print("Error: api_log.json is malformed")
            except Exception as e:
                print(f"Error reading api_log.json: {e}")

        time.sleep(60)

@socketio.on('connect')
def handle_connect():
    """Send existing logs to newly connected clients."""
    emit('initial_logs', insider_logs)



if __name__ == '__main__':
    # subprocess.Popen([sys.executable, "final-system.py"], env=dict(os.environ, FLASK_ENV="development"))
    # def run_script():
    #     os.system("python3 final_system.py")  # or "python3 other_script.py" based on your
    # t = threading.Thread(target=run_script)
    # t.start()
    log_thread = threading.Thread(target=check_api_logs, daemon=True)
    log_thread.start()
    if not os.path.exists(CONFIG["employee_csv"]):
        # subprocess.Popen([sys.executable, "final-system.py"], env=dict(os.environ, FLASK_ENV="development"))
        with open(CONFIG["employee_csv"], 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=["name", "email"])
            writer.writeheader()
    app.run(debug=True, host='0.0.0.0', port=5000)