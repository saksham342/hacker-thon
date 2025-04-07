from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import json
import os
import random
import time
from functools import wraps
import subprocess
import threading
import requests
from werkzeug.serving import run_simple
from flask_socketio import SocketIO, emit
import re
from queue import Queue
import shutil

app = Flask(__name__)
app.config['SECRET_KEY'] = 'bank-1234sdfghj1234567dfghj-key'
# socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
socketio = SocketIO(app, cors_allowed_origins="*")
LOG_FILE = "api_log.json"
STATIC_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFtcyBBZG1pbiIsImFkbWluIjp0cnVlLCJpYXQiOjE3NDM3NzAwMzksImV4cCI6MTc0Mzc3MzYzOX0.Ng7aTHcbwOQscWU5VV3QT9WcZSih53EgBMwbKsITa58"
STATIC_USERNAME = "manager@ingbank.com"
STATIC_PASSWORD = "Manager@123"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# In-memory data
BANK_DATA = {
    "accounts": [
        {"number": "123456789012", "balance": 1000.0},
        {"number": "987654321098", "balance": 500.0}
    ],
    "transactions": [
        {"type": "deposit", "amount": 1000, "account": "123456789012", "timestamp": "2025-04-04T10:00:00"}
    ]
}

SIM_DB = {
    "users": [
        {"id": 1, "name": "admin", "password": "secret"},
        {"id": 2, "name": "guest", "password": "guest123"}
    ]
}

# Vulnerability Scanner Setup
DEFAULT_DIR = "./Test"
file_queue = Queue()
scan_results = []
scan_status = {"status": "idle", "progress": 0, "total_files": 0}
scan_lock = threading.Lock()
last_commit_hash = None  # Define globally here

VULNERABLE_PATTERNS = {
    "sql_injection": [r'SELECT .* FROM .* WHERE .*=[\'"]?.*[\'"]?;', r"mysqli_query\(.*\)", r"mysql_query\(.*\)"],
    "xss": [r"document\.write\(.*\)", r"innerHTML\s*=\s*.*", r"<script>alert\(.*\)</script>"],
    "rce": [r"eval\(.*\)", r"system\(.*\)", r"exec\(.*\)"],
    # Add more patterns as needed
}

def scan_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as file:
            content = file.read()
            file_issues = {"file": filepath, "issues": []}
            lines = content.split('\n')
            for category, patterns in VULNERABLE_PATTERNS.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        snippets = []
                        for i, line in enumerate(lines):
                            if re.search(pattern, line, re.IGNORECASE):
                                snippet = '\n'.join(lines[max(0, i-2):i+3])
                                snippets.append(snippet)
                        file_issues["issues"].append({
                            "category": category,
                            "matches": matches,
                            "codeSnippet": snippets[0] if snippets else "Snippet not found"
                        })
            if file_issues["issues"]:
                with scan_lock:
                    scan_results.append(file_issues)
                    scan_status["progress"] += 1
                socketio.emit('scan_update', {
                    'progress': scan_status["progress"],
                    'total': scan_status["total_files"],
                    'status': 'scanning'
                })
    except Exception as e:
        print(f"Error scanning {filepath}: {e}")

def worker():
    while not file_queue.empty():
        filepath = file_queue.get()
        scan_file(filepath)
        file_queue.task_done()

def scan_directory(directory=DEFAULT_DIR, num_threads=10):
    global scan_results
    scan_results = []
    with scan_lock:
        scan_status["status"] = "scanning"
        scan_status["progress"] = 0
        files_to_scan = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith((".php", ".js", ".html", ".sql", ".py", ".c", ".json")):
                files_to_scan.append(os.path.join(root, file))
    scan_status["total_files"] = len(files_to_scan)
    for filepath in files_to_scan:
        file_queue.put(filepath)
    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    with scan_lock:
        scan_status["status"] = "complete"
    socketio.emit('scan_complete', {'results': scan_results})

def clone_repository(repo_url, token=None):
    if os.path.exists(DEFAULT_DIR):
        shutil.rmtree(DEFAULT_DIR)
    os.makedirs(DEFAULT_DIR)
    clone_cmd = ["git", "clone"]
    if token and repo_url.startswith("https://"):
        repo_url = repo_url.replace("https://", f"https://{token}@")
    clone_cmd.append(repo_url)
    clone_cmd.append(DEFAULT_DIR)
    try:
        subprocess.run(clone_cmd, check=True, capture_output=True)
        commit_hash = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=DEFAULT_DIR
        ).decode().strip()
        return commit_hash
    except subprocess.CalledProcessError as e:
        print(f"Clone failed: {e}")
        return None

# Log requests
def log_request():
    if request.path.startswith('/api/'):
        log_entry = {
            "url": request.url,
            "method": request.method,
            "headers": dict(request.headers),
            "body": request.get_data(as_text=True) if request.method != "GET" else "",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S")
        }
        logs = {"requests": []}
        if os.path.exists(LOG_FILE):
            try:
                with open(LOG_FILE, 'r') as f:
                    logs = json.load(f)
            except json.JSONDecodeError:
                print("Warning: Resetting corrupted api_log.json")
        logs["requests"].append(log_entry)
        try:
            with open(LOG_FILE, 'w') as f:
                json.dump(logs, f, indent=2)
            print(f"Logged request to {LOG_FILE}: {log_entry['url']}")
        except Exception as e:
            print(f"Failed to write to {LOG_FILE}: {e}")

# Token validation decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        print(f"Checking token: {token}")
        if not token or token != STATIC_TOKEN:
            log_request()
            return jsonify({"error": "Unauthorized"}), 401
        log_request()
        return f(*args, **kwargs)
    return decorated

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# Background API request handler
def api_request_in_background(method, url, headers, data=None):
    try:
        if method == 'POST':
            response = requests.post(url, json=data, headers=headers)
        elif method == 'DELETE':
            response = requests.delete(url, headers=headers)
        print(f"Background {method} API response: {response.text}")
    except Exception as e:
        print(f"Error in background {method} request to {url}: {e}")

@app.before_request
def before_request():
    if request.path.startswith('/api/'):
        log_request()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == STATIC_USERNAME and password == STATIC_PASSWORD:
            session['logged_in'] = True
            session['token'] = STATIC_TOKEN
            print(f"Login successful for {username}")
            return redirect(url_for('index'))
        print(f"Login failed for {username}")
        return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        action = request.form['action']
        if action == 'add_account':
            number = ''.join([str(random.randint(0, 9)) for _ in range(12)])
            BANK_DATA["accounts"].append({"number": number, "balance": 0.0})
        elif action in ['deposit', 'withdraw']:
            amount = float(request.form['amount'])
            account = request.form['account']
            headers = {"Authorization": f"Bearer {session['token']}", "Content-Type": "application/json"}
            data = {"account": account, "amount": amount, "action": action}
            print(f"Processing {action} for {account} with amount {amount}")
            for acc in BANK_DATA["accounts"]:
                if acc["number"] == account:
                    if action == 'deposit':
                        acc["balance"] += amount
                        BANK_DATA["transactions"].append({
                            "type": "deposit", "amount": amount, "account": account,
                            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S")
                        })
                    elif action == 'withdraw' and acc["balance"] >= amount:
                        acc["balance"] -= amount
                        BANK_DATA["transactions"].append({
                            "type": "withdraw", "amount": amount, "account": account,
                            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S")
                        })
                    break
            threading.Thread(target=api_request_in_background, args=('POST', "http://127.0.0.1:5001/api/transactions", headers, data), daemon=True).start()
        elif action == 'delete':
            account = request.form['account']
            headers = {"Authorization": f"Bearer {session['token']}"}
            print(f"Deleting account {account}")
            BANK_DATA["accounts"] = [acc for acc in BANK_DATA["accounts"] if acc["number"] != account]
            threading.Thread(target=api_request_in_background, args=('DELETE', f"http://127.0.0.1:5001/api/accounts/{account}", headers), daemon=True).start()

    total_balance = sum(acc["balance"] for acc in BANK_DATA["accounts"])
    return render_template('index_.html', accounts=BANK_DATA["accounts"], transactions=BANK_DATA["transactions"], total_balance=total_balance, token=session['token'])

@app.route('/db_simulator', methods=['GET', 'POST'])
@login_required
def db_simulator():
    query_result = None
    update_result = None
    if request.method == 'POST':
        action = request.form['action']
        if action == 'query':
            query = request.form['query']
            headers = {"Authorization": f"Bearer {session['token']}"}
            print(f"Sending query request: {query} with headers {headers}")
            response = requests.get(f"http://127.0.0.1:5001/api/db/query?query={query}", headers=headers)
            query_result = response.json()
            print(f"Query API response: {response.text}")
        elif action == 'update':
            user_id = request.form['user_id']
            new_name = request.form['new_name']
            headers = {"Authorization": f"Bearer {session['token']}"}
            data = {"id": user_id, "name": new_name}
            print(f"Updating user {user_id} to {new_name}")
            for user in SIM_DB["users"]:
                if str(user["id"]) == user_id:
                    user["name"] = new_name
                    break
            update_result = {"message": f"Updated user {user_id} to {new_name}"}
            threading.Thread(target=api_request_in_background, args=('POST', "http://127.0.0.1:5001/api/db/update", headers, data), daemon=True).start()
    return render_template('db_simulator.html', users=SIM_DB["users"], query_result=query_result, update_result=update_result)

# API Routes
@app.route('/api/accounts', methods=['GET', 'POST'])
@token_required
def api_accounts():
    if request.method == 'GET':
        return jsonify({"accounts": BANK_DATA["accounts"]})
    number = ''.join([str(random.randint(0, 9)) for _ in range(12)])
    BANK_DATA["accounts"].append({"number": number, "balance": 0.0})
    return jsonify({"message": "Account added", "account_number": number}), 201

@app.route('/api/transactions', methods=['POST'])
@token_required
def api_transactions():
    data = request.get_json()
    action = data['action']
    amount = float(data['amount'])
    account = data['account']
    for acc in BANK_DATA["accounts"]:
        if acc["number"] == account:
            if action == 'deposit':
                acc["balance"] += amount
                BANK_DATA["transactions"].append({
                    "type": "deposit", "amount": amount, "account": account,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S")
                })
                return jsonify({"message": "Deposit successful"})
            elif action == 'withdraw' and acc["balance"] >= amount:
                acc["balance"] -= amount
                BANK_DATA["transactions"].append({
                    "type": "withdraw", "amount": amount, "account": account,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S")
                })
                return jsonify({"message": "Withdrawal successful"})
    return jsonify({"error": "Invalid transaction"}), 400

@app.route('/api/summary', methods=['GET'])
@token_required
def api_summary():
    return jsonify({"total_balance": sum(acc["balance"] for acc in BANK_DATA["accounts"]), "account_count": len(BANK_DATA["accounts"])})

@app.route('/api/accounts/<account_number>', methods=['DELETE'])
def api_accounts_delete(account_number):
    BANK_DATA["accounts"] = [acc for acc in BANK_DATA["accounts"] if acc["number"] != account_number]
    return jsonify({"message": "Account deleted"})

@app.route('/api/balance/update', methods=['POST'])
@token_required
def api_balance_update():
    data = request.get_json()
    account = data['account']
    new_balance = float(data['balance'])
    for acc in BANK_DATA["accounts"]:
        if acc["number"] == account:
            acc["balance"] = new_balance
            return jsonify({"message": "Balance updated"})
    return jsonify({"error": "Account not found"}), 404

@app.route('/api/db/query', methods=['GET'])
@token_required
def api_db_query():
    query = request.args.get('query')
    simulated_query = f"SELECT * FROM users WHERE name = '{query}'"
    result = [user for user in SIM_DB["users"] if query in user["name"]]
    try:
        eval(f"print('Executing query: {query}')")
    except:
        pass
    return jsonify({"query": simulated_query, "result": result})

@app.route('/api/db/update', methods=['POST'])
@token_required
def api_db_update():
    data = request.get_json()
    user_id = data['id']
    new_name = data['name']
    for user in SIM_DB["users"]:
        if str(user["id"]) == user_id:
            user["name"] = new_name
            os.system(f"echo Updating user {user_id} to {new_name}")
            break
    return jsonify({"message": f"Updated user {user_id} to {new_name}"})

@app.route('/staging', methods=['GET', 'POST'])
@token_required
def staging():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        from_account = data.get('from_account')
        to_account = data.get('to_account')
        amount = float(data.get('amount', 0))
        unsafe_query = f"SELECT balance FROM accounts WHERE number = '{from_account}' OR '1'='1' /* Blockchain sync */"
        eval(f"print('Processing quantum ledger transfer of {amount} from {from_account} via smart contract')")
        os.system(f"echo AI-driven transfer {amount} to {to_account} with ML-optimized routing")
        include_file = f"../blockchain/{to_account}.conf"
        document_write = f"<script>document.write('Transfer initiated for {amount}')</script>"
        for acc in BANK_DATA["accounts"]:
            if acc["number"] == from_account and acc["balance"] >= amount:
                acc["balance"] -= amount
                for to_acc in BANK_DATA["accounts"]:
                    if to_acc["number"] == to_account:
                        to_acc["balance"] += amount
                        break
                break
        if request.is_json:
            return jsonify({"message": f"Quantum ledger transfer of {amount} from {from_account} to {to_account} completed"})
        return redirect(url_for('staging'))
    return render_template('staging.html', accounts=BANK_DATA["accounts"])

# Dashboard App
dashboard_app = Flask(__name__, template_folder='templates', static_folder='static')
dashboard_app.config['SECRET_KEY'] = 'dashboard-secret-key'
dashboard_app.jinja_env.add_extension('jinja2.ext.do')

def run_test_in_background():
    print("Running test_unauth.py in background...")
    test_script = os.path.join(BASE_DIR, "test_unauth.py")
    if os.path.exists(test_script):
        try:
            subprocess.run(["python3", "test_unauth.py"], cwd=BASE_DIR, check=True)
            print("test_unauth.py completed successfully in background.")
        except subprocess.CalledProcessError as e:
            print(f"Error running test_unauth.py in background: {e}")
        except FileNotFoundError:
            print("Error: 'python3' not found in the system PATH.")
    else:
        print(f"Error: 'test_unauth.py' not found in {BASE_DIR}")

@dashboard_app.route('/')
def dashboard():
    results = []
    results_file = os.path.join(BASE_DIR, "unauth_results.json")
    if os.path.exists(results_file):
        try:
            with open(results_file, 'r') as f:
                results = json.load(f)
        except json.JSONDecodeError:
            print(f"Error: 'unauth_results.json' is corrupted or invalid JSON.")
    else:
        print(f"Warning: '{results_file}' not found. Displaying empty results.")
    return render_template('dashboard.html', results=results)

@dashboard_app.route('/run_test', methods=['POST'])
def run_test():
    print("Processing run_test request from dashboard...")
    results_file = os.path.join(BASE_DIR, "unauth_results.json")
    log_file = os.path.join(BASE_DIR, "api_log.json")
    should_run_test = True
    if os.path.exists(results_file) and os.path.exists(log_file):
        results_mtime = os.path.getmtime(results_file)
        log_mtime = os.path.getmtime(log_file)
        if results_mtime >= log_mtime:
            print("Results are up-to-date with api_log.json. Skipping test run.")
            should_run_test = False
    if should_run_test:
        threading.Thread(target=run_test_in_background, daemon=True).start()
        print("Test started in background. Returning to dashboard immediately.")
    else:
        print("Using existing unauth_results.json.")
    return redirect(url_for('dashboard'))

# Vulnerability Scanner Routes
@app.route('/vuln_scanner')
def vuln_scanner():
    return render_template('vuln_scanner.html')

# def schedule_scan(repo_url, token, hours):
#     def run_scheduled():
#         time.sleep(hours * 3600)  # Convert hours to seconds
#         start_scan(repo_url, token, scheduled=True)
#     threading.Thread(target=run_scheduled, daemon=True).start()

import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@app.route('/vuln_scan', methods=['POST'])
@login_required
def start_vuln_scan():
    global last_commit_hash
    data = request.json
    if not data:
        logger.error("No JSON data provided in request")
        return jsonify({'error': 'No JSON data provided'}), 400

    repo_url = data.get('repo_url')
    token = data.get('token')
    schedule_hours = data.get('schedule_hours')

    if not repo_url:
        logger.error("Repository URL is required but not provided")
        return jsonify({'error': 'Repository URL is required'}), 400

    if schedule_hours:
        schedule_scan(repo_url, token, float(schedule_hours))
        return jsonify({'message': f'Scan scheduled in {schedule_hours} hours'}), 202

    def start_scan(repo_url, token, scheduled=False):
        global last_commit_hash
        with scan_lock:
            if scan_status["status"] in ["scanning", "cloning"]:
                socketio.emit('scan_update', {'status': 'already_running', 'message': 'Scan in progress'})
                logger.debug("Scan already running, skipping new scan")
                return
            scan_status["status"] = "cloning"
            scan_status["progress"] = 0
            scan_status["total_files"] = 0
        socketio.emit('scan_update', {'status': 'cloning', 'progress': 0})
        logger.debug(f"Cloning repository: {repo_url}")

        new_commit_hash = clone_repository(repo_url, token)
        if not new_commit_hash:
            with scan_lock:
                scan_status["status"] = "error"
            socketio.emit('scan_update', {'status': 'error', 'message': 'Clone failed'})
            logger.error("Repository clone failed")
            return

        # Count files to scan for progress
        files_to_scan = [
            os.path.join(root, file)
            for root, _, files in os.walk(DEFAULT_DIR)
            for file in files
            if file.endswith((".php", ".js", ".html", ".sql", ".py", ".c", ".json"))
        ]
        total_files = len(files_to_scan)
        logger.debug(f"Total files to scan: {total_files}")

        if last_commit_hash == new_commit_hash and not scheduled:
            with scan_lock:
                scan_status["status"] = "complete"
                scan_status["progress"] = total_files  # Full progress
                scan_status["total_files"] = total_files
            if os.path.exists('scan_results.json'):
                try:
                    with open('scan_results.json', 'r') as f:
                        saved_results = json.load(f)
                    socketio.emit('scan_complete', {
                        'results': saved_results,
                        'message': 'no_new_commits',
                        'progress': total_files,
                        'total': total_files
                    })
                    logger.debug(f"Emitted existing results: {saved_results}")
                except (json.JSONDecodeError, IOError) as e:
                    socketio.emit('scan_complete', {
                        'results': [],
                        'message': f'Error loading results: {str(e)}',
                        'progress': total_files,
                        'total': total_files
                    })
                    logger.error(f"Failed to load scan_results.json: {str(e)}")
            else:
                socketio.emit('scan_complete', {
                    'results': [],
                    'message': 'No previous results found',
                    'progress': total_files,
                    'total': total_files
                })
                logger.debug("No scan_results.json exists")
            return

        last_commit_hash = new_commit_hash
        with scan_lock:
            scan_status["status"] = "scanning"
            scan_status["progress"] = 0
            scan_status["total_files"] = total_files
        socketio.emit('scan_update', {
            'status': 'scanning',
            'progress': 0,
            'total': total_files
        })
        logger.debug("Starting scan process")

        def run_scan():
            global scan_results
            scan_results = []
            try:
                # Run sonar.py
                result = subprocess.run(
                    ['python3', 'sonar.py', DEFAULT_DIR],
                    check=True,
                    capture_output=True,
                    text=True
                )
                logger.debug(f"sonar.py stdout: {result.stdout}")
                if result.stderr:
                    logger.debug(f"sonar.py stderr: {result.stderr}")

                # Load results from scan_results.json
                if os.path.exists('scan_results.json'):
                    with open('scan_results.json', 'r') as f:
                        scan_results = json.load(f)
                    logger.debug(f"Loaded scan results: {scan_results}")
                    # Update progress based on files processed (assume all done)
                    with scan_lock:
                        scan_status["progress"] = total_files
                        scan_status["status"] = "complete"
                    socketio.emit('scan_complete', {
                        'results': scan_results,
                        'message': 'Scan completed',
                        'progress': total_files,
                        'total': total_files
                    })
                    logger.debug(f"Emitted scan results: {scan_results}")
                else:
                    logger.warning("scan_results.json not found after scan")
                    with scan_lock:
                        scan_status["status"] = "complete"
                        scan_status["progress"] = total_files
                    socketio.emit('scan_complete', {
                        'results': [],
                        'message': 'No results generated',
                        'progress': total_files,
                        'total': total_files
                    })
            except subprocess.CalledProcessError as e:
                with scan_lock:
                    scan_status["status"] = "error"
                socketio.emit('scan_update', {
                    'status': 'error',
                    'message': f'sonar.py failed: {e.stderr}',
                    'progress': scan_status["progress"],
                    'total': total_files
                })
                logger.error(f"sonar.py execution failed: {e.stderr}")
            except Exception as e:
                with scan_lock:
                    scan_status["status"] = "error"
                socketio.emit('scan_update', {
                    'status': 'error',
                    'message': f'Scan error: {str(e)}',
                    'progress': scan_status["progress"],
                    'total': total_files
                })
                logger.error(f"Unexpected scan error: {str(e)}")

        threading.Thread(target=run_scan, daemon=True).start()

    threading.Thread(target=start_scan, args=(repo_url, token), daemon=True).start()
    logger.debug("Scan request accepted, returning 202")
    return jsonify({'message': 'Scan started asynchronously'}), 202

@app.route('/vuln_status', methods=['GET'])
@login_required
def get_vuln_status():
    with scan_lock:
        return jsonify(scan_status)

# Modified run_apps function
def run_apps():
    def print_urls():
        urls = [
            "http://0.0.0.0:5001 - Main Banking App",
            "http://0.0.0.0:5002 - Dashboard App",
            "http://0.0.0.0:5003/vuln_scanner - Vulnerability Scanner App"
        ]
        print("\nAvailable Services:")
        for url in urls:
            print(url)
        print("\n")

    threading.Thread(target=lambda: run_simple('0.0.0.0', 5001, app, use_reloader=False, use_debugger=True)).start()
    threading.Thread(target=lambda: run_simple('0.0.0.0', 5002, dashboard_app, use_reloader=False, use_debugger=True)).start()
    threading.Thread(target=lambda: socketio.run(app, host='0.0.0.0', port=5003, debug=True, use_reloader=False), daemon=True).start()
    print_urls()

if __name__ == '__main__':
    run_apps()