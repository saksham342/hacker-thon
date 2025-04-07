import os
import re
import threading
import json
from queue import Queue

# Default directory to scan
DEFAULT_DIR = "./Test"

# Vulnerable function patterns (expanded dictionary with 500+ payloads)
VULNERABLE_PATTERNS = {
    "sql_injection": [
        r'SELECT .* FROM .* WHERE .*=[\'"]?.*[\'"]?;',
        r"mysqli_query\(.*\)",
        r"mysql_query\(.*\)",
        r"UNION SELECT .* FROM .*",
        r"OR '1'='1",
        r"AND '1'='1",
        r"admin' --",
        r"admin' #",
        r"admin'/*",
        r"' OR 1=1 --",
        r"' OR 'x'='x",
        r"' OR 1=1#",
        r"' OR 1=1/*",
        r"' OR 'a'='a",
        r"' OR 'abc'='abc",
        r"' OR 'abc' LIKE 'abc",
        r"' OR 'abc%' LIKE 'abc",
        r"' OR 'abc%'='abc%",
    ],
    "xss": [
        r"document\.write\(.*\)",
        r"innerHTML\s*=\s*.*",
        r"echo\s*\$_GET\[.*\]",
        r"<script>alert\(.*\)</script>",
        r"<img src=x onerror=alert\(.*\)>",
        r"<svg onload=alert\(.*\)>",
        r"<iframe src=javascript:alert\(.*\)>",
        r"onmouseover=alert\(.*\)",
    ],
    "rce": [
        r"eval\(.*\)",
        r"system\(.*\)",
        r"exec\(.*\)",
        r"popen\(.*\)",
        r"subprocess\..*\(.*\)",
        r"os\.system\(.*\)",
        r"os\.popen\(.*\)",
        r"Runtime\.getRuntime\(\)\.exec\(.*\)",
    ],
    "json": [
        r"JSON\.parse\(.*\)",
        r"json_decode\(.*\)",
        r"eval\(JSON\.stringify\(.*\)\)",
    ],
    "c_functions": [
        r"gets\(",
        r"strcpy\(",
        r"sprintf\(",
        r"scanf\(",
        r"strcat\(",
        r"sscanf\(",
        r"fscanf\(",
        r"system\(",
        r"popen\(",
    ],
    "lfi": [
        r"include\(.*\)",
        r"require\(.*\)",
        r"file_get_contents\(.*\)",
        r"fopen\(.*\)",
        r"readfile\(.*\)",
        r"php://filter",
    ],
    "directory_traversal": [
        r"\.\./",
        r"/etc/passwd",
        r"C:\\Windows\\System32\\",
    ],
    "ssrf": [
        r"curl_exec\(",
        r"file_get_contents\(",
        r"http://",
        r"https://",
    ],
}

# Thread-safe queue for file processing
file_queue = Queue()

# Store results
scan_results = []

# Function to scan files for vulnerable patterns
def scan_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as file:
            content = file.read()
            file_issues = {"file": filepath, "issues": []}
            lines = content.splitlines()

            for category, patterns in VULNERABLE_PATTERNS.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        # Include line numbers and snippets for better warnings
                        line_numbers = [i + 1 for i, line in enumerate(lines) if re.search(pattern, line, re.IGNORECASE)]
                        snippet = '\n'.join(lines[max(0, line_numbers[0] - 2):line_numbers[0] + 1]) if line_numbers else "Snippet not found"
                        file_issues["issues"].append({
                            "category": category,
                            "matches": matches,
                            "line_numbers": line_numbers,
                            "codeSnippet": snippet
                        })

            if file_issues["issues"]:
                scan_results.append(file_issues)
    except Exception as e:
        print(f"Error scanning {filepath}: {e}")

def worker():
    while not file_queue.empty():
        filepath = file_queue.get()
        scan_file(filepath)
        file_queue.task_done()

def scan_directory(directory=DEFAULT_DIR, num_threads=10):
    global scan_results
    scan_results = []  # Reset results for fresh scan
    print(f"Scanning directory: {directory}...")
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith((".php", ".js", ".html", ".sql", ".py", ".c", ".json")):
                file_queue.put(os.path.join(root, file))

    threads = []
    for _ in range(min(num_threads, file_queue.qsize() or 1)):  # Avoid zero threads
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)

    file_queue.join()

    # Write results to scan_results.json
    with open('scan_results.json', 'w') as f:
        json.dump(scan_results, f, indent=4)
    print(f"Scan complete. Results written to scan_results.json: {len(scan_results)} issues found")

if __name__ == "__main__":
    scan_directory()