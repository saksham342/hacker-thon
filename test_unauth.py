# ~/simple_bank/test_unauth.py
import json
import subprocess
import threading
from threading import Lock

# Load captured API logs
with open("api_log.json", "r") as f:
    captured = json.load(f)

# Shared list for results and a lock for thread-safe appending
results = []
results_lock = Lock()

# Function to test a single request
def test_request(req):
    url = req["url"]
    method = req["method"]
    headers = req["headers"]
    body = req.get("body", "")

    cmd_headers = []
    if "Authorization" in headers:
        del headers["Authorization"]  # Remove JWT for unauthorized test
    for k, v in headers.items():
        cmd_headers.extend(["-H", f"{k}: {v}"])

    if method == "GET" or not body:
        cmd = ["curl", "-X", method] + cmd_headers + [url]
    else:
        cmd = ["curl", "-X", method] + cmd_headers + ["-H", "Content-Type: application/json", "-d", body, url]

    result = subprocess.run(cmd, capture_output=True, text=True)  # No shell=True
    response = result.stdout
    is_unauth = "Unauthorized" not in response

    # Thread-safe append to results
    with results_lock:
        results.append({
            "url": url,
            "method": method,
            "headers": headers,
            "body": body,
            "response": response,
            "is_unauth": is_unauth
        })

# Create and start threads for each request
threads = []
for req in captured["requests"]:
    thread = threading.Thread(target=test_request, args=(req,))
    threads.append(thread)
    thread.start()

# Wait for all threads to complete
for thread in threads:
    thread.join()

# Write results to file
with open("unauth_results.json", "w") as f:
    json.dump(results, f, indent=2)

print("Results saved to unauth_results.json")