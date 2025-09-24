# benchmark.py
import requests
import time
import concurrent.futures

WAF_URL = "http://localhost:8080"

# A mix of legitimate and attack payloads
# Includes evasion techniques (encoding, case mixing, comments)
PAYLOADS = {
    "Legitimate": [
        {'path': '/', 'params': {'id': '1'}},
        {'path': '/search', 'params': {'query': 'product selection'}},
        {'path': '/api/items', 'params': {}},
    ],
    "SQL Injection": [
        {'path': '/search', 'params': {'q': "1' OR '1'='1"}},
        {'path': '/items', 'params': {'id': "1 UNION SELECT username, password FROM users"}},
        {'path': '/items', 'params': {'id': "1; drop table users;--"}}, # Stacked query
        {'path': '/items', 'params': {'id': "1%20UNION%20SELECT%20NULL,NULL--"}} # URL Encoded
    ],
    "Cross-Site Scripting (XSS)": [
        {'path': '/', 'params': {'name': '<script>alert("XSS")</script>'}},
        {'path': '/search', 'params': {'q': '<img src=x onerror=alert(1)>'}},
        {'path': '/profile', 'params': {'bio': 'jaVaScRiPt:alert(1)'}}, # Case mixing & entity
    ],
    "Command Injection": [
        {'path': '/tools', 'params': {'host': '8.8.8.8; whoami'}},
        {'path': '/exec', 'params': {'cmd': '`id`'}}, # Backticks
        {'path': '/exec', 'params': {'cmd': '$(ls -la)'}}, # Substitution
    ],
    "Directory Traversal": [
        {'path': '/../../../../etc/passwd', 'params': {}},
        {'path': '/static', 'params': {'file': '../secret.txt'}},
        {'path': '/static', 'params': {'file': '..%2f..%2fboot.ini'}}, # Encoded
    ],
    "SSRF": [
        {'path': '/proxy', 'params': {'url': 'http://localhost:8000/admin'}},
        {'path': '/proxy', 'params': {'url': 'http://169.254.169.254/latest/meta-data/'}},
    ],
    "JWT Alg:None": [
        {'path': '/secure', 'headers': {'Authorization': 'Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.'}}
    ]
}

def send_request(session, payload):
    method = payload.get('method', 'GET')
    url = WAF_URL + payload['path']
    params = payload.get('params')
    headers = payload.get('headers')
    start_time = time.perf_counter()
    try:
        response = session.request(method, url, params=params, headers=headers, timeout=2)
        latency = (time.perf_counter() - start_time) * 1000  # in ms
        return response.status_code, latency
    except requests.exceptions.RequestException:
        latency = (time.perf_counter() - start_time) * 1000
        return None, latency

def run_test_suite(mode_name):
    print("-" * 50)
    print(f"🔬 Running Benchmark Suite in '{mode_name}' Mode")
    print("-" * 50)

    results = {
        'total_requests': 0,
        'blocked_attacks': 0,
        'missed_attacks': 0,
        'blocked_legitimate': 0,
        'total_latency': 0,
        'attack_payloads_count': 0
    }
    
    with requests.Session() as session:
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_payload = {}
            for category, payloads in PAYLOADS.items():
                is_attack = (category != "Legitimate")
                if is_attack:
                    results['attack_payloads_count'] += len(payloads)

                for p in payloads:
                    future = executor.submit(send_request, session, p)
                    future_to_payload[future] = is_attack
            
            for future in concurrent.futures.as_completed(future_to_payload):
                is_attack = future_to_payload[future]
                status_code, latency = future.result()
                
                results['total_requests'] += 1
                results['total_latency'] += latency

                if status_code is None:
                    continue # Skip failed requests

                is_blocked = (status_code == 403)
                
                if is_attack:
                    if is_blocked:
                        results['blocked_attacks'] += 1
                    else:
                        results['missed_attacks'] += 1
                else: # Is legitimate
                    if is_blocked:
                        results['blocked_legitimate'] += 1

    # --- Print Results ---
    avg_latency = results['total_latency'] / results['total_requests']
    detection_rate = (results['blocked_attacks'] / results['attack_payloads_count']) * 100 if results['attack_payloads_count'] > 0 else 0
    false_positive_rate = (results['blocked_legitimate'] / len(PAYLOADS['Legitimate'])) * 100 if PAYLOADS['Legitimate'] else 0

    print(f"  Total Requests Sent: {results['total_requests']}")
    print(f"  Average Latency: {avg_latency:.2f} ms\n")
    print(f"  ✅ Attack Detection Rate (True Positives): {detection_rate:.1f}% ({results['blocked_attacks']}/{results['attack_payloads_count']})")
    print(f"  ❌ Missed Attacks (False Negatives): {results['missed_attacks']}")
    print(f"  🚫 False Positive Rate (Blocked Legitimate): {false_positive_rate:.1f}% ({results['blocked_legitimate']}/{len(PAYLOADS['Legitimate'])})\n")
    return avg_latency, detection_rate

if __name__ == '__main__':
    print("WAF Benchmarking and Robustness Evaluation Tool")
    print("Ensure the WAF is running. This tool will test it in both 'passthrough' and 'enforcing' modes.")
    input("Press Enter to start...")

    # For a true comparison, you would set WAF_MODE and restart the WAF between tests.
    # For simplicity, this script assumes you will run it twice, once after setting
    # export WAF_MODE=passthrough and once with export WAF_MODE=enforcing (or unset)
    
    # Run in the current mode
    run_test_suite("Current WAF_MODE")

    print("\nTo get a baseline comparison, please do the following:")
    print("1. Stop the WAF.")
    print("2. Run 'export WAF_MODE=passthrough' in your terminal.")
    print("3. Restart the WAF (`python3 waf.py`).")
    print("4. Run this benchmark script again.")
