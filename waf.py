# waf.py
import os
import time
import re
import urllib.parse
import base64
import json
import multiprocessing
import requests
import sqlparse
from flask import Flask, request, Response
from lxml import etree
import redis
from html import unescape

# --- Import the logger app ---
# This is needed to run the logger in a separate process for local testing.
# In production, these would be separate services.
from logger import app as logger_app, init_db as init_logger_db

# ==============================================================================
# == 1. CONFIGURATION (from Environment Variables)
# ==============================================================================
REAL_APP_HOST = os.getenv('REAL_APP_HOST', 'localhost')
REAL_APP_PORT = int(os.getenv('REAL_APP_PORT', 80))
LOGGER_URL = os.getenv('LOGGER_URL', 'http://localhost:8081/log')
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))

# --- WAF Mode & Threat Scoring ---
# 'enforcing': Blocks malicious requests.
# 'passthrough': Allows all requests for baseline performance testing.
WAF_MODE = os.getenv('WAF_MODE', 'enforcing')
THREAT_SCORE_THRESHOLD = int(os.getenv('THREAT_SCORE_THRESHOLD', 15))
BAN_SCORE_THRESHOLD = int(os.getenv('BAN_SCORE_THRESHOLD', 25))

# --- Rate Limiting & Banning Configuration ---
RATE_LIMIT_COUNT = int(os.getenv('RATE_LIMIT_COUNT', 100))
RATE_LIMIT_WINDOW = int(os.getenv('RATE_LIMIT_WINDOW', 60)) # seconds
BAN_DURATION = int(os.getenv('BAN_DURATION', 300)) # seconds

# ==============================================================================
# == 2. INITIALIZATION
# ==============================================================================
app = Flask(__name__)

try:
    redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)
    redis_client.ping()
    print(f"--> Successfully connected to Redis at {REDIS_HOST}:{REDIS_PORT}")
except redis.exceptions.ConnectionError as e:
    print(f"[FATAL] Could not connect to Redis: {e}. Exiting.")
    exit(1)

def start_logger():
    """Runs the logger Flask app in a separate process."""
    init_logger_db()
    print("--> Initializing Logger service on http://localhost:8081")
    logger_app.run(host='0.0.0.0', port=8081)

def log_attack(ip, attack_type, details, score):
    """Sends log data including the threat score to the logging service."""
    try:
        log_data = {
            'source_ip': ip,
            'attack_type': attack_type,
            'details': details,
            'path': request.full_path,
            'threat_score': score
        }
        requests.post(LOGGER_URL, json=log_data, timeout=0.5)
    except requests.exceptions.RequestException:
        print(f"[WARNING] Could not connect to logging service at {LOGGER_URL}")

# ==============================================================================
# == 3. ADVERSARIAL ROBUSTNESS & NORMALIZATION
# ==============================================================================
def normalize_input(input_string):
    """
    Applies multiple layers of decoding and normalization to combat evasion.
    This is crucial for detecting obfuscated attacks.
    """
    if not isinstance(input_string, str):
        return ""
    normalized = input_string
    for _ in range(3): # Multi-pass URL decoding (e.g., %253c -> %3c -> <)
        normalized = urllib.parse.unquote(normalized)
    normalized = unescape(normalized) # HTML entity decoding (e.g., &lt; -> <)
    normalized = normalized.lower() # Use lowercase for case-insensitive matching
    return normalized

# ==============================================================================
# == 4. SECURITY LOGIC (with Threat Scoring)
# ==============================================================================
# Each function now returns a score (0 for no threat, >0 for a threat).
# This provides context-awareness and reduces false positives.

def check_for_sqli(input_string):
    score = 0
    suspicious_patterns = {
        r"\b(union|select|insert|update|delete|drop|alter|exec)\b": 5,
        r"(--|#|;|\/\*)": 3, # SQL comments/terminators
        r"(\b(and|or)\b\s+['\"]\w+['\"]\s*=\s*['\"]\w+['\"])": 10 # Tautology (e.g., 'a'='a')
    }
    for pattern, value in suspicious_patterns.items():
        if re.search(pattern, input_string, re.IGNORECASE): score += value
    if len(sqlparse.split(input_string)) > 1: score += 15 # Stacked queries are high-confidence
    return score

def check_for_xss(input_string):
    score = 0
    xss_patterns = {
        r"<script.*?>": 15, # <script> tag
        r"\bon\w+\s*=\s*.*?[\"']": 10, # Event handlers like 'onerror='
        r"javascript:": 10 # javascript: protocol
    }
    for pattern, value in xss_patterns.items():
        if re.search(pattern, input_string, re.IGNORECASE): score += value
    return score

def check_for_command_injection(input_string):
    score = 0
    injection_patterns = {
        r"[;&|`$()]": 5, # Shell metacharacters
        r"\b(cat|ls|whoami|uname|pwd)\b": 7, # Common recon commands
        r"(\$\(|`cmd`)": 15 # Command substitution is high-confidence
    }
    for pattern, value in injection_patterns.items():
        if re.search(pattern, input_string): score += value
    return score
    
def check_for_directory_traversal(input_string):
    return 20 if "../" in input_string or "..\\" in input_string else 0

def check_for_xxe(xml_string):
    if not xml_string or 'xml' not in request.headers.get('Content-Type', '').lower(): return 0
    # Checking for an ENTITY declaration using a SYSTEM identifier is a strong indicator of XXE
    return 25 if re.search(r"<!ENTITY.*SYSTEM", xml_string, re.IGNORECASE) else 0

def check_for_ssrf(input_string):
    # Checks for URLs pointing to internal/metadata services
    ssrf_patterns = {
        r"(127\.0\.0\.1|localhost|169\.254\.169\.254)": 20, # Loopback and AWS metadata
        r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})\b": 15 # Private IP ranges
    }
    for pattern, value in ssrf_patterns.items():
        if re.search(pattern, input_string): return value
    return 0

def check_jwt_alg_none(headers):
    auth_header = headers.get('Authorization', '')
    if not auth_header.lower().startswith('bearer '): return 0
    try:
        # Decode JWT header without verification to check 'alg' field
        token = auth_header.split(' ')[1]
        header_b64 = token.split('.')[0]
        decoded_header = base64.urlsafe_b64decode(header_b64 + '==').decode('utf-8')
        if json.loads(decoded_header).get('alg', '').lower() == 'none':
            return 30 # Critical vulnerability
    except Exception:
        return 0 # Not a valid JWT or malformed
    return 0

# Dictionaries mapping attack types to check functions
INPUT_CHECKS = {
    "SQL Injection": check_for_sqli, "Cross-Site Scripting (XSS)": check_for_xss,
    "Command Injection": check_for_command_injection, "Directory Traversal": check_for_directory_traversal,
    "Server-Side Request Forgery (SSRF)": check_for_ssrf,
}
BODY_CHECKS = {"XML External Entity (XXE)": check_for_xxe}
HEADER_CHECKS = {"JWT Alg:None Attack": check_jwt_alg_none}

# ==============================================================================
# == 5. IP MANAGEMENT & PROXY LOGIC
# ==============================================================================
def is_ip_banned(ip): return redis_client.exists(f"ban:{ip}")
def ban_ip(ip): redis_client.set(f"ban:{ip}", "banned", ex=BAN_DURATION)

def is_rate_limited(ip):
    key = f"rate_limit:{ip}"
    count = redis_client.incr(key)
    if count == 1: redis_client.expire(key, RATE_LIMIT_WINDOW)
    return count > RATE_LIMIT_COUNT

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    # Passthrough mode for benchmarking performance overhead
    if WAF_MODE == 'passthrough':
        return forward_request(path)

    client_ip = request.remote_addr
    
    # 1. IP Ban & Rate Limit Checks
    if is_ip_banned(client_ip): return "Forbidden: Your IP has been temporarily blocked.", 403
    if is_rate_limited(client_ip):
        log_attack(client_ip, "DDoS / Rate Limit", f"Exceeded {RATE_LIMIT_COUNT} reqs", 5)
        return "Too many requests", 429

    # 2. Initialize Threat Score for this request
    total_threat_score = 0
    triggered_rules = []

    # 3. Check parameters (args, form data) where attacks are most common
    params_to_check = {**request.args.to_dict(), **request.form.to_dict()}
    for key, value in params_to_check.items():
        normalized_value = normalize_input(value)
        for attack_type, check_function in INPUT_CHECKS.items():
            score = check_function(normalized_value)
            if score > 0:
                total_threat_score += score
                triggered_rules.append(f"{attack_type} in param '{key}' (score: {score})")

    # 4. Separately check the path for traversal to avoid false positives on CSS/fonts
    normalized_path = normalize_input(request.path)
    traversal_score = check_for_directory_traversal(normalized_path)
    if traversal_score > 0:
        total_threat_score += traversal_score
        triggered_rules.append(f"Directory Traversal in path (score: {traversal_score})")

    # 5. Run body and header specific checks
    request_body_raw = request.get_data(as_text=True)
    for attack_type, check_function in BODY_CHECKS.items():
        score = check_function(request_body_raw)
        if score > 0:
            total_threat_score += score
            triggered_rules.append(f"{attack_type} in request body (score: {score})")
    for attack_type, check_function in HEADER_CHECKS.items():
        score = check_function(request.headers)
        if score > 0:
            total_threat_score += score
            triggered_rules.append(f"{attack_type} in headers (score: {score})")
            
    # 6. Make a final decision based on the accumulated score
    if total_threat_score >= THREAT_SCORE_THRESHOLD:
        attack_types = ", ".join(set(rule.split(' ')[0] for rule in triggered_rules))
        log_attack(client_ip, attack_types, " | ".join(triggered_rules), total_threat_score)
        
        # Ban if score is over a higher threshold
        if total_threat_score >= BAN_SCORE_THRESHOLD:
            ban_ip(client_ip)
            
        return f"Malicious request detected. Threat Score: {total_threat_score}", 403

    # 7. If all checks pass, proxy the request to the backend
    return forward_request(path)

def forward_request(path):
    """Forwards the clean request to the backend and returns the response with security headers."""
    try:
        backend_url = f"http://{REAL_APP_HOST}:{REAL_APP_PORT}/{path}"
        resp = requests.request(
            method=request.method, url=backend_url,
            headers={key: value for (key, value) in request.headers if key != 'Host'},
            data=request.get_data(), cookies=request.cookies,
            params=request.args, allow_redirects=False, timeout=5
        )
        # Filter out headers that are controlled by the proxy
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(n, v) for (n, v) in resp.raw.headers.items() if n.lower() not in excluded_headers]
        
        # **FIX**: A more practical CSP that allows inline styles for proper rendering of most web apps.
        csp_policy = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
        
        # Add security headers to the response
        headers.extend([
            ('X-Content-Type-Options', 'nosniff'),
            ('X-Frame-Options', 'SAMEORIGIN'),
            ('Content-Security-Policy', csp_policy),
            ('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
        ])
        return Response(resp.content, resp.status_code, headers)
    except requests.exceptions.RequestException as e:
        return f"Error connecting to backend application: {e}", 502

# ==============================================================================
# == 6. APPLICATION LAUNCH
# ==============================================================================
if __name__ == '__main__':
    # For easy local testing, we start the logger in a separate process.
    # In production, you would run 'waf.py' and 'logger.py' as separate services.
    logger_process = multiprocessing.Process(target=start_logger)
    logger_process.daemon = True
    logger_process.start()
    time.sleep(1) # Give the logger a moment to initialize

    print("--> Initializing WAF service on http://localhost:8080")
    print("    Configuration:")
    print(f"    - WAF Mode: {WAF_MODE.upper()}")
    print(f"    - Backend App: http://{REAL_APP_HOST}:{REAL_APP_PORT}")
    print(f"    - Block Threshold: {THREAT_SCORE_THRESHOLD}, Ban Threshold: {BAN_SCORE_THRESHOLD}")

    try:
        # In production, use a proper WSGI server like Gunicorn:
        # gunicorn --workers 4 --bind 0.0.0.0:8080 waf:app
        app.run(port=8080, host='0.0.0.0', threaded=True)
    except KeyboardInterrupt:
        print("\nShutting down WAF...")
    finally:
        logger_process.terminate()
        logger_process.join()
        print("Logger service stopped.")
