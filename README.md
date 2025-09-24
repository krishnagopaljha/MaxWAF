MaxWAF 🛡️
==========

MaxWAF is an intelligent, proxy-based Web Application Firewall (WAF) designed to provide robust, context-aware protection for your web applications. It goes beyond simple pattern matching by using a threat-scoring engine to reduce false positives and implementing advanced normalization techniques to detect evasive attacks.

It inspects all incoming HTTP requests and leverages a Redis backend for high-performance rate limiting and IP banning. All detected threats are logged to a real-time security dashboard for immediate analysis.

Key Features
------------

*   **🧠 Intelligent Threat Scoring:** Instead of blocking on the first trigger, MaxWAF accumulates a threat score for each request. A request is only blocked if its score exceeds a configurable threshold, dramatically reducing false positives.
    
*   **🛡️ Comprehensive Threat Coverage:** Protects against a wide range of common and emerging vulnerabilities:
    
    *   SQL Injection (SQLi)
        
    *   Cross-Site Scripting (XSS)
        
    *   Command Injection
        
    *   XML External Entity (XXE)
        
    *   Directory Traversal
        
    *   Server-Side Request Forgery (SSRF)
        
    *   JWT alg:none Manipulation
        
*   **🤺 Adversarial Robustness:** Implements multi-layered input normalization (URL decoding, HTML entity decoding, lowercasing) to counter common evasion techniques used by attackers.
    
*   **⚡ High-Performance DDoS Protection:** Utilizes a Redis backend for fast, efficient rate limiting and temporary IP banning of malicious actors.
    
*   **📊 Real-time Security Dashboard:** A separate logger service provides a clean, web-based dashboard that displays all detected security events as they happen, with filtering capabilities.
    
*   **🔧 Flexible Configuration:** All settings are managed via environment variables for easy integration into containerized and cloud environments.
    
*   **🚀 Production-Ready:** Includes guidance for deployment using a production-grade WSGI server like Gunicorn.
    

Requirements
------------

*   Python 3.8+
    
*   A running **Redis Server** instance
    
*   Required Python packages, which can be installed from requirements.txt.
    

Installation
------------

1.  Bashgit clone cd
    
   ```
    bleach
    Flask
    gunicorn
    lxml
    redis
    requests
    sqlparse
   ```
    
3.  ``` pip install -r requirements.txt ```
    
4.  **Ensure Redis is running** and accessible from where you are running the WAF.
