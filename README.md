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
    
Configuration
-------------
MaxWAF is configured entirely through **environment variables**. You can set them in your terminal, a .env file, or your deployment environment (like Docker, Kubernetes, or Heroku.

*   **REAL\_APP\_HOST**
    
    *   _Description_: The hostname or IP of your backend web application.
        
    *   _Default_: localhost
        
*   **REAL\_APP\_PORT**
    
    *   _Description_: The port your backend web application is running on.
        
    *   _Default_: 80
        
*   **REDIS\_HOST**
    
    *   _Description_: The hostname or IP of your Redis server.
        
    *   _Default_: localhost
        
*   **REDIS\_PORT**
    
    *   _Description_: The port your Redis server is running on.
        
    *   _Default_: 6379
        
*   **RATE\_LIMIT\_COUNT**
    
    *   _Description_: Maximum number of requests allowed from a single IP within the time window.
        
    *   _Default_: 100
        
*   **RATE\_LIMIT\_WINDOW**
    
    *   _Description_: The time window for rate limiting, in seconds.
        
    *   _Default_: 60
        
*   **BAN\_DURATION**
    
    *   _Description_: How long an IP is banned after hitting the BAN\_SCORE\_THRESHOLD, in seconds.
        
    *   _Default_: 300
        
*   **THREAT\_SCORE\_THRESHOLD**
    
    *   _Description_: A request with a total score above this value will be **blocked** with a 403 error.
        
    *   _Default_: 15
        
*   **BAN\_SCORE\_THRESHOLD**
    
    *   _Description_: A request with a total score above this value will cause the source IP to be **banned**.
        
    *   _Default_: 25
        
*   **WAF\_MODE**
    
    *   _Description_: Set to passthrough to disable all security checks, which is useful for benchmarking performance.
        
    *   _Default_: enforcing
      
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


Running the WAF
---------------

``` redis-server ```

**Run the Logger Service (in a separate terminal/process):**

```python logger.py```
