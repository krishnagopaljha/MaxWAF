# logger.py
from flask import Flask, jsonify, request, render_template_string
import datetime
import os
import sqlite3

app = Flask(__name__)

LOG_DIR = 'logs'
DATABASE = os.path.join(LOG_DIR, 'logger.db')

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

def init_db():
    """Initializes the database, adding the new threat_score column."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            source_ip TEXT,
            path TEXT,
            details TEXT,
            threat_score INTEGER
        )
    ''')
    # Add the threat_score column if it doesn't exist (for backward compatibility)
    try:
        cursor.execute("ALTER TABLE logs ADD COLUMN threat_score INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass # Column already exists
    
    conn.commit()
    conn.close()
    print(f"Database initialized successfully at {DATABASE}")

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>WAF Security Dashboard</title>
    <style>
        body { font-family: system-ui, sans-serif; background-color: #121212; color: #e0e0e0; margin: 0; padding: 25px; }
        h1 { text-align: center; color: #03dac6; border-bottom: 2px solid #03dac6; padding-bottom: 10px; }
        .filter-nav { text-align: center; margin-bottom: 25px; }
        .filter-btn { background-color: #333; color: #e0e0e0; border: 1px solid #555; padding: 10px 15px; margin: 0 5px; border-radius: 20px; cursor: pointer; transition: all 0.3s; }
        .filter-btn.active, .filter-btn:hover { background-color: #03dac6; color: #121212; border-color: #03dac6; font-weight: bold; }
        #log-container { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 15px; }
        .log-entry { background-color: #1e1e1e; border-radius: 8px; padding: 15px; box-shadow: 0 4px 8px rgba(0,0,0,0.5); border-left: 5px solid; word-wrap: break-word; }
        .log-entry strong { color: #bb86fc; }
        .log-entry .details { color: #cf6679; }
        /* Color coding for attack types */
        .log-entry.sqli { border-color: #f44336; }
        .log-entry.xss { border-color: #ff9800; }
        .log-entry.ddos { border-color: #9c27b0; }
        .log-entry.xxe { border-color: #03a9f4; }
        .log-entry.cmdi { border-color: #e91e63; } /* Command Injection */
        .log-entry.trav { border-color: #4caf50; } /* Traversal */
        .log-entry.ssrf { border-color: #ffeb3b; } /* NEW: SSRF */
        .log-entry.jwt { border-color: #ffffff; }  /* NEW: JWT */
    </style>
</head>
<body>
    <h1>🛡 WAF Security Dashboard</h1>
    <div class="filter-nav">
        <button class="filter-btn active" data-filter="All">All</button>
        <button class="filter-btn" data-filter="SQL Injection">SQLi</button>
        <button class="filter-btn" data-filter="Cross-Site Scripting (XSS)">XSS</button>
        <button class="filter-btn" data-filter="Command Injection">CMDi</button>
        <button class="filter-btn" data-filter="Directory Traversal">Traversal</button>
        <button class="filter-btn" data-filter="DDoS / Rate Limit">DDoS</button>
        <button class="filter-btn" data-filter="SSRF">SSRF</button>
        <button class="filter-btn" data-filter="JWT">JWT</button>
    </div>
    <div id="log-container"></div>
    <script>
        let allLogs = []; let currentFilter = 'All';
        const typeClassMap = {
            'SQL Injection': 'sqli', 'Cross-Site Scripting (XSS)': 'xss', 'DDoS / Rate Limit': 'ddos',
            'XML External Entity (XXE)': 'xxe', 'Command Injection': 'cmdi', 'Directory Traversal': 'trav',
            'Server-Side Request Forgery (SSRF)': 'ssrf', 'JWT Alg:None Attack': 'jwt'
        };
        const escape = (str) => String(str).replace(/[&<>"']/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
        
        function createLogElement(log) {
            let typeClass = '';
            for (const type in typeClassMap) {
                if (log.attack_type.includes(type)) { typeClass = typeClassMap[type]; break; }
            }
            return `
                <div class="log-entry ${typeClass}">
                    <strong>Type:</strong> ${escape(log.attack_type)} [Score: ${log.threat_score}]<br>
                    <strong>Time:</strong> ${new Date(log.timestamp).toLocaleString()}<br>
                    <strong>IP:</strong> ${escape(log.source_ip)}<br>
                    <strong>Path:</strong> ${escape(log.path)}<br>
                    <strong>Details:</strong> <span class="details">${escape(log.details)}</span>
                </div>`;
        }
        function renderLogs() {
            const container = document.getElementById('log-container');
            container.innerHTML = '';
            const filteredLogs = allLogs.filter(log => currentFilter === 'All' || log.attack_type.includes(currentFilter));
            filteredLogs.forEach(log => { container.innerHTML += createLogElement(log); });
        }
        async function fetchLogs() {
            try {
                const response = await fetch('/api/logs');
                allLogs = await response.json();
                renderLogs();
            } catch (error) { console.error("Error fetching logs:", error); }
        }
        document.querySelectorAll('.filter-btn').forEach(button => {
            button.addEventListener('click', () => {
                document.querySelector('.filter-btn.active').classList.remove('active');
                button.classList.add('active');
                currentFilter = button.getAttribute('data-filter');
                renderLogs();
            });
        });
        setInterval(fetchLogs, 2000);
        document.addEventListener('DOMContentLoaded', fetchLogs);
    </script>
</body>
</html>
"""

@app.route('/')
def dashboard():
    return render_template_string(DASHBOARD_TEMPLATE)

@app.route('/log', methods=['POST'])
def log_event():
    log_data = request.json
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO logs (timestamp, attack_type, source_ip, path, details, threat_score)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                datetime.datetime.now().isoformat(),
                log_data.get('attack_type', 'Unknown'),
                log_data.get('source_ip'),
                log_data.get('path'),
                log_data.get('details'),
                log_data.get('threat_score', 0)
            )
        )
        conn.commit()
        conn.close()
        return jsonify({"status": "logged"}), 200
    except Exception as e:
        print(f"[ERROR] Could not write to database: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/logs')
def get_logs():
    try:
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 100")
        logs = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify(logs)
    except Exception as e:
        print(f"[ERROR] Could not read from database: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    init_db()
    app.run(port=8081, host='0.0.0.0')
