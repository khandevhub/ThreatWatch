# detector.py — detection engine with threat-intel integration
import sqlite3, os, csv, logging
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("detector")

DB = os.environ.get("DB_FILE", "db.sqlite")
DETECTION_WINDOW = int(os.environ.get("DETECTION_WINDOW", "60"))
BRUTE_FORCE_THRESHOLD = int(os.environ.get("BRUTE_FORCE_THRESHOLD", "5"))
TRAFFIC_SPIKE_THRESHOLD = int(os.environ.get("TRAFFIC_SPIKE_THRESHOLD", "1000000"))

INTEL_FILE = os.environ.get("INTEL_FILE", "intel/blacklist.csv")
blacklist = set()
try:
    if os.path.exists(INTEL_FILE):
        with open(INTEL_FILE, 'r') as f:
            rdr = csv.DictReader(f)
            for r in rdr:
                ip = r.get('ip')
                if ip:
                    blacklist.add(ip.strip())
    logger.info("Loaded %d intel entries", len(blacklist))
except Exception as e:
    logger.exception("Failed loading intel: %s", e)

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        time TEXT,
        rule TEXT,
        severity TEXT,
        details TEXT
    )''')
    conn.commit()
    conn.close()

def push_alert(rule, severity, details):
    try:
        sev = severity
        for ip in blacklist:
            if ip in details:
                sev = 'CRITICAL' if severity=='HIGH' else 'HIGH'
                details = details + f" | KNOWN_THREAT:{ip}"
                break
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        t = datetime.utcnow().isoformat()
        c.execute("INSERT INTO alerts (time, rule, severity, details) VALUES (?, ?, ?, ?)", (t, rule, sev, details))
        conn.commit()
        conn.close()
        logger.info("[ALERT] %s %s %s", t, rule, details)
    except Exception as e:
        logger.exception("Failed to push alert: %s", e)

failed_logins = {}

def process_event(evt):
    typ = evt.get('type')
    if typ == 'auth_failed':
        src = evt.get('src', 'unknown')
        now = datetime.utcnow()
        lst = failed_logins.get(src, [])
        lst = [t for t in lst if t > now - timedelta(seconds=DETECTION_WINDOW)]
        lst.append(now)
        failed_logins[src] = lst
        logger.debug("Failed attempts for %s: %d", src, len(lst))
        if len(lst) >= BRUTE_FORCE_THRESHOLD:
            push_alert("BRUTE_FORCE", "HIGH", f"Multiple failed logins from {src}: {len(lst)} attempts")
            failed_logins[src] = []
    elif typ == 'port_scan':
        src = evt.get('src', 'unknown')
        ports = evt.get('ports', [])
        push_alert("PORT_SCAN", "MEDIUM", f"Port scan detected from {src} - ports: {ports}")
    elif typ == 'traffic_spike':
        bytes_val = int(evt.get('bytes', 0))
        if bytes_val >= TRAFFIC_SPIKE_THRESHOLD:
            push_alert("TRAFFIC_SPIKE", "LOW", f"High outbound traffic: {bytes_val} bytes")
    else:
        logger.debug("Unhandled event type: %s", typ)

if __name__ == '__main__':
    init_db()
    process_event({'type':'auth_failed','src':'10.0.0.5'})
    process_event({'type':'auth_failed','src':'10.0.0.5'})
    process_event({'type':'auth_failed','src':'10.0.0.5'})
    process_event({'type':'auth_failed','src':'10.0.0.5'})
    process_event({'type':'auth_failed','src':'10.0.0.5'})
