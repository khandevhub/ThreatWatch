# detector.py - full working detector
import sqlite3, os, logging
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger('detector')

DB = os.environ.get('DB_FILE', 'db.sqlite')
DETECTION_WINDOW = int(os.environ.get('DETECTION_WINDOW', '60'))
BRUTE_FORCE_THRESHOLD = int(os.environ.get('BRUTE_FORCE_THRESHOLD', '5'))
THREAT_INTEL = os.environ.get('THREAT_INTEL', 'threat_intel.csv')


def load_threat_intel(path):
    """Load threat-intel IPs from a newline-separated CSV (header: ip,tag).

    Tolerates a stray BOM. Returns {ip: tag}; the default tag for untagged
    entries is 'known_threat'. (Line-splitting assumes the file uses real
    newlines; the repo-wide newline corruption is repaired separately.)
    """
    table = {}
    if not path or not os.path.exists(path):
        logger.warning('Threat intel file not found: %s', path)
        return table
    with open(path, 'r', encoding='utf-8-sig', newline='') as f:
        for lineno, raw in enumerate(f, start=1):
            line = raw.strip()
            if not line or line.lower().startswith('ip'):
                continue
            parts = [p.strip() for p in line.split(',')]
            if not parts or not parts[0]:
                continue
            tag = parts[1] if len(parts) > 1 and parts[1] else 'known_threat'
            table[parts[0]] = tag
    return table


bad_ips = load_threat_intel(THREAT_INTEL)


def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT, rule TEXT, severity TEXT, details TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS alert_enrichment (id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id INTEGER NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL)''')
    conn.commit()
    conn.close()


def push_alert(rule, severity, details, enrichment=None):
    """Write an alert row and, when provided, key/value enrichment rows."""
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        t = datetime.utcnow().isoformat()
        c.execute("INSERT INTO alerts (time, rule, severity, details) VALUES (?, ?, ?, ?)", (t, rule, severity, details))
        alert_id = c.lastrowid
        if enrichment:
            for k, v in enrichment.items():
                c.execute("INSERT INTO alert_enrichment (alert_id, key, value) VALUES (?, ?, ?)", (alert_id, k, v))
        conn.commit()
        conn.close()
        logger.info('[ALERT] %s %s %s', t, rule, details)
    except Exception:
        logger.exception('Failed to write alert')


failed_logins = {}


def process_event(evt):
    """Process one normalized event dict and emit alerts as needed."""
    typ = evt.get('type')
    if typ == 'auth_failed':
        src = evt.get('src', 'unknown')
        now = datetime.utcnow()
        lst = failed_logins.get(src, [])
        lst = [t for t in lst if t > now - timedelta(seconds=DETECTION_WINDOW)]
        lst.append(now)
        failed_logins[src] = lst
        if len(lst) >= BRUTE_FORCE_THRESHOLD:
            enrichment = {'source_ip': src, 'known_threat': 'true' if src in bad_ips else 'false'}
            tag = bad_ips.get(src)
            note = f' [{tag.upper()}]' if tag else ''
            push_alert(
                'BRUTE_FORCE', 'HIGH',
                f'Multiple failed logins from {src}: {len(lst)} attempts' + note,
                enrichment,
            )
            failed_logins[src] = []
    elif typ == 'port_scan':
        src = evt.get('src', 'unknown')
        ports = evt.get('ports', [])
        enrichment = {'source_ip': src, 'known_threat': 'true' if src in bad_ips else 'false'}
        tag = bad_ips.get(src)
        note = f' [{tag.upper()}]' if tag else ''
        push_alert('PORT_SCAN', 'MEDIUM', f'Port scan detected from {src} - ports: {ports}' + note, enrichment)
    elif typ == 'traffic_spike':
        bytes_val = evt.get('bytes', 0)
        src = evt.get('src', 'unknown')
        enrichment = {'source_ip': src, 'known_threat': 'true' if src in bad_ips else 'false'}
        tag = bad_ips.get(src)
        note = f' [KNOWN_THREAT]' if src in bad_ips else ''
        push_alert('TRAFFIC_SPIKE', 'LOW', f'High outbound traffic: {bytes_val} bytes' + note, enrichment)
    else:
        logger.debug('Unhandled event type: %s', typ)


if __name__ == '__main__':
    init_db()
    for _ in range(5):
        process_event({'type': 'auth_failed', 'src': '10.0.0.5'})
    print('Detector self-test complete. Check the alerts table in', DB)
