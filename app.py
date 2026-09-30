# app.py - Flask dashboard for ThreatWatch
from flask import Flask, render_template, jsonify
import sqlite3, os

app = Flask(__name__)
DB = os.environ.get('DB_FILE', 'db.sqlite')


def get_alerts(limit=200):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT id, time, rule, severity, details FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return [{"id": r[0], "time": r[1], "rule": r[2], "severity": r[3], "details": r[4]} for r in rows]


@app.route('/')
def index():
    return render_template('dashboard.html')


@app.route('/api/alerts')
def api_alerts():
    return jsonify(get_alerts())


@app.route('/api/summary')
def api_summary():
    alerts = get_alerts(1000)
    summary = {}
    for a in alerts:
        summary[a['rule']] = summary.get(a['rule'], 0) + 1
    return jsonify(summary)


if __name__ == '__main__':
    conn = sqlite3.connect(DB)
    conn.execute('''CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT, rule TEXT, severity TEXT, details TEXT)''')
    conn.commit()
    conn.close()
    app.run(debug=False, threaded=True)
