from flask import Flask, render_template, jsonify, request
import sqlite3, os
from datetime import datetime, timedelta

app = Flask(__name__)
DB = os.environ.get("DB_FILE", "db.sqlite")

def get_alerts(limit=200):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT id,time,rule,severity,details FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    alerts = [{"id": r[0], "time": r[1], "rule": r[2], "severity": r[3], "details": r[4]} for r in rows]
    return alerts

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/alerts')
def api_alerts():
    sev = request.args.get('severity')
    typ = request.args.get('type')
    alerts = get_alerts(500)
    if sev:
        alerts = [a for a in alerts if a['severity'].lower()==sev.lower()]
    if typ:
        alerts = [a for a in alerts if a['rule'].lower()==typ.lower()]
    return jsonify(alerts)

@app.route('/api/summary')
def api_summary():
    alerts = get_alerts(1000)
    totals = {}
    by_sev = {}
    for a in alerts:
        totals[a['rule']] = totals.get(a['rule'],0)+1
        by_sev[a['severity']] = by_sev.get(a['severity'],0)+1
    return jsonify({"counts": totals, "severity": by_sev})

if __name__ == '__main__':
    if not os.path.exists(DB):
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT, rule TEXT, severity TEXT, details TEXT)''')
        conn.commit()
        conn.close()
    app.run(debug=True)
