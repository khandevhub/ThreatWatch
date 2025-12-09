# collector.py (pro) - unchanged core but with logging and timestamp normalization
import os, time, json, logging
from detector import process_event, init_db
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("collector")

LOGFILE_LINUX = os.environ.get("LOG_PATH", "/var/log/auth.log")
SIM_FILE = os.environ.get("SIM_FILE", "simulated_logs.jsonl")
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", "0.5"))

def tail_file(path, callback):
    logger.info("Tailing file: %s", path)
    try:
        with open(path, 'r') as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(POLL_INTERVAL)
                    continue
                callback(line)
    except Exception as e:
        logger.exception("Error tailing file: %s", e)
        raise

def handle_line(line):
    line = line.strip()
    if not line:
        return
    if 'Failed password' in line or 'authentication failure' in line:
        parts = line.split()
        src = 'unknown'
        for p in parts:
            if p.count('.')==3:
                src = p
                break
        evt = {'type':'auth_failed','src':src,'message':line,'time':datetime.utcnow().isoformat()}
        process_event(evt)
        logger.info("Processed auth failure from %s", src)

def process_sim_file(path):
    logger.info("Processing simulated logs: %s", path)
    try:
        with open(path,'r') as f:
            for line in f:
                try:
                    evt = json.loads(line)
                    if 'time' not in evt:
                        evt['time'] = datetime.utcnow().isoformat()
                    process_event(evt)
                except json.JSONDecodeError:
                    logger.warning("Skipping invalid JSON line")
    except Exception as e:
        logger.exception("Error processing simulated file: %s", e)
        raise

if __name__ == '__main__':
    init_db()
    if os.path.exists(LOGFILE_LINUX):
        logger.info("Found linux log: %s", LOGFILE_LINUX)
        try:
            tail_file(LOGFILE_LINUX, handle_line)
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
    elif os.path.exists(SIM_FILE):
        process_sim_file(SIM_FILE)
    else:
        logger.info("No system log and no simulated file. Creating sample %s", SIM_FILE)
        sample = [
            {"type":"auth_failed","src":"192.168.1.10","message":"Failed password for invalid user"},
            {"type":"auth_failed","src":"192.168.1.10","message":"Failed password for invalid user"},
            {"type":"auth_failed","src":"192.168.1.10","message":"Failed password for invalid user"},
            {"type":"auth_failed","src":"192.168.1.10","message":"Failed password for invalid user"},
            {"type":"auth_failed","src":"192.168.1.10","message":"Failed password for invalid user"},
            {"type":"port_scan","src":"192.168.1.20","ports":[22,80,443]},
            {"type":"traffic_spike","bytes":12345678}
        ]
        with open(SIM_FILE,'w') as f:
            for s in sample:
                f.write(json.dumps(s) + "\n")
        logger.info("Wrote sample %s. Run collector again to process it.", SIM_FILE)
