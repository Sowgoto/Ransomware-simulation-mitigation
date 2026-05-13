import sqlite3
import json
import logging
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timedelta

# Config
DB_PATH = "monitor.db"
EXPECTED_USER = "ss4334"
WHITELISTED_PROCESSES = {"explorer.exe", "bash", "python", "systemd"}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.StreamHandler()]
)

# Fetch recent events from DB
def fetch_recent_events(db_path: str, limit=100):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT ts_human, action, path, candidates FROM events ORDER BY ts DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    events = []
    for ts_human, action, path, candidates_json in rows:
        candidates = json.loads(candidates_json) if candidates_json else []
        events.append({
            "ts_human": ts_human,
            "action": action,
            "path": path,
            "candidates": candidates
        })
    return events

# Define violation based on user/process policy
def is_violation(event):
    action = event["action"]
    candidates = event["candidates"]

    # Allow all creations by default 
    if action == "created":
        return False

    # For modified or deleted files:
    for proc in candidates:
        user = proc.get("username", "").lower()
        proc_name = (proc.get("name") or "").lower()
        if user != EXPECTED_USER.lower():
            logging.warning(f"Violation: {action} by unauthorized user {user}")
            return True
        if proc_name not in WHITELISTED_PROCESSES:
            logging.warning(f"Violation: {action} by unapproved process {proc_name}")
            return True

    # If no processes found for modification/deletion event -> suspicious
    if not candidates:
        logging.warning(f"Violation: {action} with no candidate processes")
        return True

    return False

# Helper: print alert messages clearly
def print_alert(message):
    print(f"[ALERT] {message}")

# Detect violations and print alerts
def detect_policy_violations(db_path, mitigation_callback=None):
    events = fetch_recent_events(db_path)
    logging.info(f"Analyzing {len(events)} recent events for violations...")

    # look for burst of modified events 
    modified_events = [e for e in events if e["action"] == "modified"]
    recent_modifications = defaultdict(list)  # key: timestamp day/minute, value: paths

    # Group modified files by minute to detect burst activity
    for e in modified_events:
        try:
            ts = datetime.fromisoformat(e["ts_human"].replace("Z", ""))
            key = ts.replace(second=0, microsecond=0)  # group by minute
            recent_modifications[key].append(e["path"])
        except Exception:
            continue

    # Check for bursts of modifications in a minute 
    for key, paths in recent_modifications.items():
        if len(paths) >= 5:
            print_alert(f"Suspicious activity detected: Multiple files modified within a short period ({len(paths)} files at {key.isoformat()})")

    # Now check individual events for violations
    for event in events:
        if is_violation(event):
            print_alert(f"Potential ransomware activity detected on file: {event['path']} at {event['ts_human']}")
            if mitigation_callback:
                mitigation_callback(event)
            else:
                logging.warning(f"Violation detected but no mitigation applied: {event}")

# Main runner
def main():
    detect_policy_violations(DB_PATH)

if __name__ == "__main__":
    main()
