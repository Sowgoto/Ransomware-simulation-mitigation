import json
import logging
import os
import signal
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path
import smtplib
from email.message import EmailMessage

try:
    import psutil
except ImportError:
    print("Please install psutil with: pip install psutil")
    sys.exit(1)

# Configure logging to file + console
LOG_FILE = "mitigation.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)

DB_PATH = "monitor.db"
EUID = "ss4334"  # The expected user for legitimate processes

# Backup folder 
BACKUP_DIR = Path("backup")
MONITOR_DIR = Path.home() / "personal_ss4334"
def alert_admin(event_action: str, file_path: str, timestamp: str, process_info: list):
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 587
    EMAIL_ADDRESS = "raha.sowgoto14@gmail.com" # email address
    EMAIL_PASSWORD = "eoli sfim esjb feec"  # Use app password for Gmail

    subject = f"URGENT: Security Alert - {event_action.upper()} Detected on {file_path}"
    
    process_details = "No suspicious processes identified."
    if process_info:
        lines = []
        for proc in process_info:
            pid = proc.get('pid', 'N/A')
            name = proc.get('name', 'N/A')
            user = proc.get('username', 'N/A')
            lines.append(f"- PID: {pid}, Name: {name}, User: {user}")
        process_details = "\n".join(lines)

    body = f"""
Hello Admin,

A security alert has been triggered by our automated monitoring system.

Details:
----------
Action Detected: {event_action}
File/Path: {file_path}
Timestamp: {timestamp}

Suspicious Processes Involved:
{process_details}

Recommended Actions:
- Immediately review the suspicious processes listed above.
- Check system logs and investigate the cause of the file {event_action}.
- Restore any critical files from backup if necessary.
- Report any confirmed security breaches to the security team.
If you need assistance, please contact the IT security department immediately.
This message was generated automatically by the security monitoring system.

Regards,
Automated Security System
"""

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = EMAIL_ADDRESS
    msg.set_content(body)

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
            logging.info("Alert email sent successfully.")
    except Exception as e:
        logging.error(f"Failed to send alert email: {e}")

# Suspend suspicious process by PID    
def suspend_process(pid: int) -> bool:
    """
    Attempt to suspend the suspicious process by PID.
    Returns True on success, False otherwise.
    """
    try:
        p = psutil.Process(pid)
        p.suspend()
        logging.info(f"Suspended process PID={pid}, name={p.name()}")
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
        logging.error(f"Failed to suspend PID={pid}: {e}")
        return False

# Terminate suspicious process by PID
def terminate_process(pid: int) -> bool:
    """
    Terminate a process forcibly.
    """
    try:
        p = psutil.Process(pid)
        p.terminate()
        p.wait(timeout=3)
        logging.info(f"Terminated process PID={pid}, name={p.name()}")
        return True
    except Exception as e:
        logging.error(f"Failed to terminate PID={pid}: {e}")
        return False

# Restore file from backup
def restore_backup(file_path: Path):
    backup_file = BACKUP_DIR / file_path.name
    if backup_file.exists():
        try:
            dest_file = file_path
            if dest_file.exists():
                dest_file.unlink()
            backup_file.replace(dest_file)
            logging.info(f"Restored {file_path} from backup")
        except Exception as e:
            logging.error(f"Failed to restore {file_path}: {e}")
    else:
        logging.warning(f"No backup found for {file_path}")

# Handle a single defense-in-depth violation event
def defense_in_depth_violation_handler(event):
    action = event['action']
    path = Path(event['path'])
    ts_human = event['ts_human']
    candidates = json.loads(event.get('candidates', '[]'))

    logging.info(f"Mitigation triggered for {action} on {path} at {ts_human}")

    # Alert admin about the event with detailed info
    alert_admin(
        event_action=action,
        file_path=str(path),
        timestamp=ts_human,
        process_info=candidates
    )

    # Attempt to suspend suspicious processes 
    if candidates:
        for c in candidates:
            pid = c.get('pid')
            if pid:
                if suspend_process(pid):
                    logging.info(f"Process {pid} suspended successfully")
                else:
                    logging.warning(f"Attempting to terminate process {pid} as fallback")
                    terminate_process(pid)
    else:
        logging.warning("No candidate processes found for event; unable to suspend/terminate.")

    # if a critical file deleted/modified, try restore
    if action in ("deleted", "modified"):
        restore_backup(path)

    logging.info("Mitigation completed.\n")

# Fetch policy violations from DB
def fetch_policy_violations(db_path: str):
    """
    Fetch events that are flagged as violations or suspicious from DB.
    This can be customized to fetch specific alerts or events.
    """
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    # Assuming alerts table stores policy violation alerts
    c.execute("SELECT ts_human, reason, details FROM alerts ORDER BY ts DESC LIMIT 10")
    rows = c.fetchall()
    conn.close()

    violations = []
    for row in rows:
        ts_human, reason, details_json = row
        details = json.loads(details_json)
        violations.append({
            'ts_human': ts_human,
            'reason': reason,
            'details': details,
        })
    return violations


def main():
    logging.info("Mitigation component started.")
    violations = fetch_policy_violations(DB_PATH)

    if not violations:
        logging.info("No violations detected in DB.")
        return

    for idx, violation in enumerate(violations, 1):
        logging.info(f"Processing violation #{idx}: {violation['reason']} at {violation['ts_human']}")

        # Extract event info from violation details
        details = violation['details']
        event = {
            'action': details.get('action', 'unknown'),
            'path': details.get('example_path', ''),
            'ts_human': violation['ts_human'],
            'candidates': json.dumps(details.get('candidates', []))
        }
        defense_in_depth_violation_handler(event)

    logging.info("Mitigation component finished.")

if __name__ == "__main__":
    main()
