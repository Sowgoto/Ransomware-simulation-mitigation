#!/usr/bin/env python3
"""
Requirements: pip install watchdog psutil

"""
import argparse
import json
import sqlite3
import time
import traceback
from datetime import datetime
from pathlib import Path

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except Exception as e:
    raise SystemExit("Missing dependency 'watchdog'. Install with: pip install watchdog") from e

try:
    import psutil
except Exception as e:
    raise SystemExit("Missing dependency 'psutil'. Install with: pip install psutil") from e


DEFAULT_DB = "monitor.db" # Default SQLite DB path

# Database helpers for tables events and alerts
def init_db(conn: sqlite3.Connection):
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL,
        ts_human TEXT NOT NULL,
        action TEXT NOT NULL,
        path TEXT NOT NULL,
        is_dir INTEGER NOT NULL,
        candidates TEXT  -- JSON list of candidate process info
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL,
        ts_human TEXT NOT NULL,
        reason TEXT NOT NULL,
        details TEXT
    )""")
    conn.commit()

# def insert_event helper for events table
def insert_event(conn: sqlite3.Connection, ts: float, action: str, path: str, is_dir: bool, candidates):
    c = conn.cursor()
    c.execute(
        "INSERT INTO events (ts, ts_human, action, path, is_dir, candidates) VALUES (?, ?, ?, ?, ?, ?)",
        (ts, datetime.utcfromtimestamp(ts).isoformat() + "Z", action, path, int(is_dir), json.dumps(candidates))
    )
    conn.commit()

# def insert_alert helper for alerts table
def insert_alert(conn: sqlite3.Connection, ts: float, reason: str, details: dict):
    c = conn.cursor()
    c.execute(
        "INSERT INTO alerts (ts, ts_human, reason, details) VALUES (?, ?, ?, ?)",
        (ts, datetime.utcfromtimestamp(ts).isoformat() + "Z", reason, json.dumps(details))
    )
    conn.commit()


# Process attribution helpers 
def find_candidate_processes_for_path(path: Path, max_candidates=5):
    """
    Try to find processes that have this path open.
    """
    candidates = []
    try:
        for p in psutil.process_iter(['pid', 'name', 'username']):
            try:
                files = p.open_files()
                for f in files:
                    try:
                        if Path(f.path).resolve() == path.resolve():
                            candidates.append({"pid": p.pid, "name": p.info.get("name"), "username": p.info.get("username")})
                            break
                    except Exception:
                        continue
                if len(candidates) >= max_candidates:
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        traceback.print_exc()
    return candidates

# Detection logic
class SimpleRateDetector:
    def __init__(self, threshold: int = 0, window: float = 0.0):
        self.threshold = threshold
        self.window = window

    def add_event_and_check(self, ts: float):
        # Trigger alert immediately on any event
        return True, 1

# Watchdog event handler
class DBLoggingHandler(FileSystemEventHandler):
    def __init__(self, db_conn: sqlite3.Connection, detector: SimpleRateDetector, verbose=True):
        super().__init__()
        self.conn = db_conn
        self.detector = detector
        self.verbose = verbose

    def _handle(self, action: str, src_path: str, is_dir: bool, dest_path: str = None):
        ts = time.time()
        path_obj = Path(src_path)
        candidates = find_candidate_processes_for_path(path_obj)
        insert_event(self.conn, ts, action, str(path_obj), is_dir, candidates)

        if self.verbose:
            now = datetime.fromtimestamp(ts).isoformat()
            print(f"[{now}] {action.upper():8} {src_path} (dir={is_dir}) candidates={len(candidates)}")
            for c in candidates[:3]:
                print(f"    - pid={c['pid']} name={c.get('name')} user={c.get('username')}")

        triggered, count = self.detector.add_event_and_check(ts)
        if triggered:
            reason = f"Detected event: {action.upper()} on {str(path_obj)}"
            details = {"event_action": action, "path": str(path_obj), "candidates": candidates}
            insert_alert(self.conn, ts, reason, details)
            print("=" * 60)
            print(f"ALERT: {reason}")
            print("A mitigation action should be taken (suspend process / notify admin / restore backup).")
            print("Alert details written to DB.")
            print("=" * 60)

    def on_modified(self, event):
        self._handle("modified", event.src_path, event.is_directory)

    def on_created(self, event):
        self._handle("created", event.src_path, event.is_directory)

    def on_deleted(self, event):
        self._handle("deleted", event.src_path, event.is_directory)

    def on_moved(self, event):
        self._handle("moved", event.src_path, event.is_directory, getattr(event, 'dest_path', None))


# Main runner
def resolve_target_dir(provided: str = None) -> Path:
    if provided:
        t = Path(provided).expanduser()
        if not t.exists():
            print(f"Provided target {t} does not exist. Creating it.")
            t.mkdir(parents=True, exist_ok=True)
        return t.resolve()

    # Default preference order:
    local = Path.cwd() / "personal_ss4334"
    home = Path.home() / "personal_ss4334"
    for candidate in (local, home):
        if candidate.exists():
            return candidate.resolve()
    # If none exist, create local
    local.mkdir(parents=True, exist_ok=True)
    return local.resolve()


def main():
    parser = argparse.ArgumentParser(description="Real-time FS monitor for Ransomware project. Press Ctrl+C to stop.")
    parser.add_argument("--target", "-t", help="Target directory to monitor (default: ./personal_ss4334 or ~/personal_ss4334)", default=None)
    parser.add_argument("--db", "-d", help="SQLite DB path (default: ./monitor.db)", default=DEFAULT_DB)
    parser.add_argument("--verbose", action="store_true", default=True, help="Verbose real-time output (default: True)")
    args = parser.parse_args()

    target = resolve_target_dir(args.target)
    db_path = Path(args.db).resolve()

    print("=" * 60)
    print(f"Monitoring target: {target}")
    print(f"Logging DB: {db_path}")
    print("Triggering alert on ANY file event.")
    print("Press Ctrl+C to stop.")
    print("=" * 60)

    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    init_db(conn)

    detector = SimpleRateDetector(threshold=0, window=0.0)  # Immediate alert
    handler = DBLoggingHandler(conn, detector, verbose=args.verbose)
    observer = Observer()
    observer.schedule(handler, str(target), recursive=True)

    try:
        observer.start()
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\nStopping monitor (Ctrl+C received)...")
        observer.stop()
    except Exception as e:
        print("Unexpected error:", e)
        traceback.print_exc()
        observer.stop()
    observer.join()
    conn.close()
    print("Monitor stopped. DB closed.")


if __name__ == "__main__":
    main()
