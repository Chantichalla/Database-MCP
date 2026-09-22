"""Append-only structured audit log (JSON lines, one event per line).

A3: zero-dependency audit logger. B4 adds SIEM-ready stderr alerting
via ALERT_EVENTS (see below).
"""
import json
import sys
import time
from pathlib import Path

# Project-root-anchored default; override with AUDIT_LOG_PATH env var.
AUDIT_LOG = Path(__file__).resolve().parent.parent.parent / "audit.log"

# B4: high-severity event types also emit a structured ALERT line to stderr
# so Docker/systemd -> Datadog/CloudWatch/Splunk can ingest with zero code.
ALERT_EVENTS = {"CIRCUIT_BREAKER_TRIP", "MUTATION_REJECTED", "QUERY_REJECTED"}


def log_event(event_type: str, **fields):
    """Append a single JSON-lines audit entry; also ALERT to stderr if severe."""
    entry = {"ts": time.time(), "type": event_type, **fields}
    line = json.dumps(entry, default=str)
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        # Audit must never break query execution.
        pass
    if event_type in ALERT_EVENTS:
        try:
            print(f"ALERT [{event_type}] {json.dumps(fields, default=str)}",
                  file=sys.stderr)
        except Exception:
            pass


def read_last_events(n: int = 20):
    """Return the last N audit events (oldest-first). Empty list if no log."""
    try:
        with open(AUDIT_LOG, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except (OSError, FileNotFoundError):
        return []
    events = []
    for line in lines[-max(1, n):]:
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events
