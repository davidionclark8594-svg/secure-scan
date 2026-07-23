import json
import os
from datetime import datetime


def save_scan_history(severity_counts, risk_score):

    history_file = "scan_history.json"

    history = []

    if os.path.exists(history_file):
        with open(history_file, "r") as file:
            history = json.load(file)

    history.append({
        "timestamp": datetime.now().strftime("%Y-%m_%d %H:%M:%S"),
        "high": severity_counts.get("HIGH", 0),
        "medium": severity_counts.get("MEDIUM", 0),
        "low": severity_counts.get("LOW", 0),
        "risk_score": risk_score
    })

    with open(history_file, "w") as file:
        json.dump(history, file, indent=4)

def get_previous_scan():

    history_file = "scan_history.json"

    if not os.path.exists(history_file):
        return None

    with open(history_file, "r") as file:
        history = json.load(file)

    if len(history) < 2:
        return None

    return history[-2]

def get_scan_history(limit=None):
    """
    Returns the full scan history.

    If limit is provided, only the newest 'limit'
    scans are returned.
    """

    history_file = "scan_history.json"

    if not os.path.exists(history_file):
        return []

    with open(history_file, "r") as file:
        history = json.load(file)

    if limit is not None:
        return history[-limit:]

    return history

def get_changed_scan_history(limit=None):
    """
    Returns scan history while removing consecutive
    scans that contain identical security results.
    """

    history = get_scan_history()
    changed_history = []

    previous_signature = None

    for scan in history:
        current_signature = (
            scan.get("high", 0),
            scan.get("medium", 0),
            scan.get("low", 0),
            scan.get("risk_score", 0),
        )

        if current_signature != previous_signature:
            changed_history.append(scan)
            previous_signature = current_signature

    if limit is not None:
        return changed_history[-limit:]

    return changed_history