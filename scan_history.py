import json
from pathlib import Path
from datetime import datetime

HISTORY_FILE = Path("scan_history.json")


def load_scan_history():
    if not HISTORY_FILE.exists():
        return []

    with open(HISTORY_FILE, "r") as file:
        return json.load(file)


def save_scan_history(history):
    with open(HISTORY_FILE, "w") as file:
        json.dump(history, file, indent=4)


def add_scan(
    total_findings,
    high,
    medium,
    low,
    risk_score,
):
    history = load_scan_history()

    history.append({
        "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "total": total_findings,
        "high": high,
        "medium": medium,
        "low": low,
        "risk_score": risk_score,
    })

    save_scan_history(history)