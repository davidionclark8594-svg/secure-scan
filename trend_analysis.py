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