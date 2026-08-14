import argparse
import glob
import os
import shutil

from datetime import datetime
from pathlib import Path


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="SecureScan - Application Security Scanner"
    )

    parser.add_argument(
        "--scan",
        default="data",
        help="Folder to scan. Default is data.",
    )

    return parser.parse_args()

def clean_reports_directory():
    for old_report in glob.glob("reports/*"):
        try:
            if os.path.isdir(old_report):
                shutil.rmtree(old_report)
            else:
                os.remove(old_report)
        except Exception as error:
            print(
                f"Could not remove {old_report}: {error}"
            )

def build_scan_paths(scan_folder):
    base_dir = Path(__file__).resolve().parent

    folder_path = (
        base_dir / scan_folder
    ).resolve()

    timestamp = datetime.now().strftime(
        "%Y-%m-%d_%H-%M-%S"
    )

    report_path = (
        base_dir
        / "reports"
        / f"scan_report_{timestamp}.txt"
    ).resolve()

    json_report_path = (
        base_dir
        / "reports"
        / f"scan_report_{timestamp}.json"
    ).resolve()

    html_report_path = (
        base_dir
        / "reports"
        / f"scan_report_{timestamp}.html"
    ).resolve()

    csv_report_path = (
        base_dir
        / "reports"
        / f"scan_report_{timestamp}.csv"
    ).resolve()

    report_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    report_path.write_text(
        "",
        encoding="utf-8",
    )

    return {
        "base_dir": base_dir,
        "folder_path": folder_path,
        "report_paths": {
            "text": report_path,
            "json": json_report_path,
            "html": html_report_path,
            "csv": csv_report_path,
        },
    }