import json

from csv_report import write_csv_report
from html_report import write_html_report


def write_json_report(
    json_report_path,
    total_matches,
    findings,
):
    output = {
        "total_matches": total_matches,
        "findings": findings,
    }

    json_report_path.write_text(
        json.dumps(
            output,
            indent=2,
        ),
        encoding="utf-8",
    )


def write_all_reports(
    report_paths,
    total_matches,
    findings,
    risk_level,
    previous_scan,
    scan_history,
):
    """
    Generate all structured scan reports.

    The text report is already written by
    scan_engine while files are scanned.
    """
    write_json_report(
        report_paths["json"],
        total_matches,
        findings,
    )

    write_html_report(
        report_paths["html"],
        findings,
        risk_level,
        previous_scan,
        scan_history,
    )

    write_csv_report(
        report_paths["csv"],
        findings,
    )

    return {
        "text": report_paths["text"],
        "json": report_paths["json"],
        "html": report_paths["html"],
        "csv": report_paths["csv"],
    }