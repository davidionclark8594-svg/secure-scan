from colorama import Fore


def print_scan_summary(
    total_matches,
    report_path,
    json_report_path,
    html_report_path,
    csv_report_path,
    files_scanned,
    files_skipped,
    scan_duration,
):
    print(f"HTML report saved to: {html_report_path}")

    print(
        f"✅ Folder scan complete. Total matches: {total_matches}"
    )

    print(
        f"📄 Combined report saved to: {report_path}"
    )

    print(
        f"🧾 JSON report saved to: {json_report_path}"
    )

    print("\n--- Scan Statistics ---")

    print(f"Files scanned: {files_scanned}")
    print(f"Files skipped: {files_skipped}")
    print(
        f"Scan duration: {scan_duration} seconds"
    )

    print("\n--- Severity Summary ---")


def print_risk_summary(
    severity_counts,
    risk_score,
    risk_level,
):
    print(
        Fore.RED
        + f"HIGH findings: {severity_counts['HIGH']}"
    )

    print(
        Fore.YELLOW
        + f"MEDIUM findings: {severity_counts['MEDIUM']}"
    )

    print(
        Fore.GREEN
        + f"LOW findings: {severity_counts['LOW']}"
    )

    print(
        f"Overall Risk Score: {risk_score}"
    )

    print(
        Fore.MAGENTA
        + f"Risk Level: {risk_level}"
    )


def print_vulnerability_history(
    history_summary,
):
    print("\nVulnerability History:")

    print(
        "Tracked:",
        history_summary["total_tracked"],
    )

    print(
        "Active:",
        history_summary["active_count"],
    )

    print(
        "New:",
        history_summary["new_count"],
    )

    print(
        "Fixed:",
        history_summary["fixed_count"],
    )

    print(
        "Reappeared:",
        history_summary["reappeared_count"],
    )