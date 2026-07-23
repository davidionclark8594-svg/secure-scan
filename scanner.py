
import time
from colorama import init
init(autoreset=True)
from trend_analysis import (
    save_scan_history,
    get_previous_scan,
    get_changed_scan_history,
)
from vulnerability_history import (update_vulnerability_history,)
from scan_statistics import (build_scan_statistics,)
from console_output import (print_scan_summary, print_risk_summary, print_vulnerability_history,)
from scan_engine import scan_folder
from report_manager import write_all_reports
from scan_setup import (
    parse_arguments,
    clean_reports_directory,
    build_scan_paths,
)

def main():
    print("🧠 Directory Log Scanner")

    args = parse_arguments()

    clean_reports_directory()

    start_time = time.time()

    scan_setup = build_scan_paths(
        args.scan
    )

    base_dir = scan_setup[
        "base_dir"
    ]

    folder_path = scan_setup[
        "folder_path"
    ]

    report_paths = scan_setup[
        "report_paths"
    ]

    report_path = report_paths["text"]
    json_report_path = report_paths["json"]
    html_report_path = report_paths["html"]
    csv_report_path = report_paths["csv"]

    if not folder_path.exists() or not folder_path.is_dir():
        print(f"❌ Not a folder: {folder_path}")
        return

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("", encoding="utf-8")  # clear report

    scan_results = scan_folder(
        folder_path,
        report_path,
    )

    json_findings = scan_results[
        "findings"
    ]

    total_matches = scan_results[
        "total_matches"
    ]

    files_scanned = scan_results[
        "files_scanned"
    ]

    files_skipped = scan_results[
        "files_skipped"
    ]

    severity_counts = scan_results[
        "severity_counts"
    ]

    scan_duration = round(
        time.time() - start_time,
        2,
    )

    scan_statistics = build_scan_statistics(
        severity_counts
)

    risk_score = scan_statistics[
        "risk_score"
    ]

    risk_level = scan_statistics[
        "risk_level"
    ]

    total_findings = scan_statistics[
        "total_findings"
    ]

    previous_scan = get_previous_scan()
    scan_history = get_changed_scan_history(10)

    save_scan_history(
        severity_counts,
        risk_score
    )

    vulnerability_history_summary = (
        update_vulnerability_history(
            json_findings
        )
    )

    generated_reports = write_all_reports(
        report_paths,
        total_matches,
        json_findings,
        risk_level,
        previous_scan,
        scan_history,
    )

    print_scan_summary(
        total_matches,
        report_path,
        json_report_path,
        html_report_path,
        csv_report_path,
        files_scanned,
        files_skipped,
        scan_duration
    )

    print_risk_summary(
    severity_counts,
    risk_score,
    risk_level,
)

    print_vulnerability_history(
        vulnerability_history_summary
    )
    
if __name__ == "__main__":
    main()

