from scan_comparison import compare_scans
from drilldown_pages import generate_owasp_drilldown_pages
from file_detail_pages import generate_file_detail_pages
from metrics import (calculate_scan_metrics, calculate_top_risky_files, calculate_remediation_queue, calculate_historical_progress, calculate_previous_scan_changes,)
from report_components.executive import (get_executive_metrics_section, get_executive_summary_section,)
from report_components.header import (get_header_section, get_scan_summary_section,)
from report_components.history import (get_historical_progress_section, get_vulnerability_timeline_section,)
from report_components.charts import (get_risk_distribution_section,)
from report_components.findings import (get_top_findings_section, get_most_common_findings_section,)
from report_components.risky_files import (get_top_risky_files_section,)
from report_components.remediation import (get_remediation_queue_section,)
from report_components.owasp import (get_owasp_categories_section,)
from report_components.tables import (get_findings_table_section,)
from report_components.styles import (get_report_styles,)
from report_components.scripts import (get_report_scripts,)
from collections import Counter
from cwe_drilldown_pages import (generate_cwe_drilldown_pages,)
from report_components.cwe import (get_cwe_categories_section,)
from report_components.dashboard import (get_dashboard_section,)
import html

def write_html_report(report_path, findings, risk_level, previous_scan, scan_history):

    metrics = calculate_scan_metrics(findings)
    top_risky_files = calculate_top_risky_files(findings)
    remediation_queue = calculate_remediation_queue(findings)

    owasp_drilldown_pages = generate_owasp_drilldown_pages(
        findings,
        report_path,
    )

    cwe_counts = Counter(
        str(
            finding.get(
                "cwe",
                "CWE Not Assigned",
            )
        ).strip()
        or "CWE Not Assigned"
        for finding in findings
    )

    cwe_drilldown_pages = generate_cwe_drilldown_pages(
        findings,
        report_path,
    )

    file_detail_pages = generate_file_detail_pages(
    findings,
    report_path,
)

    historical_progress = calculate_historical_progress(
    scan_history,
    metrics["current_risk_score"],
    metrics["total_findings"],
)
    
    previous_changes = calculate_previous_scan_changes(
    previous_scan,
    metrics["high_count"],
    metrics["medium_count"],
    metrics["low_count"],
    metrics["current_risk_score"],
)

    high_count = metrics["high_count"]
    medium_count = metrics["medium_count"]
    low_count = metrics["low_count"]
    total_findings = metrics["total_findings"]

    owasp_counts = metrics["owasp_counts"]
    owasp_category_count = metrics["owasp_category_count"]

    unique_findings = metrics["unique_findings"]
    unique_vulnerability_count = metrics[
        "unique_vulnerability_count"
    ]

    file_count = metrics["file_count"]
    average_cvss = metrics["average_cvss"]
    highest_cvss = metrics["highest_cvss"]
    confidence_percent = metrics["confidence_percent"]
    critical_finding_rate = metrics["critical_finding_rate"]
    risk_density = metrics["risk_density"]
    remediation_load = metrics["remediation_load"]

    current_risk_score = metrics["current_risk_score"]
    risk_score_per_file = metrics["risk_score_per_file"]
    security_posture_score = metrics[
        "security_posture_score"
    ]

    top_findings = metrics["top_findings"]
    most_common_findings = metrics[
        "most_common_findings"

    ]

    starting_risk_score = historical_progress[
        "starting_risk_score"
    ]

    latest_risk_score = historical_progress[
        "latest_risk_score"
    ]

    starting_findings = historical_progress[
        "starting_findings"
    ]

    latest_findings = historical_progress[
        "latest_findings"
    ]

    historical_risk_change = historical_progress[
        "historical_risk_change"
    ]

    historical_improvement = historical_progress[
        "historical_improvement"
    ]

    historical_status = historical_progress[
        "historical_status"
    ]

    high_change = previous_changes["high_change"]
    medium_change = previous_changes["medium_change"]
    low_change = previous_changes["low_change"]
    risk_change = previous_changes["risk_change"]
    previous_total = previous_changes["previous_total"]

    
    comparison = compare_scans(
        previous_total,
        total_findings,
        previous_scan.get("risk_score", 0) if previous_scan else 0,
        current_risk_score
    )

    with open(report_path, "w") as report:
        report.write(f"""   
                                  
<html>
<head>
<title>Secure Scan Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>

{get_report_styles()}

</head>
                     
<body>
                     
{get_header_section()}

{get_dashboard_section(
    total_findings,
    current_risk_score,
    high_count,
    owasp_category_count,
    len(cwe_counts),
    file_count,
)}
                     
{get_scan_summary_section(high_count, medium_count, low_count, total_findings, risk_level)}

{get_executive_metrics_section(
    unique_vulnerability_count,
    file_count,
    average_cvss,
    highest_cvss,
    confidence_percent,
    owasp_category_count,
    critical_finding_rate,
    risk_density,
    remediation_load,
    risk_score_per_file,
    security_posture_score
)}

{get_executive_summary_section(
    total_findings,
    high_count,
    risk_level,
    current_risk_score,
    high_change,
    medium_change,
    low_change,
    risk_change,
    comparison
)}

{get_risk_distribution_section()}

{get_historical_progress_section(
    starting_risk_score,
    latest_risk_score,
    historical_risk_change,
    starting_findings,
    latest_findings,
    historical_improvement,
    historical_status
)}

{get_vulnerability_timeline_section()}

{get_top_findings_section(top_findings)}

{get_top_risky_files_section(top_risky_files, file_detail_pages)}

{get_remediation_queue_section(remediation_queue)}

{get_most_common_findings_section(most_common_findings)}

{get_owasp_categories_section(owasp_counts, owasp_drilldown_pages)} 

{get_cwe_categories_section(cwe_counts, cwe_drilldown_pages,)}
                     
{get_findings_table_section(findings)}

{get_report_scripts(high_count, medium_count, low_count, scan_history)}

        </body>
        </html>
        """)