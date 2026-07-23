import html
import re
from pathlib import Path


def create_safe_filename(value):
    """
    Convert a category name into a safe filename.

    Example:
    'A03: Injection' becomes 'a03-injection'
    """

    safe_value = value.lower().strip()

    safe_value = re.sub(
        r"[^a-z0-9]+",
        "-",
        safe_value,
    )

    return safe_value.strip("-")


def generate_owasp_drilldown_pages(
    findings,
    main_report_path,
):
    """
    Generate one HTML page for every OWASP category.

    Returns a dictionary that maps each OWASP category
    to its generated relative HTML path.
    """

    main_report_path = Path(main_report_path)

    drilldown_directory = (
        main_report_path.parent / "drilldowns"
    )

    drilldown_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    findings_by_owasp = {}

    for finding in findings:
        owasp = finding.get(
            "owasp",
            "UNKNOWN",
        ).strip()

        if owasp not in findings_by_owasp:
            findings_by_owasp[owasp] = []

        findings_by_owasp[owasp].append(finding)

    generated_pages = {}

    for owasp, category_findings in findings_by_owasp.items():
        safe_filename = create_safe_filename(owasp)

        output_path = (
            drilldown_directory /
            f"{safe_filename}.html"
        )

        high_count = sum(
            1
            for finding in category_findings
            if finding.get("severity") == "HIGH"
        )

        medium_count = sum(
            1
            for finding in category_findings
            if finding.get("severity") == "MEDIUM"
        )

        low_count = sum(
            1
            for finding in category_findings
            if finding.get("severity") == "LOW"
        )

        unique_vulnerabilities = len({
            finding.get("keyword", "UNKNOWN")
            for finding in category_findings
        })

        affected_files = len({
            finding.get("file", "UNKNOWN")
            for finding in category_findings
        })

        cvss_scores = [
            float(finding.get("cvss", 0) or 0)
            for finding in category_findings
        ]

        average_cvss = round(
            sum(cvss_scores) / max(len(cvss_scores), 1),
            2,
        )

        highest_cvss = max(
            cvss_scores,
            default=0,
        )

        rows = ""

        for finding in category_findings:
            keyword = html.escape(
                str(
                    finding.get(
                        "keyword",
                        "UNKNOWN",
                    )
                )
            )

            severity = html.escape(
                str(
                    finding.get(
                        "severity",
                        "UNKNOWN",
                    )
                )
            )

            cvss = html.escape(
                str(
                    finding.get(
                        "cvss",
                        0,
                    )
                )
            )

            file_path = html.escape(
                str(
                    finding.get(
                        "file",
                        "UNKNOWN",
                    )
                )
            )

            line_number = html.escape(
                str(
                    finding.get(
                        "line",
                        0,
                    )
                )
            )

            remediation = html.escape(
                str(
                    finding.get(
                        "remediation",
                        "No recommendation available",
                    )
                )
            )

            rows += f"""
            <tr>
                <td>{keyword}</td>
                <td>{severity}</td>
                <td>{cvss}</td>
                <td>{file_path}</td>
                <td>{line_number}</td>
                <td>{remediation}</td>
            </tr>
            """

        category_title = html.escape(owasp)

        page_html = f"""
<!DOCTYPE html>

<html>
<head>
    <meta charset="UTF-8">

    <title>{category_title} Drill-Down</title>

    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 30px;
            background: #f8fafc;
            color: #111827;
        }}

        .header {{
            background: #1f2937;
            color: white;
            padding: 24px;
            border-radius: 10px;
            margin-bottom: 25px;
        }}

        .summary-card {{
            background: white;
            border: 1px solid #d1d5db;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 25px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
        }}

        th,
        td {{
            border: 1px solid #d1d5db;
            padding: 10px;
            text-align: left;
            vertical-align: top;
        }}

        th {{
            background: #e5e7eb;
        }}

        .back-link {{
            display: inline-block;
            margin-bottom: 20px;
            color: #2563eb;
            font-weight: bold;
            text-decoration: none;
        }}

        .back-link:hover {{
            text-decoration: underline;
        }}
    </style>
</head>

<body>

<a class="back-link" href="../{main_report_path.name}">
    ← Back to Secure Scan Report
</a>

<div class="header">
    <h1>{category_title}</h1>
    <p>OWASP Security Finding Drill-Down</p>
</div>

<div class="metrics-grid">
    <div class="metric-card">
        <strong>Total Findings</strong>
        <span>{len(category_findings)}</span>
    </div>

    <div class="metric-card">
        <strong>Unique Vulnerabilities</strong>
        <span>{unique_vulnerabilities}</span>
    </div>

    <div class="metric-card">
        <strong>Affected Files</strong>
        <span>{affected_files}</span>
    </div>

    <div class="metric-card">
        <strong>Average CVSS</strong>
        <span>{average_cvss}</span>
    </div>

    <div class="metric-card">
        <strong>Highest CVSS</strong>
        <span>{highest_cvss}</span>
    </div>

    <div class="metric-card severity-high">
        <strong>HIGH</strong>
        <span>{high_count}</span>
    </div>

    <div class="metric-card severity-medium">
        <strong>MEDIUM</strong>
        <span>{medium_count}</span>
    </div>

    <div class="metric-card severity-low">
        <strong>LOW</strong>
        <span>{low_count}</span>
    </div>
</div>

<table>
    <tr>
        <th>Finding</th>
        <th>Severity</th>
        <th>CVSS</th>
        <th>Affected File</th>
        <th>Line</th>
        <th>Recommended Action</th>
    </tr>

    {rows}
</table>

</body>
</html>
"""

        with open(
            output_path,
            "w",
            encoding="utf-8",
        ) as page:
            page.write(page_html)

        generated_pages[owasp] = (
            f"drilldowns/{output_path.name}"
        )

    return generated_pages