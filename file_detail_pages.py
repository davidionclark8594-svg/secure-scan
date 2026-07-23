from pathlib import Path
import html
import re


def safe_filename(value):
    value = value.lower().strip()

    value = re.sub(
        r"[^a-z0-9]+",
        "-",
        value,
    )

    return value.strip("-")

def generate_file_detail_pages(
    findings,
    report_path,
):
    """
    Creates one HTML page for every affected file.

    Returns a dictionary mapping each full file path
    to its generated relative HTML page.
    """

    report_path = Path(report_path)

    output_directory = (
        report_path.parent /
        "files"
    )

    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    findings_by_file = {}

    for finding in findings:
        file_name = finding.get(
            "file",
            "UNKNOWN",
        )

        findings_by_file.setdefault(
            file_name,
            [],
        ).append(finding)

    generated_pages = {}

    severity_weights = {
        "HIGH": 10,
        "MEDIUM": 5,
        "LOW": 1,
    }

    severity_rank = {
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "UNKNOWN": 0,
    }

    for file_name, file_findings in findings_by_file.items():
        safe_name = safe_filename(file_name)

        output_file = (
            output_directory /
            f"{safe_name}.html"
        )

        high_count = sum(
            1
            for finding in file_findings
            if finding.get("severity") == "HIGH"
        )

        medium_count = sum(
            1
            for finding in file_findings
            if finding.get("severity") == "MEDIUM"
        )

        low_count = sum(
            1
            for finding in file_findings
            if finding.get("severity") == "LOW"
        )

        risk_score = sum(
            severity_weights.get(
                finding.get("severity", "UNKNOWN"),
                0,
            )
            for finding in file_findings
        )

        highest_severity = "UNKNOWN"

        for finding in file_findings:
            severity = finding.get(
                "severity",
                "UNKNOWN",
            )

            if severity_rank.get(
                severity,
                0,
            ) > severity_rank.get(
                highest_severity,
                0,
            ):
                highest_severity = severity

        owasp_categories = sorted({
            finding.get("owasp", "UNKNOWN")
            for finding in file_findings
        })

        cvss_scores = [
            float(finding.get("cvss", 0) or 0)
            for finding in file_findings
        ]

        average_cvss = round(
            sum(cvss_scores) /
            max(len(cvss_scores), 1),
            2,
        )

        highest_cvss = max(
            cvss_scores,
            default=0,
        )

        rows = ""

        for finding in file_findings:
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

            owasp = html.escape(
                str(
                    finding.get(
                        "owasp",
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

            line_number = html.escape(
                str(
                    finding.get(
                        "line",
                        0,
                    )
                )
            )

            content = html.escape(
                str(
                    finding.get(
                        "content",
                        "No content available",
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
                <td>{owasp}</td>
                <td>{cvss}</td>
                <td>{line_number}</td>
                <td>{content}</td>
                <td>{remediation}</td>
            </tr>
            """

        owasp_list = "".join(
            f"<li>{html.escape(category)}</li>"
            for category in owasp_categories
        )

        display_name = html.escape(
            Path(file_name).name
        )

        full_path = html.escape(
            str(file_name)
        )

        page_html = f"""
<!DOCTYPE html>

<html>
<head>
    <meta charset="UTF-8">

    <title>{display_name} Security Details</title>

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

        .header p {{
            word-break: break-all;
            color: #cbd5e1;
        }}

        .metrics-grid {{
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            margin-bottom: 25px;
        }}

        .metric-card {{
            min-width: 170px;
            background: white;
            border: 1px solid #d1d5db;
            border-radius: 10px;
            padding: 18px;
        }}

        .metric-card strong {{
            display: block;
            margin-bottom: 8px;
            color: #4b5563;
        }}

        .metric-card span {{
            font-size: 26px;
            font-weight: bold;
        }}

        .severity-high {{
            border-left: 5px solid #dc2626;
        }}

        .severity-medium {{
            border-left: 5px solid #f59e0b;
        }}

        .severity-low {{
            border-left: 5px solid #16a34a;
        }}

        .category-card {{
            background: white;
            border: 1px solid #d1d5db;
            border-radius: 10px;
            padding: 18px;
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

<a class="back-link" href="../{report_path.name}">
    ← Back to Secure Scan Report
</a>

<div class="header">
    <h1>{display_name}</h1>
    <p>{full_path}</p>
</div>

<div class="metrics-grid">
    <div class="metric-card">
        <strong>Total Findings</strong>
        <span>{len(file_findings)}</span>
    </div>

    <div class="metric-card">
        <strong>Risk Score</strong>
        <span>{risk_score}</span>
    </div>

    <div class="metric-card">
        <strong>Highest Severity</strong>
        <span>{highest_severity}</span>
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

<div class="category-card">
    <h2>OWASP Categories</h2>

    <ul>
        {owasp_list}
    </ul>
</div>

<h2>Findings</h2>

<table>
    <tr>
        <th>Finding</th>
        <th>Severity</th>
        <th>OWASP</th>
        <th>CVSS</th>
        <th>Line</th>
        <th>Content</th>
        <th>Recommended Action</th>
    </tr>

    {rows}
</table>

</body>
</html>
"""

        with open(
            output_file,
            "w",
            encoding="utf-8",
        ) as page:
            page.write(page_html)

        generated_pages[file_name] = (
            f"files/{output_file.name}"
        )

    return generated_pages