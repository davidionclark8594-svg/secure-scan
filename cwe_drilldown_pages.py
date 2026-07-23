from collections import defaultdict
from pathlib import Path
import html
import re


def create_safe_cwe_filename(value):
    safe_value = re.sub(
        r"[^a-zA-Z0-9_-]+",
        "_",
        str(value),
    )

    return safe_value.strip("_").lower()


def generate_cwe_drilldown_pages(
    findings,
    main_report_path,
):
    report_path = Path(main_report_path)
    output_directory = report_path.parent / "cwe_drilldowns"

    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    findings_by_cwe = defaultdict(list)

    for finding in findings:
        cwe = str(
            finding.get(
                "cwe",
                "CWE Not Assigned",
            )
        ).strip()

        if not cwe:
            cwe = "CWE Not Assigned"

        findings_by_cwe[cwe].append(finding)

    generated_pages = {}

    for cwe, cwe_findings in findings_by_cwe.items():
        safe_name = create_safe_cwe_filename(cwe)
        page_filename = f"{safe_name}.html"
        page_path = output_directory / page_filename

        severity_counts = {
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }

        cvss_scores = []
        affected_files = set()
        finding_names = set()
        rows = ""

        for finding in cwe_findings:
            severity = str(
                finding.get(
                    "severity",
                    "UNKNOWN",
                )
            ).upper()

            if severity in severity_counts:
                severity_counts[severity] += 1

            try:
                cvss_scores.append(
                    float(
                        finding.get(
                            "cvss",
                            0,
                        )
                    )
                )
            except (TypeError, ValueError):
                pass

            file_path = str(
                finding.get(
                    "file",
                    "UNKNOWN",
                )
            )

            finding_name = str(
                finding.get(
                    "keyword",
                    finding.get(
                        "finding",
                        "UNKNOWN",
                    ),
                )
            )

            affected_files.add(file_path)
            finding_names.add(finding_name)

            rows += f"""
            <tr>
                <td>
                    {html.escape(finding_name)}
                </td>

                <td class="{severity.lower()}">
                    {html.escape(severity)}
                </td>

                <td>
                    {html.escape(file_path)}
                </td>

                <td>
                    {html.escape(
                        str(
                            finding.get(
                                "line",
                                "UNKNOWN",
                            )
                        )
                    )}
                </td>

                <td>
                    {html.escape(
                        str(
                            finding.get(
                                "owasp",
                                "Not Assigned",
                            )
                        )
                    )}
                </td>

                <td>
                    {html.escape(
                        str(
                            finding.get(
                                "cvss",
                                0,
                            )
                        )
                    )}
                </td>

                <td>
                    {html.escape(
                        str(
                            finding.get(
                                "confidence",
                                "UNKNOWN",
                            )
                        )
                    )}
                </td>

                <td>
                    {html.escape(
                        str(
                            finding.get(
                                "remediation",
                                "No remediation available.",
                            )
                        )
                    )}
                </td>
            </tr>
            """

        average_cvss = (
            sum(cvss_scores) / len(cvss_scores)
            if cvss_scores
            else 0
        )

        highest_cvss = (
            max(cvss_scores)
            if cvss_scores
            else 0
        )

        page_html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>{html.escape(cwe)} Details</title>

    <style>
        body {{
            background: #f4f6f8;
            color: #1f2933;
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 30px;
        }}

        .container {{
            margin: auto;
            max-width: 1500px;
        }}

        .back-link {{
            display: inline-block;
            margin-bottom: 24px;
            text-decoration: none;
        }}

        .metrics-grid {{
            display: grid;
            gap: 16px;
            grid-template-columns:
                repeat(
                    auto-fit,
                    minmax(180px, 1fr)
                );
            margin: 24px 0;
        }}

        .metric-card {{
            background: white;
            border-radius: 10px;
            box-shadow:
                0 2px 8px
                rgba(0, 0, 0, 0.08);
            padding: 20px;
        }}

        .metric-value {{
            font-size: 28px;
            font-weight: bold;
            margin-top: 8px;
        }}

        .high {{
            color: #b91c1c;
            font-weight: bold;
        }}

        .medium {{
            color: #b45309;
            font-weight: bold;
        }}

        .low {{
            color: #15803d;
            font-weight: bold;
        }}

        table {{
            background: white;
            border-collapse: collapse;
            width: 100%;
        }}

        th,
        td {{
            border: 1px solid #d9e2ec;
            padding: 12px;
            text-align: left;
            vertical-align: top;
        }}

        th {{
            background: #243b53;
            color: white;
        }}

        tr:nth-child(even) {{
            background: #f8fafc;
        }}

        .table-wrapper {{
            overflow-x: auto;
        }}
    </style>
</head>

<body>
    <div class="container">
        <a
            class="back-link"
            href="../{report_path.name}"
        >
            ← Back to Secure Scan Report
        </a>

        <h1>{html.escape(cwe)}</h1>

        <p>
            Detailed vulnerability information for this
            Common Weakness Enumeration category.
        </p>

        <div class="metrics-grid">
            <div class="metric-card">
                <div>Total Findings</div>

                <div class="metric-value">
                    {len(cwe_findings)}
                </div>
            </div>

            <div class="metric-card">
                <div>Unique Vulnerabilities</div>

                <div class="metric-value">
                    {len(finding_names)}
                </div>
            </div>

            <div class="metric-card">
                <div>Affected Files</div>

                <div class="metric-value">
                    {len(affected_files)}
                </div>
            </div>

            <div class="metric-card">
                <div>Average CVSS</div>

                <div class="metric-value">
                    {average_cvss:.1f}
                </div>
            </div>

            <div class="metric-card">
                <div>Highest CVSS</div>

                <div class="metric-value">
                    {highest_cvss:.1f}
                </div>
            </div>

            <div class="metric-card">
                <div>High Severity</div>

                <div class="metric-value high">
                    {severity_counts["HIGH"]}
                </div>
            </div>

            <div class="metric-card">
                <div>Medium Severity</div>

                <div class="metric-value medium">
                    {severity_counts["MEDIUM"]}
                </div>
            </div>

            <div class="metric-card">
                <div>Low Severity</div>

                <div class="metric-value low">
                    {severity_counts["LOW"]}
                </div>
            </div>
        </div>

        <h2>Findings</h2>

        <div class="table-wrapper">
            <table>
                <tr>
                    <th>Finding</th>
                    <th>Severity</th>
                    <th>File</th>
                    <th>Line</th>
                    <th>OWASP</th>
                    <th>CVSS</th>
                    <th>Confidence</th>
                    <th>Remediation</th>
                </tr>

                {rows}
            </table>
        </div>
    </div>
</body>
</html>
"""

        page_path.write_text(
            page_html,
            encoding="utf-8",
        )

        generated_pages[cwe] = (
            f"cwe_drilldowns/{page_filename}"
        )

    return generated_pages