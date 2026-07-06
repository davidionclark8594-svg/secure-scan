def write_html_report(report_path, findings, severity_counts, total_findings, risk_level, previous_scan):

    high_count = 0
    medium_count = 0
    low_count = 0
    owasp_counts = {}
    unique_findings = {}

    for finding in findings:
        owasp = repr(finding.get("owasp", "UNKNOWN"))
        print(owasp)

        clean_owasp = finding.get("owasp", "UNKNOWN").strip()

        owasp_counts[clean_owasp]= owasp_counts.get(clean_owasp, 0) + 1
        keyword = finding.get("keyword")

        if keyword not in unique_findings:
            unique_findings[keyword] = finding

    top_findings = sorted(
        unique_findings.values(),
        key=lambda finding: finding.get("cvss", 0),
        reverse=True
    )[:5]

    print("\nTotal findings passed into HTML report:")
    print(len(findings))

    print("\nFirst 5 findings:")
    for finding in findings[:5]:
        print(findings)

    finding_counts = {}

    for finding in findings:
        keyword = finding.get("keyword", "UNKNOWN")

    if keyword not in finding_counts:
        finding_counts[keyword] = 0

    from collections import Counter

    finding_counts = Counter()

    for finding in findings:
        keyword = finding.get("keyword", "UNKNOWN")
        finding_counts[keyword] +=1

    most_common_findings = finding_counts.most_common(5)

    for finding in findings:
        severity = finding["severity"]     

        owasp = finding.get("owasp", "UNKNOWN").strip()

        if owasp not in owasp_counts:
            owasp_counts[owasp] = 0
        
        owasp_counts[owasp] += 1

        if severity == "HIGH":
            high_count += 1

        elif severity == "MEDIUM":
            medium_count += 1

        elif severity == "LOW":
            low_count += 1

        risk_color = {
            "CRITICAL": "#ff4d4d",
            "HIGH": "#ff944d",
            "MEDIUM": "#ffd24d",
            "LOW": "#66cc66",
        }.get(risk_level, "#cccccc")

    if previous_scan:
        high_change = severity_counts["HIGH"] - previous_scan.get("high", 0)
        medium_change = severity_counts["MEDIUM"] - previous_scan.get("medium", 0)
        low_change = severity_counts["LOW"] - previous_scan.get("low", 0)
        
        current_risk_score = (
            severity_counts["HIGH"] * 10 +
            severity_counts["MEDIUM"] * 5 +
            severity_counts["LOW"] * 1
        )

        risk_change = current_risk_score - previous_scan.get("risk_score", 0)
    else:
        high_change = "No previous scan"
        medium_change = "No previous scan"
        low_change = "No previous scan"
        risk_change = "No previous scan"

    executive_summary = f"""
    This scan analyzed {total_findings} security findings across the target codebase.

    {high_count} findings were classified as HIGH severity, contributing to an overall {risk_level} risk posture.

    Immediate remediation should prioritize credential exposure, injection vulnerabilities, and security misconfigurations identified in the highest-risk findings.

    <h2>Overall Risk Assessment</h2>

    <div class="risk-assessment-card">

        <div class="risk-title">
            {risk_level}
        </div>

        <div class="risk-score-label">
            Risk Score
        </div>

        <div class="risk-score">
            {current_risk_score}
        </div>

    </div>

    <h2>Historical Trend Analysis</h2>

<div class="trend-grid">
    <div class="trend-card">
        <strong>HIGH Change</strong>
        <span>{high_change}</span>
    </div>

    <div class="trend-card">
        <strong>MEDIUM Change</strong>
        <span>{medium_change}</span>
    </div>

    <div class="trend-card">
        <strong>LOW Change</strong>
        <span>{low_change}</span>
    </div>

    <div class="trend-card">
        <strong>Risk Score Change</strong>
        <span>{risk_change}</span>
    </div>
</div>
"""

    with open(report_path, "w") as report:
        report.write(f"""   
              
<html>
<head>
<title>Secure Scan Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
                     
body {{
    font-family: Arial;
    margin: 20px;
}}

table {{
    border-collapse: collapse;
    width: 100%;
}}

th, td {{
    border: 1px solid black;
    padding: 8px;
}}

th {{
    background-color: #dddddd;
}}
                     
.high {{
    background-color: #ffcccc;
    color: #990000;
    font-weight: bold;
}}
                     
.medium {{
    background-color: #fff3cd;
    color: #856404;
    font-weight: bold;
}}

.low {{
    background-color: #d4edda;
    color: #155724;
    font-weight: bold;
}}     

.dashboard {{
    display: flex;
    flex-wrap: wrap;
    gap: 15px;
    margin-bottom: 25px;
}} 

.card {{
    border: 1px solid #ddd;
    border-radius: 8px;
    padding: 15px;
    min-width: 150px;
    height: auto;
}}
                     
.card .number {{
    font-size: 28px;
    font-weight: bold;
    margin-top: 5px;
}}
                     
.summary-card {{
    border: 1px solid #ddd;
    border-radius: 8px;
    padding: 25px;
    margin-bottom: 25px;
}}
                     
.summary-box p {{
    font-size: 16px;
    line-height: 1.6;
    white-space: pre-line;
}}
                     
.chart-container {{
    margin-bottom: 30px;
}}

.chart-row {{
    margin: 12px 0;
}}

.chart-row span {{
    display: inline-block;
    width: 150px;
    font-weight: bold;
}}

.chart-card {{
    border: 1px solid #ddd;
    border-radius: 10px;
    padding: 25px;
    margin-bottom: 30px;
    background: #fafafa;
    max-width: 600px;
}}

.bar {{
    display: inline-block;
    height: 25px;
    border-radius: 4px;
}}

.high-bar {{
    background-color: #dc3545;
}}

.medium-bar {{
    background-color: #ffc107;
}}

.low-bar {{
    background-color: #28a745;
}}
                     
.trend-card {{
    border: 1px solid #ddd;
    border-radius: 8px;
    padding: 12px;
    min-width: 140px;
    height: auto;
}}
                     
.trend-dashboard {{
    display: flex;
    gap: 15px;
    flex-wrap: wrap;
    margin-bottom: 30px;
    clear: both;
}}
                     
.trend-dashboard .card {{
    width: 180px;
    min-height: 60px;
    height: auto;
}}
                     
.trend-grid {{
    display: flex;
    gap: 15px;
    flex-wrap: wrap;
    margin-bottom: 25px;
}}
                     
.trend-card {{
    border: 1px solid #ddd;
    border-radius: 8px;
    padding: 15px;
    min-width: 160px;
    background-color: #fafafa;
}}
                     
.trend-card strong {{
    display: block;
    margin-bottom: 8px;
}}
                     
.trend-card span {{
    font-size: 20px;
    font-weight: bold;
}}
                     
.header {{
    background:#2d3748;
    color:white;
    padding:25px;
    border-radius:10px
    margin-bottom:25px;
}}
                     
.header h1 {{
    margin:0;
}}
                     
.header p {{
    margin-top:8px;
    color:#cbd5e0;
}}
                     
.risk-critical {{
    background-color: #ffe5e5;
    border: 6px solid #dc3545;
    color: #990000;
    font-weight: bold;
}}
                     
.risk-assessment-card {{
    border:2px solid #dc3545;
    border-radius:10px;
    padding:20px;
    margin-bottom:30px;
    background:#fff5f5;
}}
                     
.risk-title {{
    font-size:30px;
    font-weight:bold;
    color:#b30000;
}}
                     
.risk-score-label {{
    margin-top:12px;
    font-size:18px;
    color:#555;
}}
                     
.risk-score {{
    font-size:42px;
    font-weight:bold;
    color:#111;
}}

.risk-high {{
    background: #fff0e0;
    border:2px solid #ff9900;
    color:#cc6600;
}}

.risk-medium {{
    background: #fff9d6;
    border:2px solid #ffcc00;
    color:#856404;
}}

.risk-low {{
    background: #e6ffe6;
    border:2px solid #28a745;
    color:#155724;
}}     

.filter-buttons {{
    margin-bottom: 20px;
}}    

.filter-buttons button {{
    padding: 12px 22px;
    font-size: 16px;
    margin: 5px;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    font-weight: bold;
}}     

.export-button {{
    margin: 15px 0;
}}  

.export-button button {{
    background-color: #2563eb;
    color: white;
    padding: 14px 26px;
    font-size: 18px;
    font-weight: bold;
    border: none;
    border-radius: 8px;
    cursor: pointer;
    margin-bottom: 15px;
}}  
                     
.export-button button:hover {{
    background-color: #1d4ed8;
    transform: scale(1.03);
}}
                     
#findingSearch {{
    width: 500px !important;
    padding: 15px !important;
    font-size: 18px !important;
    border-radius: 6px;
    border: 3px solid red !important;
}}
                                                                                                                
</style>
</head>
                     
<body>
                     
<div class="header">
    <h1>Secure Scan Report</h1>
    <p>Application Security Analysis Dashboard</p>
</div>
                     
<h2>Scan Summary</h2>

<div class="dashboard">
                     
    <div class="card">
        <div>HIGH</div>
        <div class="number">{high_count}</div>
    </div>

    <div class="card">
        <div>MEDIUM</div>
        <div class="number">{medium_count}</div>
    </div>

    <div class="card">
        <div>LOW</div>
        <div class="number">{low_count}</div>
    </div>

    <div class="card">
        <div>TOTAL</div>
        <div class="number">{total_findings}</div>
    </div>

    <div class="card risk-critical">
        <div class="label">RISK LEVEL</div>
        <div class="number">{risk_level}</div>
    </div>

</div>

<h2>Executive Summary</h2>

<div class="summary-card">
     <p>{executive_summary}</p>
</div>

<h2>Risk Distribution</h2>

<div class="chart-card">
    <canvas id="riskChart"></canvas>
</div>

<div style="clear: both;"></div>

<h2>Top 5 Highest-Risk Findings</h2>

<table>
<tr>
    <th>Rank</th>
    <th>Keyword</th>
    <th>Severity</th>
    <th>CVSS</th>
    <th>Confidence</th>
    <th>OWASP</th>
</tr>

{"".join(
    f"""
    <tr>
        <td>#{i}</td>
        <td>{finding.get('keyword', '')}</td>
        <td>{finding.get('severity', '')}</td>
        <td>{finding.get('cvss', '')}</td>
        <td>{finding.get('confidence', 'UNKNOWN')}</td>
        <td>{finding.get('owasp', 'UNKNOWN')}</td>
    </tr>
    """
    for i, finding in enumerate(top_findings, start=1)
)}

</table>

<h2>Most Common Findings</h2>

<table>
<tr>
    <th>Rank</th>
    <th>Keyword</th>
    <th>Count</th>
</tr>

        {"".join(
            f"""
            <tr>
                <td>#{i}</td>
                <td>{keyword}</td>
                <td>{count}</td>
            </tr>
            """
            for i, (keyword, count) in enumerate(most_common_findings, start=1)
        )}

</table>

<h2>OWASP Categories</h2>
""")

        for category, count in owasp_counts.items():
            report.write(f"<p>{category}: {count}</p>")

        report.write(f"""   
                     
<h2>Search & Filter Findings</h2>   

        <input
            type="text"
            id="findingSearch"
            placeholder="Search findings..."
            onkeyup="searchFindings()"
        />                 

        <div class="filter-buttons">
            <button onclick="filterFindings('ALL')">Show All</button>
            <button onclick="filterFindings('HIGH')">High</button>
            <button onclick="filterFindings('MEDIUM')">Medium</button>
            <button onclick="filterFindings('LOW')">Low</button>
        </div>
                     
        <div class="export-button">
            <button onclick="window.print()">Export / Print PDF</button>
        </div>
                                        
        <table id="findingsTable">
            <tr>
                <th onclick="sortTable(0)">Keyword</th>
                <th onclick="sortTable(1)">Severity</th>
                <th onclick="sortTable(2)">Confidence</th>
                <th onclick="sortTable(3)">OWASP</th>
                <th onclick="sortTable(4)">CVSS</th>
                <th onclick="sortTable(5)">Remediation</th>
            </tr>
            """)

        for finding in findings:
            report.write(f"""
            <tr data-severity="{finding['severity']}">
                <td>{finding['keyword']}</td>
                <td class="{finding['severity'].lower()}">{finding['severity']}</td>
                <td>{finding['confidence']}</td>
                <td>{finding.get("owasp", "MISSING")}</td>
                <td>{finding.get("cvss", "MISSING")}</td>
                <td>{finding.get("remediation", "MISSING")}</td>
            </tr>
            """)

        report.write(f"""   
        </table>
                        
        <script>
        const ctx = document.getElementById('riskChart');

        new Chart(ctx, {{
            type: 'bar',
            data: {{
                labels: ['HIGH', 'MEDIUM', 'LOW'],
                datasets: [{{
                    label: 'Findings',
                    data: [{high_count}, {medium_count}, {low_count}],
                    backgroundColor: ['#dc3545', '#ffc107', '#28a745'],
                    borderColor: ['#dc3545', '#ffc107', '#28a745'],
                    borderWidth: 1
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }}
            }}

        }});

        function filterFindings(severity) {{
            const rows = document.querySelectorAll('tr[data-severity]');

            rows.forEach(row => {{
                if (severity === 'ALL' || row.dataset.severity === severity) {{
            row.style.display = '';
                }} else {{
                    row.style.display = 'none';
                }}
            }});
        }}

        function searchFindings() {{
            const searchInput = document.getElementById('findingSearch').value.toLowerCase();
            const rows = document.querySelectorAll('tr[data-severity]');

            rows.forEach(row => {{
                const rowText = row.innerText.toLowerCase();

            if (rowText.includes(searchInput)) {{
                row.style.display = '';
            }} else {{
            row.style.display = 'none';
            }}
        }});
    }}

        function sortTable(columnIndex) {{
            const table = document.getElementById('findingsTable');
            const rows = Array.from(table.querySelectorAll('tr[data-severity]'));
            const ascending = table.dataset.sortOrder !== 'asc';

        rows.sort((a, b) => {{
            const aText = a.children[columnIndex].innerText.trim();
            const bText = b.children[columnIndex].innerText.trim();

            const aNum = parseFloat(aText);
            const bNum = parseFloat(bText);

            if (!isNaN(aNum) && !isNaN(bNum)) {{
                return ascending ? aNum - bNum : bNum - aNum;
        }}

            return ascending 
                ? aText.localeCompare(bText) 
                : bText.localeCompare(aText);
    }});

    rows.forEach(row => table.appendChild(row));

    table.dataset.sortOrder = ascending ? 'asc' : 'desc';
}}
        </script>

        </body>
        </html>
        """)