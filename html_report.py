def write_html_report(report_path, findings, severity_counts, total_findings, risk_level):

    high_count = 0
    medium_count = 0
    low_count = 0
    owasp_counts = {}

    top_findings = sorted(
        findings,
        key=lambda finding: finding.get("cvss", 0),
        reverse=True
    )[:5]

    for finding in findings:
        severity = finding["severity"]     

        owasp = finding.get("owasp", "UNKNOWN")

        if owasp not in owasp_counts:
            owasp_counts[owasp] = 0
        
        owasp_counts[owasp] += 1

        risk_color = {
            "CRITICAL": "#ff4d4d",
            "HIGH": "#ff944d",
            "MEDIUM": "#ffd24d",
            "LOW": "#66cc66",
        }.get(risk_level, "#cccccc")

        if severity == "HIGH":
            high_count += 1

        elif severity == "MEDIUM":
            medium_count += 1

        elif severity == "LOW":
            low_count += 1

    with open(report_path, "w") as report:
        report.write(f"""                    
<html>
<head>
<title>Secure Scan Report</title>
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
    margin-bottom: 20px;
}} 

.card {{
    border: 1px solid #ccc;
    border-radius: 8px;
    padding: 15px;
    min-width: 120px;
    max-width: 120px;
    text-align: center;
    font-weight: bold;
}}
                                                                                                                
</style>
</head>
<body>
                                                                           
<h1>Secure Scan Report</h1>
                     
<h2>Scan Summary</h2>

<div class="dashboard">
    <div class="card">
        HIGH<br>
        {high_count}
    </div>

    <div class="card">
        MEDIUM<br>
        {medium_count}
    </div>

    <div class="card">
        LOW<br>
        {low_count}
    </div>

    <div class="card">
        TOTAL<br>
        {total_findings}
    </div>

    <div class="card" style="color:{risk_color};">
        RISK<br>
        {risk_level}
    </div>
</div>

<h2>Top 5 Highest-Risk Findings</h2>

<table>
<tr>
    <th>Keyword</th>
    <th>Severity</th>
    <th>CVSS</th>
    <th>File</th>
</tr>

{"".join(
    f"""
    <tr>
        <td>{finding.get('keyword', '')}</td>
        <td>{finding.get('severity', '')}</td>
        <td>{finding.get('cvss', '')}</td>
        <td>{str(finding.get('file', '')).split('/')[-1]}</td>
    </tr>
    """
    for finding in top_findings
)}

</table>

<h2>OWASP Categories</h2>
""")
    
        for category, count in owasp_counts.items():
            report.write(f"<p>{category}: {count}</p>")

        report.write(f"""              
<table>
<tr>
<th>Keyword</th>
<th>Severity</th>
<th>Confidence</th>
<th>OWASP</th>
<th>CVSS</th>
<th>Remediation</th>
</tr>
""")

        for finding in findings:
            report.write(f"""
<tr>
<td>{finding['keyword']}</td>
<td class="{finding['severity'].lower()}">{finding['severity']}</td>
<td>{finding['confidence']}</td>
<td>{finding.get("owasp", "MISSING")}</td>
<td>{finding.get("cvss", "MISSING")}</td>
<td>{finding.get("remediation", "MISSING")}</td>
</tr>
""")

        report.write("""
</table>

</body>
</html>
""")