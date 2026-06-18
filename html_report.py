def write_html_report(report_path, findings, severity_counts, total_findings, risk_level):

    high_count = 0
    medium_count = 0
    low_count = 0
    owasp_counts = {}
    unique_findings = {}

    for finding in findings:
        keyword = finding.get("keyword")

        if keyword not in unique_findings:
            unique_findings[keyword] = finding

    top_findings = sorted(
        unique_findings.values(),
        key=lambda finding: finding.get("cvss", 0),
        reverse=True
    )[:5]

    finding_counts = {}

    for finding in findings:
        keyword = finding.get("keyword")

    if keyword not in finding_counts:
        finding_counts[keyword] = 0

    finding_counts[keyword] += 1

    most_common_findings = sorted(
        finding_counts.items(),
        key=lambda item: item[1],
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

    executive_summary = f"""
    This scan analyzed {total_findings} findings.

    {high_count} findings were HIGH severity,
    {medium_count} findings were MEDIUM severity,
    and {low_count} findings were LOW severity.

    Overall Risk Level: {risk_level}
    """                 

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
                     
.summary-box {{
    border: 1px solid #ddd;
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 20px;
    background: #fafafa;
    max-width: 900px;
}}
                     
.summary-box p {{
    front-size: 16px;
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

<h2>Executive Summary</h2>

<div class="summary-box">
     <p>{executive_summary}</p>

<h2>Risk Distribution</h2>

<div class="chart-container">

    <div class="chart-row">
        <span>HIGH ({high_count})</span>
        <div class="bar high-bar"
             style="width:{high_count * 10}px;">
        </div>
    </div>

    <div class="chart-row">
        <span>MEDIUM ({medium_count})</span>
        <div class="bar medium-bar"
             style="width:{medium_count * 10}px;">
        </div>
    </div>

    <div class="chart-row">
        <span>LOW ({low_count})</span>
        <div class="bar low-bar"
             style="width:{low_count * 10}px;">
        </div>
    </div>

</div>
</div>

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
        <td>{keyword}</tb>
        <td>{count}</tb>
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