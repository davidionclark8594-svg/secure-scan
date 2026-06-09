def write_html_report(report_path, findings):

    high_count = 0
    medium_count = 0
    low_count = 0
    owasp_counts = {}

    for finding in findings:
        severity = finding["severity"]     

        owasp = finding.get("owasp", "UNKNOWN")

        if owasp not in owasp_counts:
            owasp_counts[owasp] = 0
        
        owasp_counts[owasp] += 1

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
</style>
</head>
<body>
                                                                           
<h1>Secure Scan Report</h1>
                     
<h2>Scan Summary</h2>
                     
<p>HIGH Findings: {high_count}</p>
<p>MEDIUM Findings: {medium_count}</p>
<p>LOW Findings: {low_count}</p>

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
<td> class="{finding['severity'].lower()}>{finding['severity']}</td>
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