def get_top_findings_section(top_findings):
    rows = ""

    for i, finding in enumerate(top_findings, start=1):
        rows += f"""
        <tr>
            <td>#{i}</td>
            <td>{finding.get('keyword', '')}</td>
            <td>{finding.get('severity', '')}</td>
            <td>{finding.get('cvss', '')}</td>
            <td>{finding.get('confidence', 'UNKNOWN')}</td>
            <td>{finding.get('owasp', 'UNKNOWN')}</td>
        </tr>
        """

    return f"""
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

{rows}

</table>
"""


def get_most_common_findings_section(most_common_findings):
    rows = ""

    for i, (keyword, count) in enumerate(
        most_common_findings,
        start=1,
    ):
        rows += f"""
        <tr>
            <td>#{i}</td>
            <td>{keyword}</td>
            <td>{count}</td>
        </tr>
        """

    return f"""
<h2>Most Common Findings</h2>

<table>
<tr>
    <th>Rank</th>
    <th>Keyword</th>
    <th>Count</th>
</tr>

{rows}

</table>
"""