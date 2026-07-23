import html

import html


def get_findings_table_section(findings):
    rows = ""

    for finding in findings:
        rows += f"""
        <tr class="finding-row"
            data-severity="{finding['severity']}"
            onclick="toggleDetails(this)">

            <td>
                <span class="expand-icon">▶</span>
                {finding['keyword']}
            </td>

            <td class="{finding['severity'].lower()}">
                {finding['severity']}
            </td>

            <td>{finding['confidence']}</td>
            <td>{finding.get("owasp", "MISSING")}</td>
            <td>{finding.get("cvss", "MISSING")}</td>
            <td>{finding.get("remediation", "MISSING")}</td>
        </tr>

        <tr class="details-row" style="display: none;">
            <td colspan="6">
                <strong>File:</strong>
                {html.escape(str(finding.get("file", "MISSING")))}
                <br>

                <strong>Line:</strong>
                {finding.get("line", "MISSING")}
                <br>

                <strong>Content:</strong>
                {html.escape(str(finding.get("content", "MISSING")))}
            </td>
        </tr>
        """

    return f"""
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
    <button onclick="window.print()">
        Export / Print PDF
    </button>
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

    {rows}
</table>
"""