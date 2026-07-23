def get_remediation_queue_section(remediation_queue):
    rows = ""

    for rank, item in enumerate(remediation_queue, start=1):
        finding = item["finding"]
        occurrence_count = item["count"]
        priority_score = item["priority_score"]
        priority_level = item["priority_level"]

        rows += f"""
        <tr>
            <td>#{rank}</td>

            <td>
                {finding.get("keyword", "UNKNOWN")}
            </td>

            <td class="{finding.get("severity", "").lower()}">
                {finding.get("severity", "UNKNOWN")}
            </td>

            <td>
                {finding.get("owasp", "UNKNOWN")}
            </td>

            <td>
                {finding.get("cvss", 0)}
            </td>

            <td>
                {priority_score}
            </td>

            <td class="priority-{priority_level.lower()}">
                {priority_level}
            </td>

            <td>
                {occurrence_count}
            </td>

            <td>
                {finding.get(
                    "remediation",
                    "No recommendation available",
                )}
            </td>
        </tr>
        """

    return f"""
<h2>🚨 Executive Remediation Queue</h2>

<table>
    <tr>
        <th>Priority</th>
        <th>Finding</th>
        <th>Severity</th>
        <th>OWASP</th>
        <th>CVSS</th>
        <th>Priority Score</th>
        <th>Priority Level</th>
        <th>Occurrences</th>
        <th>Recommended Action</th>
    </tr>

    {rows}
</table>
"""