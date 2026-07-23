from pathlib import Path
import html


def get_top_risky_files_section(
    top_risky_files,
    file_detail_pages,
):
    rows = ""

    for rank, file_data in enumerate(top_risky_files, start=1):

        file_path = str(
            file_data.get(
                "file",
                "UNKNOWN",
            )
        )

        display_name = html.escape(
            Path(file_path).name
        )

        safe_full_path = html.escape(
            file_path
        )

        page_path = file_detail_pages.get(
            file_path
        )

        if page_path:
            file_cell = f"""
            <a href="{page_path}" title="{safe_full_path}">
                {display_name}
            </a>
            """
        else:
            file_cell = f"""
            <span title="{safe_full_path}">
                {display_name}
            </span>
            """

        rows += f"""
        <tr>
            <td>#{rank}</td>
            <td>{file_cell}</td>
            <td>{file_data.get("findings", 0)}</td>
            <td>{file_data.get("risk_score", 0)}</td>
            <td class="{file_data.get('highest_severity', 'UNKNOWN').lower()}">
                {file_data.get("highest_severity", "UNKNOWN")}
            </td>
        </tr>
        """

    return f"""
<h2>Top Risky Files</h2>

<table>
    <tr>
        <th>Rank</th>
        <th>File</th>
        <th>Findings</th>
        <th>Risk Score</th>
        <th>Highest Severity</th>
    </tr>

    {rows}
</table>
"""