import json

def get_report_scripts(high_count, medium_count, low_count, scan_history):

    valid_history = [
        scan
        for scan in scan_history
        if scan.get("timestamp")
    ]

    timeline_labels = [
        scan.get("timestamp", "Unknown")
        for scan in valid_history
    ]

    timeline_high = [
        scan.get("high", 0)
        for scan in valid_history
    ]

    timeline_medium = [
        scan.get("medium", 0)
        for scan in valid_history
    ]

    timeline_low = [
        scan.get("low", 0)
        for scan in valid_history
    ]

    timeline_risk = [
        scan.get("risk_score", 0)
        for scan in valid_history
    ]
    return f"""
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
        const detailsRow = row.nextElementSibling;
        const shouldShow =
            severity === 'ALL' ||
            row.dataset.severity === severity;

        row.style.display = shouldShow ? '' : 'none';

        if (detailsRow && detailsRow.classList.contains('details-row')) {{
            detailsRow.style.display = 'none';
        }}

        const icon = row.querySelector('.expand-icon');

        if (icon) {{
            icon.textContent = '▶';
        }}
    }});
}}

function searchFindings() {{
    const searchInput = document
        .getElementById('findingSearch')
        .value
        .toLowerCase();

    const rows = document.querySelectorAll('tr[data-severity]');

    rows.forEach(row => {{
        const detailsRow = row.nextElementSibling;

        const findingText = row.innerText.toLowerCase();
        const detailsText =
            detailsRow &&
            detailsRow.classList.contains('details-row')
                ? detailsRow.innerText.toLowerCase()
                : '';

        const shouldShow =
            findingText.includes(searchInput) ||
            detailsText.includes(searchInput);

        row.style.display = shouldShow ? '' : 'none';

        if (detailsRow && detailsRow.classList.contains('details-row')) {{
            detailsRow.style.display = 'none';
        }}

        const icon = row.querySelector('.expand-icon');

        if (icon) {{
            icon.textContent = '▶';
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

function toggleDarkMode() {{
    document.body.classList.toggle('dark-mode');

    if (document.body.classList.contains('dark-mode')) {{
        localStorage.setItem('theme', 'dark');
    }} else {{
        localStorage.setItem('theme', 'light');
    }}
}}

window.onload = function() {{
    if (localStorage.getItem('theme') === 'dark') {{
        document.body.classList.add('dark-mode');
    }}
}};

function toggleDetails(row) {{
    const detailsRow = row.nextElementSibling;

    const icon = row.querySelector('.expand-icon');

    if (detailsRow.style.display === 'none') {{
        detailsRow.style.display = '';
        icon.textContent = '▼';
        }} else {{
            detailsRow.style.display = 'none';
            icon.textContent = '▶';
        }}
    }}

    const timelineCanvas = document.getElementById('timelineChart');

if (timelineCanvas) {{
    new Chart(timelineCanvas, {{
        type: 'line',

        data: {{
            labels: {json.dumps(timeline_labels)},

            datasets: [
                {{
                    label: 'HIGH',
                    data: {json.dumps(timeline_high)},
                    borderColor: '#dc3545',
                    backgroundColor: '#dc3545',
                    tension: 0.25
                }},
                {{
                    label: 'MEDIUM',
                    data: {json.dumps(timeline_medium)},
                    borderColor: '#ffc107',
                    backgroundColor: '#ffc107',
                    tension: 0.25
                }},
                {{
                    label: 'LOW',
                    data: {json.dumps(timeline_low)},
                    borderColor: '#28a745',
                    backgroundColor: '#28a745',
                    tension: 0.25
                }},
                {{
                    label: 'Risk Score',
                    data: {json.dumps(timeline_risk)},
                    borderColor: '#2563eb',
                    backgroundColor: '#2563eb',
                    tension: 0.25,
                    yAxisID: 'riskAxis'
                }}
            ]
        }},

        options: {{
            responsive: true,
            interaction: {{
                mode: 'index',
                intersect: false
            }},
            scales: {{
                y: {{
                    beginAtZero: true,
                    title: {{
                        display: true,
                        text: 'Finding Count'
                    }}
                }},
                riskAxis: {{
                    beginAtZero: true,
                    position: 'right',
                    grid: {{
                        drawOnChartArea: false
                    }},
                    title: {{
                        display: true,
                        text: 'Risk Score'
                    }}
                }}
            }}
        }}
    }});
}}
</script>
"""