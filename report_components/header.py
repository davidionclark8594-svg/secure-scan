def get_header_section():
    return """
<div class="header">
    <h1>Secure Scan Report</h1>
    <p>Application Security Analysis Dashboard</p>
</div>

<button class="dark-mode-toggle" onclick="toggleDarkMode()">
    🌙 Dark Mode
</button>
"""


def get_scan_summary_section(
    high_count,
    medium_count,
    low_count,
    total_findings,
    risk_level,
):
    risk_class = risk_level.lower()

    return f"""
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

    <div class="card risk-{risk_class}">
        <div class="label">RISK LEVEL</div>
        <div class="number">{risk_level}</div>
    </div>
</div>
"""