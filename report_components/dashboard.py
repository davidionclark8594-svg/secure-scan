def get_dashboard_section(
    total_findings,
    current_risk_score,
    high_count,
    owasp_category_count,
    cwe_category_count,
    file_count,
):
    return f"""
<h2>📊 Security Dashboard</h2>

<div class="dashboard-grid">

<a class="dashboard-card" href="#summary">
<div class="dashboard-number">{current_risk_score}</div>
<div class="dashboard-title">Risk Score</div>
</a>

<a class="dashboard-card" href="#findings">
<div class="dashboard-number">{total_findings}</div>
<div class="dashboard-title">Findings</div>
</a>

<a class="dashboard-card" href="#files">
<div class="dashboard-number">{file_count}</div>
<div class="dashboard-title">Affected Files</div>
</a>

<a class="dashboard-card" href="#owasp">
<div class="dashboard-number">{owasp_category_count}</div>
<div class="dashboard-title">OWASP</div>
</a>

<a class="dashboard-card" href="#cwe">
<div class="dashboard-number">{cwe_category_count}</div>
<div class="dashboard-title">CWEs</div>
</a>

<a class="dashboard-card" href="#remediation">
<div class="dashboard-number">{high_count}</div>
<div class="dashboard-title">High Severity</div>
</a>

</div>
"""