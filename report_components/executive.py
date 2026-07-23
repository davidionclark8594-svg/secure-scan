def get_executive_summary_section(
    total_findings,
    high_count,
    risk_level,
    current_risk_score,
    high_change,
    medium_change,
    low_change,
    risk_change,
    comparison,
):
    return f"""
<h2>Executive Summary</h2>

<div class="summary-card">
    <p>
This scan analyzed {total_findings} security findings across the target codebase.

{high_count} findings were classified as HIGH severity, contributing to an overall {risk_level} risk posture.

Immediate remediation should prioritize credential exposure, injection vulnerabilities, and security misconfigurations identified in the highest-risk findings.
    </p>
</div>

<h2>Overall Risk Assessment</h2>

<div class="risk-assessment-card">
    <div class="risk-title">{risk_level}</div>
    <div class="risk-score-label">Risk Score</div>
    <div class="risk-score">{current_risk_score}</div>
</div>

<h2>Historical Trend Analysis</h2>

<div class="trend-grid">
    <div class="trend-card">
        <strong>HIGH Change</strong>
        <span>{high_change}</span>
    </div>

    <div class="trend-card">
        <strong>MEDIUM Change</strong>
        <span>{medium_change}</span>
    </div>

    <div class="trend-card">
        <strong>LOW Change</strong>
        <span>{low_change}</span>
    </div>

    <div class="trend-card">
        <strong>Risk Score Change</strong>
        <span>{risk_change}</span>
    </div>
</div>

<h2>Scan Comparison</h2>

<div class="trend-grid">
    <div class="trend-card">
        <strong>Previous Scan</strong>
        <span>{comparison["previous_total"]}</span>
    </div>

    <div class="trend-card">
        <strong>Current Scan</strong>
        <span>{comparison["current_total"]}</span>
    </div>

    <div class="trend-card">
        <strong>Resolved Findings</strong>
        <span>{comparison["resolved"]}</span>
    </div>

    <div class="trend-card">
        <strong>New Findings</strong>
        <span>{comparison["new"]}</span>
    </div>

    <div class="trend-card">
        <strong>Improvement</strong>
        <span>{comparison["improvement"]}%</span>
    </div>

    <div class="trend-card">
        <strong>Status</strong>
        <span>{comparison["status"]}</span>
    </div>
</div>
"""


def get_executive_metrics_section(
    unique_vulnerability_count,
    file_count,
    average_cvss,
    highest_cvss,
    confidence_percent,
    owasp_category_count,
    critical_finding_rate,
    risk_density,
    remediation_load,
    risk_score_per_file,
    security_posture_score,
):
    return f"""
<h2>Executive Metrics</h2>

<div class="dashboard">
    <div class="card metric-card">
        <div class="metric-label">UNIQUE VULNERABILITIES</div>
        <div class="metric-value">{unique_vulnerability_count}</div>
    </div>

    <div class="card metric-card">
        <div class="metric-label">FILES WITH FINDINGS</div>
        <div class="metric-value">{file_count}</div>
    </div>

    <div class="card metric-card">
        <div class="metric-label">AVERAGE CVSS</div>
        <div class="metric-value">{average_cvss}</div>
    </div>

    <div class="card metric-card">
        <div class="metric-label">HIGHEST CVSS</div>
        <div class="metric-value">{highest_cvss}</div>
    </div>

    <div class="card metric-card">
        <div class="metric-label">HIGH CONFIDENCE</div>
        <div class="metric-value">{confidence_percent}%</div>
    </div>

    <div class="card metric-card">
        <div class="metric-label">OWASP CATEGORIES</div>
        <div class="metric-value">{owasp_category_count}</div>
    </div>

    <div class="card metric-card">
        <div class="metric-label">CRITICAL FINDING RATE</div>
        <div class="metric-value">{critical_finding_rate}%</div>
    </div>

    <div class="card metric-card">
        <div class="metric-label">RISK DENSITY</div>
        <div class="metric-value">{risk_density}</div>
    </div>

    <div class="card metric-card">
        <div class="metric-label">REMEDIATION LOAD</div>
        <div class="metric-value">{remediation_load}</div>
    </div>

    <div class="card metric-card">
        <div class="metric-label">RISK SCORE / FILE</div>
        <div class="metric-value">{risk_score_per_file}</div>
    </div>

    <div class="card metric-card">
        <div class="metric-label">SECURITY POSTURE</div>
        <div class="metric-value">{security_posture_score}/100</div>
    </div>
</div>
"""