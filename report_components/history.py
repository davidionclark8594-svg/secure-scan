def get_historical_progress_section(
    starting_risk_score,
    latest_risk_score,
    historical_risk_change,
    starting_findings,
    latest_findings,
    historical_improvement,
    historical_status,
):
    return f"""
<h2>Historical Progress Summary</h2>

<div class="trend-grid">
    <div class="trend-card">
        <strong>Starting Risk Score</strong>
        <span>{starting_risk_score}</span>
    </div>

    <div class="trend-card">
        <strong>Current Risk Score</strong>
        <span>{latest_risk_score}</span>
    </div>

    <div class="trend-card">
        <strong>Risk Score Change</strong>
        <span>{historical_risk_change:+}</span>
    </div>

    <div class="trend-card">
        <strong>Starting Findings</strong>
        <span>{starting_findings}</span>
    </div>

    <div class="trend-card">
        <strong>Current Findings</strong>
        <span>{latest_findings}</span>
    </div>

    <div class="trend-card">
        <strong>Overall Improvement</strong>
        <span>{historical_improvement}%</span>
    </div>

    <div class="trend-card">
        <strong>Historical Status</strong>
        <span>{historical_status}</span>
    </div>
</div>
"""


def get_vulnerability_timeline_section():
    return """
<h2>Vulnerability Timeline</h2>

<div class="chart-card timeline-chart-card">
    <canvas id="timelineChart"></canvas>
</div>

<div style="clear: both;"></div>
"""