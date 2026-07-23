def get_report_styles():
    return """
<style>

body {
    font-family: Arial, sans-serif;
    margin: 20px;
    transition: background-color 0.3s ease, color 0.3s ease;
}

table {
    border-collapse: collapse;
    width: 100%;
    margin-bottom: 25px;
}

th, td {
    border: 1px solid #ccc;
    padding: 8px;
}

th {
    background-color: #dddddd;
    cursor: pointer;
}

.high {
    background-color: #ffcccc;
    color: #990000;
    font-weight: bold;
}

.medium {
    background-color: #fff3cd;
    color: #856404;
    font-weight: bold;
}

.low {
    background-color: #d4edda;
    color: #155724;
    font-weight: bold;
}

.header {
    background: #2d3748;
    color: white;
    padding: 25px;
    border-radius: 10px;
    margin-bottom: 25px;
}

.header h1 {
    margin: 0;
}

.header p {
    margin-top: 8px;
    color: #cbd5e0;
}

.dashboard {
    display: flex;
    flex-wrap: wrap;
    gap: 15px;
    margin-bottom: 30px;
}

.card {
    border: 1px solid #ddd;
    border-radius: 8px;
    padding: 15px;
    min-width: 150px;
    background: white;
}

.card .number {
    font-size: 28px;
    font-weight: bold;
    margin-top: 5px;
}

.summary-card,
.chart-card,
.risk-assessment-card,
.trend-card {
    border: 1px solid #ddd;
    border-radius: 10px;
    padding: 20px;
    margin-bottom: 30px;
    background: #fafafa;
}

.summary-card p {
    font-size: 16px;
    line-height: 1.6;
    white-space: pre-line;
}

.trend-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 15px;
}

.trend-card {
    min-width: 160px;
}

.trend-card strong {
    display: block;
    margin-bottom: 8px;
}

.trend-card span {
    font-size: 20px;
    font-weight: bold;
}

.risk-title {
    font-size: 30px;
    font-weight: bold;
    color: #b30000;
}

.risk-score-label {
    margin-top: 12px;
    font-size: 18px;
    color: #555;
}

.risk-score {
    font-size: 42px;
    font-weight: bold;
}

.risk-critical {
    background: #ffe5e5;
    border: 3px solid #dc3545;
}

.risk-high {
    background: #fff0e0;
    border: 3px solid #ff9900;
}

.risk-medium {
    background: #fff9d6;
    border: 3px solid #ffcc00;
}

.risk-low {
    background: #e6ffe6;
    border: 3px solid #28a745;
}

.chart-card {
    max-width: 650px;
}

.filter-buttons {
    margin-bottom: 20px;
}

.filter-buttons button {
    padding: 12px 22px;
    margin: 5px;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    font-size: 16px;
    font-weight: bold;
}

.export-button {
    margin: 15px 0;
}

.export-button button {
    background: #2563eb;
    color: white;
    padding: 14px 26px;
    border: none;
    border-radius: 8px;
    cursor: pointer;
    font-size: 18px;
    font-weight: bold;
}

.export-button button:hover {
    background: #1d4ed8;
    transform: scale(1.03);
}

#findingSearch {
    width: 500px;
    padding: 15px;
    font-size: 18px;
    border-radius: 6px;
    border: 2px solid #2563eb;
    margin-bottom: 20px;
}

.dark-mode-toggle {
    margin: 20px 0;
    padding: 12px 18px;
    border: none;
    border-radius: 6px;
    background: #1f2937;
    color: white;
    cursor: pointer;
    font-size: 16px;
    font-weight: bold;
}

body.dark-mode {
    background: #111827;
    color: #f9fafb;
}

body.dark-mode .card,
body.dark-mode .summary-card,
body.dark-mode .chart-card,
body.dark-mode .risk-assessment-card,
body.dark-mode .trend-card {
    background: #1f2937;
    color: #f9fafb;
    border-color: #374151;
}

body.dark-mode table {
    background: #1f2937;
    color: #f9fafb;
}

body.dark-mode th {
    background: #374151;
    color: white;
}

body.dark-mode td {
    border-color: #4b5563;
}

body.dark-mode input {
    background: #1f2937;
    color: white;
    border: 1px solid #6b7280;
}

@media print {

    body {
        margin: 0.5in;
        font-size: 12px;
    }

    .filter-buttons,
    #findingSearch,
    .export-button,
    .dark-mode-toggle {
        display: none;
    }

    .header {
        background: white;
        color: black;
        border-bottom: 2px solid #333;
    }

    .header p {
        color: black;
    }

    table {
        page-break-inside: auto;
    }

    tr {
        page-break-inside: avoid;
        page-break-after: auto;
    }

    h2 {
        page-break-after: avoid;
    }
}

.finding-row {
    cursor: pointer;
}

.finding-row:hover {
    background: #f2f7ff
}

.dark-mode .finding-row:hover {
    background: #2d3748;
}

.metric-card {
    border-left: 5px solid #2563eb;
}

.metric-label {
    font-size: 13px;
    color: #666;
    font-weight: bold;
    text-transform: uppercase;
}

.metric-value {
    font-size: 30px;
    font-weight: bold;
    margin-top: 8px;
}

body.dark-mode .metric-label {
    color: #cbd5e1;
}

.priority-critical {
    background-color: #7f1d1d;
    color: white;
    font-weight: bold;
}

.priority-urgent {
    background-color: #dc2626;
    color: white;
    font-weight: bold;
}

.priority-high {
    background-color: #f59e0b;
    color: #111827;
    font-weight: bold;
}

.priority-moderate {
    background-color: #fef3c7;
    color: #92400e;
    font-weight: bold;
}

.owasp-category-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 15px;
    margin-bottom: 30px;
}

.owasp-category-card {
    display: flex;
    flex-direction: column;
    min-width: 230px;
    padding: 18px;
    border: 1px solid #d1d5db;
    border-left: 5px solid #2563eb;
    border-radius: 10px;
    background: white;
    color: #111827;
    text-decoration: none;
    transition:
        transform 0.2s ease,
        box-shadow 0.2s ease;
}

.owasp-category-card strong {
    margin-bottom: 8px;
}

.owasp-category-card span {
    color: #4b5563;
}

.owasp-category-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 16px rgba(0, 0, 0, 0.12);
}

body.dark-mode .owasp-category-card {
    background: #1f2937;
    color: #f9fafb;
    border-color: #374151;
    border-left-color: #60a5fa;
}

body.dark-mode .owasp-category-card span {
    color: #cbd5e1;
}

.metrics-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 15px;
    margin-bottom: 25px;
}

.metric-card {
    min-width: 170px;
    background: white;
    border: 1px solid #d1d5db;
    border-radius: 10px;
    padding: 18px;
}

.metric-card strong {
    display: block;
    margin-bottom: 8px;
    color: #4b5563;
}

.metric-card span {
    font-size: 26px;
    font-weight: bold;
}

.severity-high {
    border-left: 5px solid #dc2626;
}

.severity-medium {
    border-left: 5px solid #f59e0b;
}

.severity-low {
    border-left: 5px solid #16a34a;
}

.dashboard-grid{
display:grid;
grid-template-columns:repeat(auto-fit,minmax(200px,1fr));
gap:20px;
margin:30px 0;
}

.dashboard-card{
background:#ffffff;
border-radius:12px;
padding:24px;
text-align:center;
text-decoration:none;
color:inherit;
box-shadow:0 2px 8px rgba(0,0,0,.12);
transition:.25s;
}

.dashboard-card:hover{
transform:translateY(-4px);
box-shadow:0 10px 24px rgba(0,0,0,.18);
}

.dashboard-number{
font-size:42px;
font-weight:bold;
color:#2563eb;
margin-bottom:10px;
}

</style>
"""