import csv


def write_csv_report(csv_report_path, findings):
    with open(csv_report_path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)

        writer.writerow([
            "Keyword",
            "Severity",
            "Confidence",
            "OWASP",
            "CVSS",
            "Remediation",
            "File",
            "Line",
            "Content"
        ])

        for finding in findings:
            writer.writerow([
                finding.get("keyword", "MISSING"),
                finding.get("severity", "MISSING"),
                finding.get("confidence", "MISSING"),
                finding.get("owasp", "MISSING"),
                finding.get("cvss", "MISSING"),
                finding.get("remediation", "MISSING"),
                finding.get("file", "MISSING"),
                finding.get("line", "MISSING"),
                finding.get("content", "MISSING")
            ])