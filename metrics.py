from collections import Counter


SEVERITY_WEIGHTS = {
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 1,
}


def calculate_scan_metrics(findings):
    """
    Calculate reusable security metrics from a list of findings.
    """

    high_count = 0
    medium_count = 0
    low_count = 0

    owasp_counts = {}
    unique_findings = {}
    affected_files = set()
    cvss_scores = []

    high_confidence_count = 0
    remediation_load = 0

    finding_counts = Counter()

    for finding in findings:
        severity = finding.get("severity", "UNKNOWN")
        keyword = finding.get("keyword", "UNKNOWN")
        owasp = finding.get("owasp", "UNKNOWN").strip()
        file_path = finding.get("file", "")
        confidence = finding.get("confidence", "UNKNOWN")
        cvss = float(finding.get("cvss", 0) or 0)

        if severity == "HIGH":
            high_count += 1
        elif severity == "MEDIUM":
            medium_count += 1
        elif severity == "LOW":
            low_count += 1

        owasp_counts[owasp] = owasp_counts.get(owasp, 0) + 1

        if keyword not in unique_findings:
            unique_findings[keyword] = finding

        if file_path:
            affected_files.add(file_path)

        cvss_scores.append(cvss)
        finding_counts[keyword] += 1

        if confidence == "HIGH":
            high_confidence_count += 1

        if finding.get("remediation", "MISSING") != "MISSING":
            remediation_load += 1

    total_findings = high_count + medium_count + low_count
    file_count = len(affected_files)

    average_cvss = round(
        sum(cvss_scores) / max(len(cvss_scores), 1),
        2,
    )

    highest_cvss = max(cvss_scores, default=0)

    confidence_percent = round(
        (
            high_confidence_count /
            max(total_findings, 1)
        ) * 100
    )

    critical_finding_rate = round(
        (
            high_count /
            max(total_findings, 1)
        ) * 100,
        2,
    )

    risk_density = round(
        total_findings / max(file_count, 1),
        2,
    )

    current_risk_score = (
        high_count * SEVERITY_WEIGHTS["HIGH"] +
        medium_count * SEVERITY_WEIGHTS["MEDIUM"] +
        low_count * SEVERITY_WEIGHTS["LOW"]
    )

    risk_score_per_file = round(
        current_risk_score / max(file_count, 1),
        2,
    )

    security_posture_score = max(
        0,
        100 - current_risk_score,
    )

    top_findings = sorted(
        unique_findings.values(),
        key=lambda finding: float(
            finding.get("cvss", 0) or 0
        ),
        reverse=True,
    )[:5]

    most_common_findings = finding_counts.most_common(5)

    return {
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "total_findings": total_findings,
        "owasp_counts": owasp_counts,
        "owasp_category_count": len(owasp_counts),
        "unique_findings": unique_findings,
        "unique_vulnerability_count": len(unique_findings),
        "file_count": file_count,
        "average_cvss": average_cvss,
        "highest_cvss": highest_cvss,
        "confidence_percent": confidence_percent,
        "critical_finding_rate": critical_finding_rate,
        "risk_density": risk_density,
        "remediation_load": remediation_load,
        "current_risk_score": current_risk_score,
        "risk_score_per_file": risk_score_per_file,
        "security_posture_score": security_posture_score,
        "top_findings": top_findings,
        "most_common_findings": most_common_findings,
    }

def calculate_top_risky_files(findings, limit=5):
    """
    Rank affected files by accumulated severity risk.
    """

    severity_weights = {
        "HIGH": 10,
        "MEDIUM": 5,
        "LOW": 1,
    }

    severity_rank = {
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "UNKNOWN": 0,
    }

    file_risk_data = {}

    for finding in findings:
        file_path = finding.get("file", "UNKNOWN")
        severity = finding.get("severity", "UNKNOWN")

        if file_path not in file_risk_data:
            file_risk_data[file_path] = {
                "file": file_path,
                "findings": 0,
                "risk_score": 0,
                "highest_severity": "UNKNOWN",
            }

        file_data = file_risk_data[file_path]

        file_data["findings"] += 1
        file_data["risk_score"] += severity_weights.get(
            severity,
            0,
        )

        current_highest = file_data["highest_severity"]

        if severity_rank.get(
            severity,
            0,
        ) > severity_rank.get(
            current_highest,
            0,
        ):
            file_data["highest_severity"] = severity

    return sorted(
        file_risk_data.values(),
        key=lambda file_data: (
            file_data["risk_score"],
            file_data["findings"],
        ),
        reverse=True,
    )[:limit]

def calculate_remediation_queue(findings, limit=5):
    """
    Build a prioritized queue of unique vulnerability types.
    """

    unique_remediation_findings = {}

    for finding in findings:
        keyword = finding.get("keyword", "UNKNOWN")

        if keyword not in unique_remediation_findings:
            unique_remediation_findings[keyword] = {
                "finding": finding,
                "count": 1,
            }
            continue

        item = unique_remediation_findings[keyword]
        item["count"] += 1

        existing_finding = item["finding"]

        existing_cvss = float(
            existing_finding.get("cvss", 0) or 0
        )

        current_cvss = float(
            finding.get("cvss", 0) or 0
        )

        if current_cvss > existing_cvss:
            item["finding"] = finding

    severity_bonus = {
        "HIGH": 20,
        "MEDIUM": 10,
        "LOW": 5,
        "UNKNOWN": 0,
    }

    for item in unique_remediation_findings.values():
        finding = item["finding"]
        occurrence_count = item["count"]

        cvss_score = float(
            finding.get("cvss", 0) or 0
        )

        severity = finding.get(
            "severity",
            "UNKNOWN",
        )

        priority_score = round(
            (cvss_score * 10)
            + occurrence_count
            + severity_bonus.get(severity, 0),
            1,
        )

        item["priority_score"] = priority_score

        if priority_score >= 120:
            item["priority_level"] = "CRITICAL"

        elif priority_score >= 90:
            item["priority_level"] = "URGENT"

        elif priority_score >= 60:
            item["priority_level"] = "HIGH"

        else:
            item["priority_level"] = "MODERATE"

    return sorted(
        unique_remediation_findings.values(),
        key=lambda item: (
            item["priority_score"],
            float(
                item["finding"].get("cvss", 0)
                or 0
            ),
            item["count"],
        ),
        reverse=True,
    )[:limit]

def calculate_historical_progress(
    scan_history,
    current_risk_score,
    total_findings,
):
    """
    Compare the earliest available scan with the latest scan.
    """

    if not scan_history:
        return {
            "starting_risk_score": 0,
            "latest_risk_score": current_risk_score,
            "starting_findings": 0,
            "latest_findings": total_findings,
            "historical_risk_change": 0,
            "historical_improvement": 0.0,
            "historical_status": "No Historical Data",
        }

    first_history_scan = scan_history[0]
    latest_history_scan = scan_history[-1]

    starting_risk_score = first_history_scan.get(
        "risk_score",
        0,
    )

    latest_risk_score = latest_history_scan.get(
        "risk_score",
        current_risk_score,
    )

    starting_findings = (
        first_history_scan.get("high", 0)
        + first_history_scan.get("medium", 0)
        + first_history_scan.get("low", 0)
    )

    latest_findings = (
        latest_history_scan.get("high", 0)
        + latest_history_scan.get("medium", 0)
        + latest_history_scan.get("low", 0)
    )

    historical_risk_change = (
        latest_risk_score - starting_risk_score
    )

    if starting_risk_score > 0:
        historical_improvement = round(
            (
                (starting_risk_score - latest_risk_score)
                / starting_risk_score
            )
            * 100,
            1,
        )
    else:
        historical_improvement = 0.0

    if historical_risk_change < 0:
        historical_status = "🟢 Security Improved"

    elif historical_risk_change > 0:
        historical_status = "🔴 Security Regressed"

    else:
        historical_status = "🟡 No Overall Change"

    return {
        "starting_risk_score": starting_risk_score,
        "latest_risk_score": latest_risk_score,
        "starting_findings": starting_findings,
        "latest_findings": latest_findings,
        "historical_risk_change": historical_risk_change,
        "historical_improvement": historical_improvement,
        "historical_status": historical_status,
    }

def calculate_previous_scan_changes(
    previous_scan,
    high_count,
    medium_count,
    low_count,
    current_risk_score,
):
    """
    Compare the current scan against the immediately previous scan.
    """

    if not previous_scan:
        return {
            "high_change": "No previous scan",
            "medium_change": "No previous scan",
            "low_change": "No previous scan",
            "risk_change": "No previous scan",
            "previous_total": 0,
        }

    high_change = (
        high_count -
        previous_scan.get("high", 0)
    )

    medium_change = (
        medium_count -
        previous_scan.get("medium", 0)
    )

    low_change = (
        low_count -
        previous_scan.get("low", 0)
    )

    risk_change = (
        current_risk_score -
        previous_scan.get("risk_score", 0)
    )

    previous_total = (
        previous_scan.get("high", 0) +
        previous_scan.get("medium", 0) +
        previous_scan.get("low", 0)
    )

    return {
        "high_change": high_change,
        "medium_change": medium_change,
        "low_change": low_change,
        "risk_change": risk_change,
        "previous_total": previous_total,
    }