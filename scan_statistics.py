def calculate_risk_score(severity_counts):
    return (
        severity_counts.get("HIGH", 0) * 10
        + severity_counts.get("MEDIUM", 0) * 5
        + severity_counts.get("LOW", 0)
    )


def calculate_total_findings(severity_counts):
    return sum(
        severity_counts.values()
    )


def determine_risk_level(risk_score):
    if risk_score >= 150:
        return "CRITICAL"

    if risk_score >= 75:
        return "HIGH"

    if risk_score >= 25:
        return "MEDIUM"

    return "LOW"


def build_scan_statistics(severity_counts):
    risk_score = calculate_risk_score(
        severity_counts
    )

    return {
        "high_count": severity_counts.get(
            "HIGH",
            0,
        ),
        "medium_count": severity_counts.get(
            "MEDIUM",
            0,
        ),
        "low_count": severity_counts.get(
            "LOW",
            0,
        ),
        "total_findings": (
            calculate_total_findings(
                severity_counts
            )
        ),
        "risk_score": risk_score,
        "risk_level": determine_risk_level(
            risk_score
        ),
    }