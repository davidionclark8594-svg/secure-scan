def compare_scans(previous_total, current_total, previous_score, current_score):
    resolved = max(previous_total - current_total, 0)
    new = max(current_total - previous_total, 0)

    if previous_total > 0:
        improvement = round((resolved / previous_total) * 100, 1)
    else:
        improvement = 0

    if current_score < previous_score:
        status = "GREEN Security Improved"
    elif current_score > previous_score:
        status = "RED Security Regressed"
    else:
        status = "YELLOW No Significant Change"

    return {
        "previous_total": previous_total,
        "current_total": current_total,
        "resolved": resolved,
        "new": new,
        "improvement": improvement,
        "previous_score": previous_score,
        "current_score": current_score,
        "status": status,
    }