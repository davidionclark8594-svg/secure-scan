REMEDIATION_MAP = {
    "github_token": "Remove token and rotate credentials.",
    "jwt_token": "Store tokens securely and rotate compromised tokens.",
    "sql_injection_payload": "Use parameterized queries.",
    "xss_payload": "Sanitize and encode user input.",
    "weak_password": "Enforce strong password policies.",
    "api_key": "Move secrets to environment variables.",
    "reverse_shell": "Investigate for malware and isolate host.",
    "download_activity": "Validate download source and block malicious URLs.",
    "double_extension": "Block execution and inspect file.",
    "powershell": "Review command and restrict execution policy."
}

def get_remediation(keyword):
    return REMEDIATION_MAP.get(
        keyword,
        "Review finding and remediate appropriately."
    )