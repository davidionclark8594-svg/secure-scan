CONFIDENCE_MAP = {
    "reverse_shell": "HIGH",
    "download_activity": "HIGH",
    "powershell": "HIGH",

    "jwt_token": "MEDIUM",
    "weak_password": "MEDIUM",
    "github_token": "MEDIUM",

    "email": "LOW",
    "ip_address": "LOW",
    "double_extension": "HIGH",
    "suspicious_filename": "MEDIUM",
    "dangerous_file_type": "HIGH",
    "reverse_shell": "HIGH",
    "powershell": "HIGH",
    "download_activity": "HIGH",
    "os_system": "HIGH",
}

def classify_confidence(keyword):
    return CONFIDENCE_MAP.get(keyword, "MEDIUM")