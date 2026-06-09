OWASP_MAP = {
    "xss": "A03: Injection",
    "sql_injection_payload": "A03: Injection",

    "jwt_token": "A07: Identification and Authentication Failures",

    "password_assignment": "A07: Identification and Authentication Failures",
    "weak_password": "A07: Identification and Authentication Failures",

    "github_token": "A02: Cryptographic Failures",
    "aws_key": "A02: Cryptographic Failures",
    "api_key_assignment": "A02: Cryptographic Failures",

    "dangerous_file_type": "A05: Security Misconfiguration",
    "double_extension": "A05: Security Misconfiguration",
    "suspicious_filename": "A05: Security Misconfiguration",
    "reverse_shell": "A03: Injection",
    "powershell": "A03: Injection",
    "download_activity": "A05: Security Misconfiguration",
    "os_system": "A03: Injection",
    "sql_injection_payload": "A03: Imjection",
    "xss": "A03: Injection",
    "admin_access": "A01: Broken Access Control",
}


def get_owasp_category(keyword):
    return OWASP_MAP.get(keyword, "Uncategorized")