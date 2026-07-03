OWASP_MAP = {
    "xss": "A03: Injection",
    "sql_injection_payload": "A03: Injection",
    "command_injection": "A03: Injection",
    "reverse_shell": "A03: Injection",
    "admin": "A01: Broken Access Control",
    "broken_access": "A01: Broken Access Control",
    "unauthorized": "A01: Broken Access Control",
    "sql": "A03: Injection",

    "jwt_token": "A07: Identification and Authentication Failures",

    "password_assignment": "A07: Identification and Authentication Failures",
    "weak_password": "A07: Identification and Authentication Failures",
    "password": "A02: Cryptographic Failures",

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
    "xss": "A03: Injection",
    "admin_access": "A01: Broken Access Control",
    "unauthorized_access": "A01: Broken Access Control",
    "powershell": "A05: Security Misconfiguration",
    "ip_address": "A05: Security Misconfiguration",
    "token": "A02: Cryptographic Failures",
    "api_key": "A02: Cryptographic Failures",
    "secret": "A02: Cryptographic Failure",
    "access_denied": "A01: Broken Access Controll",
    "weak_password": "A02: Cryptographic Failures",
    "api_endpoint": "A05: Security Misconfiguration",
    "email": "A02: Cryptographic Failures",
    "hardcore_login": "A07: Identification and Authentification Failures",
    "admin_endpoint": "A01: Broken Access Control",
    "os_system_usage": "A05: Security Misconfiguration",
    "eval_usage": "A03: Injection",
    "debug_endpoint": "A05: Security Misconfiguration",
    "powershell": "A05: Security Misconfiguration",
    "reverse_shell": "A05: Security Misconfiguration",
    "pickle_loads": "A08: Software and Data Integrity Failures",

    "default_credentials": "A05: Security Misconfiguration",
    "debug": "A05: Security Misconfiguration",

    "outdated_component": "A06: Vulnerable and Outdated Components",
    "ssrf": "A10: Server-Side Request Forgery",
}


def get_owasp_category(keyword):
    return OWASP_MAP.get(keyword, "UNKNOWN")