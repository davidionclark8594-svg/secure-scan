OWASP_MAP = {
    # A01: Broken Access Control
    "admin": "A01: Broken Access Control",
    "admin_access": "A01: Broken Access Control",
    "admin_endpoint": "A01: Broken Access Control",
    "unauthorized": "A01: Broken Access Control",
    "unauthorized_access": "A01: Broken Access Control",
    "access_denied": "A01: Broken Access Control",
    "broken_access": "A01: Broken Access Control",

    # A02: Cryptographic Failures
    "password": "A02: Cryptographic Failures",
    "token": "A02: Cryptographic Failures",
    "github_token": "A02: Cryptographic Failures",
    "aws_key": "A02: Cryptographic Failures",
    "api_key": "A02: Cryptographic Failures",
    "api_key_assignment": "A02: Cryptographic Failures",
    "secret": "A02: Cryptographic Failures",
    "email": "A02: Cryptographic Failures",
    "token_assignment": "A02: Cryptographic Failures",
    "bearer_token": "A02: Cryptographic Failures",
    "authorization_header": "A02: Cryptographic Failures",
    "basic_auth": "A02: Cryptographic Failures",

    # A02: Cryptographic Failures
    "base64_payload": "A02: Cryptographic Failures",

    # A03: Injection
    "sql": "A03: Injection",
    "sql_injection_payload": "A03: Injection",
    "xss": "A03: Injection",
    "command_injection": "A03: Injection",
    "reverse_shell": "A03: Injection",
    "os_system": "A03: Injection",
    "eval_usage": "A03: Injection",
    "login_bypass": "A03: Injection",
    "exec_usage": "A03: Injection",
    "subprocess_usage": "A03: Injection",

    # A05: Security Misconfiguration
    "dangerous_file_type": "A05: Security Misconfiguration",
    "double_extension": "A05: Security Misconfiguration",
    "suspicious_filename": "A05: Security Misconfiguration",
    "powershell": "A05: Security Misconfiguration",
    "download_activity": "A05: Security Misconfiguration",
    "ip_address": "A05: Security Misconfiguration",
    "api_endpoint": "A05: Security Misconfiguration",
    "debug": "A05: Security Misconfiguration",
    "debug_endpoint": "A05: Security Misconfiguration",
    "default_credentials": "A05: Security Misconfiguration",
    "os_system_usage": "A05: Security Misconfiguration",

    # A06: Vulnerable and Outdated Components
    "outdated_component": "A06: Vulnerable and Outdated Components",

    # A07: Identification and Authentication Failures
    "jwt_token": "A07: Identification and Authentication Failures",
    "password_assignment": "A07: Identification and Authentication Failures",
    "weak_password": "A07: Identification and Authentication Failures",
    "hardcore_login": "A07: Identification and Authentication Failures",

    # A08: Software and Data Integrity Failures
    "pickle_loads": "A08: Software and Data Integrity Failures",

    # A10: Server-Side Request Forgery
    "ssrf": "A10: Server-Side Request Forgery",
}


def get_owasp_category(keyword):
    return OWASP_MAP.get(keyword, "UNKNOWN")