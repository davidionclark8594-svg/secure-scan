CVSS_MAP = {
    "sql_injection_payload": 9.8,
    "xss_payload": 8.8,
    "jwt_token": 7.5,
    "github_token": 9.0,
    "password": 8.0,
    "password_assignment": 8.5,
    "reverse_shell": 10.0,
    "powershell": 9.5,
    "download_activity": 9.0,
    "double_extension": 8.0,
    "api_key": 8.5,
    "weak_password": 6.5,
    "email": 3.0,
    "ip_address": 2.0
}

def get_cvss(keyword):
    return CVSS_MAP.get(keyword, 5.0)