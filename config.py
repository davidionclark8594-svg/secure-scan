KEYWORDS = [
    "password",
    "token",
    "sql",
    "injection",
    "xss",
    "admin",
    "secret",
    "apikey",
    "api key",
]


SEVERITY_MAP = {
    "password": "HIGH",
    "token": "HIGH",
    "apikey": "HIGH",
    "api key": "HIGH",
    "sql": "MEDIUM",
    "injection": "MEDIUM",
    "xss": "MEDIUM",
    "admin": "MEDIUM",
    "secret": "HIGH",
}


ALLOWED_EXTENSIONS = {
    ".log",
    ".txt",
    ".env",
    ".config",
    ".json",
    ".yaml",
    ".yml",
    ".py",
}


DANGEROUS_EXTENSIONS = {
    ".exe",
    ".bat",
    ".cmd",
    ".js",
    ".php",
    ".ps1",
    ".sh",
}


SUSPICIOUS_NAMES = {
    "password",
    "bank",
    "login",
    "urgent",
    "payroll",
    "invoice",
    "credential",
    "secret",
}


SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "UNKNOWN": 4,
}