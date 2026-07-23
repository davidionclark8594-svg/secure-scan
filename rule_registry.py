from patterns import PATTERNS


RULE_METADATA = {
    "password": {
        "severity": "HIGH",
        "description": "Possible hardcoded password detected.",
        "cwe": "CWE-798",
        "owasp": "A07:2021 - Identification and Authentication Failures",
    },
    "token": {
        "severity": "HIGH",
        "description": "Possible hardcoded access token detected.",
        "cwe": "CWE-798",
        "owasp": "A07:2021 - Identification and Authentication Failures",
    },
    "secret": {
        "severity": "HIGH",
        "description": "Possible exposed secret detected.",
        "cwe": "CWE-798",
        "owasp": "A07:2021 - Identification and Authentication Failures",
    },
    "apikey": {
        "severity": "HIGH",
        "description": "Possible hardcoded API key detected.",
        "cwe": "CWE-798",
        "owasp": "A07:2021 - Identification and Authentication Failures",
    },
    "api key": {
        "severity": "HIGH",
        "description": "Possible hardcoded API key detected.",
        "cwe": "CWE-798",
        "owasp": "A07:2021 - Identification and Authentication Failures",
    },
    "sql": {
        "severity": "MEDIUM",
        "description": "Possible unsafe SQL usage detected.",
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
    },
    "injection": {
        "severity": "HIGH",
        "description": "Possible injection vulnerability detected.",
        "cwe": "CWE-74",
        "owasp": "A03:2021 - Injection",
    },
    "xss": {
        "severity": "HIGH",
        "description": "Possible cross-site scripting vulnerability detected.",
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
    },
    "admin": {
        "severity": "MEDIUM",
        "description": "Administrative functionality or credentials detected.",
        "cwe": "CWE-284",
        "owasp": "A01:2021 - Broken Access Control",
    },
}


DEFAULT_METADATA = {
    "severity": "UNKNOWN",
    "description": "Potential security issue detected.",
    "cwe": "UNKNOWN",
    "owasp": "UNKNOWN",
}


def load_rules():
    """
    Return all registered pattern rules with
    their associated security metadata.
    """
    rules = []

    for keyword, pattern in PATTERNS.items():
        metadata = RULE_METADATA.get(
            keyword,
            DEFAULT_METADATA,
        )

        rules.append(
            {
                "keyword": keyword,
                "pattern": pattern,
                "severity": metadata["severity"],
                "description": metadata["description"],
                "cwe": metadata["cwe"],
                "owasp": metadata["owasp"],
            }
        )

    return rules