
import requests
from typing import List, Dict, Any

from modules.report import add_finding

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "description": "Mitigates XSS and other injection attacks.",
        "remediation": "Implement a strict Content-Security-Policy."
    },
    "X-Frame-Options": {
        "description": "Protects against clickjacking attacks.",
        "remediation": "Set X-Frame-Options to 'SAMEORIGIN' or 'DENY'."
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-sniffing attacks.",
        "remediation": "Set X-Content-Type-Options to 'nosniff'."
    },
    "Strict-Transport-Security": {
        "description": "Enforces secure (HTTPS) connections.",
        "remediation": "Set Strict-Transport-Security to 'max-age=31536000; includeSubDomains'."
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information is sent.",
        "remediation": "Set Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'."
    }
}

def check_security_headers(target: str, findings: List[Dict[str, Any]], timeout: float):
    """
    Checks for the presence of important security headers.

    :param target: The target URL.
    :param findings: The list of findings to append to.
    :param timeout: The request timeout in seconds.
    """
    try:
        response = requests.get(target, timeout=timeout, allow_redirects=True)
        headers = response.headers

        for header, info in SECURITY_HEADERS.items():
            if header not in headers:
                add_finding(
                    findings,
                    f"Missing Security Header: {header}",
                    "Medium",
                    info["description"],
                    info["remediation"]
                )
    except requests.RequestException as e:
        add_finding(findings, "Header Check Error", "Info", f"Could not fetch headers: {e}")
