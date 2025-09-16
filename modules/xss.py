
import requests
from typing import List, Dict, Any
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from bs4 import BeautifulSoup

from modules.report import add_finding

# Harmless payloads for detecting reflected XSS
XSS_PAYLOADS = [
    '"><script>/*x*/</script>',
    '"><svg onload=1>',
    '<img src=x onerror=alert(1)>',
]

def check_xss(target: str, findings: List[Dict[str, Any]], timeout: float, aggressive: bool):
    """
    Checks for reflected XSS vulnerabilities in URL parameters.

    :param target: The target URL.
    :param findings: The list of findings to append to.
    :param timeout: The request timeout in seconds.
    :param aggressive: Whether to perform aggressive checks.
    """
    if not aggressive:
        return

    parsed_url = urlparse(target)
    query_params = parse_qs(parsed_url.query)

    if not query_params:
        return

    for param in query_params:
        original_value = query_params[param][0]
        for payload in XSS_PAYLOADS:
            query_params[param] = payload
            new_query = urlencode(query_params, doseq=True)
            test_url = urlunparse(parsed_url._replace(query=new_query))

            try:
                response = requests.get(test_url, timeout=timeout)
                if payload in response.text:
                    add_finding(
                        findings,
                        "Potential Reflected XSS",
                        "Medium",
                        f"A potential reflected XSS vulnerability was found in the '{param}' parameter.",
                        "Implement input validation and output encoding to prevent XSS."
                    )
                    break  # Move to the next parameter
            except requests.RequestException:
                pass
        query_params[param] = original_value  # Restore original value
