
import requests
from typing import List, Dict, Any
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

from modules.report import add_finding

# Benign payloads that don't cause harm but can trigger database errors
SQLI_PAYLOADS = [
    "'",
    '"',
    "' OR 1=1--",
    '" OR 1=1--',
    "' OR '1'='1",
    '" OR "1"="1',
]

# Common database error messages
DB_ERRORS = [
    "sql syntax",
    "mysql",
    "unclosed quotation mark",
    "odbc",
    "oracle",
    "microsoft ole db provider for odbc drivers error",
]

def check_sqli(target: str, findings: List[Dict[str, Any]], timeout: float, aggressive: bool):
    """
    Checks for SQL injection vulnerabilities in URL parameters.

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
        for payload in SQLI_PAYLOADS:
            query_params[param] = original_value + payload
            new_query = urlencode(query_params, doseq=True)
            test_url = urlunparse(parsed_url._replace(query=new_query))

            try:
                response = requests.get(test_url, timeout=timeout)
                for error in DB_ERRORS:
                    if error in response.text.lower():
                        add_finding(
                            findings,
                            "Potential SQL Injection",
                            "High",
                            f"A potential SQL injection vulnerability was found in the '{param}' parameter.",
                            "Use parameterized queries to prevent SQL injection."
                        )
                        break  # Move to the next parameter
            except requests.RequestException:
                pass
        query_params[param] = original_value  # Restore original value
