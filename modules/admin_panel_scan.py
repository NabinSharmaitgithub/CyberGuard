
import requests
from typing import List, Dict, Any
from urllib.parse import urljoin

from modules.report import add_finding

ADMIN_PATHS = [
    "admin/",
    "administrator/",
    "login/",
    "admin/login.php",
    "admin/index.php",
    "wp-admin/",
    "admin.php",
    "admin.html",
    "login.php",
    "login.html",
]

def check_admin_panels(target: str, findings: List[Dict[str, Any]], timeout: float):
    """
    Checks for common admin login panels.

    :param target: The target URL.
    :param findings: The list of findings to append to.
    :param timeout: The request timeout in seconds.
    """
    for path in ADMIN_PATHS:
        url = urljoin(target, path)
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=False) # Don't follow redirects
            if response.status_code == 200:
                add_finding(
                    findings,
                    f"Admin Panel Found: {url}",
                    "Low",
                    f"An admin panel was found at {url}. This could be a target for brute-force attacks.",
                    "Ensure the admin panel has strong credentials and is protected against brute-force attacks. Consider restricting access by IP."
                )
        except requests.RequestException:
            pass # Ignore connection errors
