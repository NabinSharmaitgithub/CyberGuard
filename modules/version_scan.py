
import requests
from typing import List, Dict, Any
import re

from modules.report import add_finding

# A small database of known vulnerable server versions.
# In a real-world scenario, this would be a comprehensive and regularly updated database.
VULNERABLE_VERSIONS = {
    "apache": [
        r"2\.4\.[0-9]$",  # Example: Apache 2.4.0-2.4.9 are vulnerable
        r"2\.2\..*"
    ],
    "nginx": [
        r"1\.1[0-7]\..*" # Example: Nginx 1.10-1.17 are vulnerable
    ]
}

def check_version(target: str, findings: List[Dict[str, Any]], timeout: float):
    """
    Checks the server version from the 'Server' header and determines if it's a known vulnerable version.

    :param target: The target URL.
    :param findings: The list of findings to append to.
    :param timeout: The request timeout in seconds.
    """
    try:
        response = requests.get(target, timeout=timeout, allow_redirects=True)
        server_header = response.headers.get("Server", "")

        if not server_header:
            add_finding(findings, "Server Version Check", "Info", "Could not determine server version (Server header missing).")
            return

        add_finding(findings, "Server Version", "Info", f"Server header found: {server_header}")

        for software, patterns in VULNERABLE_VERSIONS.items():
            if software.lower() in server_header.lower():
                for pattern in patterns:
                    # Extract version from header
                    version_match = re.search(r'(\d+\.\d+\.\d+)', server_header)
                    if version_match:
                        version = version_match.group(1)
                        if re.match(pattern, version):
                            add_finding(
                                findings,
                                f"Outdated Server Version: {software.capitalize()}",
                                "High",
                                f"The server is running {server_header}, which is a known vulnerable version.",
                                "Update the server software to the latest version."
                            )
                            return # Found a vulnerability, no need to check other patterns for this software

    except requests.RequestException as e:
        add_finding(findings, "Version Check Error", "Info", f"Could not fetch headers: {e}")
