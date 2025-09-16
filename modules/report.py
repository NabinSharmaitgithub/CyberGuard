
import json
from typing import List, Dict, Any

# ANSI color codes
class Colors:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    ENDC = '\033[0m'

SEVERITY_COLORS = {
    "High": Colors.RED,
    "Medium": Colors.YELLOW,
    "Low": Colors.BLUE,
    "Info": Colors.GREEN,
}

def print_report(findings: List[Dict[str, Any]], output_format: str = "text"):
    """
    Prints the scan report in the specified format.

    :param findings: A list of finding dictionaries.
    :param output_format: The output format ('text' or 'json').
    """
    if output_format == "json":
        print(json.dumps(findings, indent=4))
    else:
        for finding in findings:
            color = SEVERITY_COLORS.get(finding["severity"], Colors.ENDC)
            print(f"{color}[{finding['severity']}] {finding['title']}{Colors.ENDC}")
            print(f"  Description: {finding['description']}")
            if "remediation" in finding:
                print(f"  Remediation: {finding['remediation']}")
            print()

def add_finding(findings: List[Dict[str, Any]], title: str, severity: str, description: str, remediation: str = None):
    """
    Adds a finding to the list of findings.

    :param findings: The list of findings to append to.
    :param title: The title of the finding.
    :param severity: The severity of the finding (High, Medium, Low, Info).
    :param description: A description of the finding.
    :param remediation: Optional remediation advice.
    """
    finding = {
        "title": title,
        "severity": severity,
        "description": description,
    }
    if remediation:
        finding["remediation"] = remediation
    findings.append(finding)
