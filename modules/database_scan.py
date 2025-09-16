
import socket
from typing import List, Dict, Any

from modules.report import add_finding

DATABASE_PORTS = {
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    1433: "Microsoft SQL Server",
    1521: "Oracle",
}

def check_databases(ip: str, findings: List[Dict[str, Any]], timeout: float):
    """
    Scans for open database ports.

    :param ip: The target IP address.
    :param findings: The list of findings to append to.
    :param timeout: The timeout for network connections in seconds.
    """
    for port, db_name in DATABASE_PORTS.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    add_finding(
                        findings,
                        f"Open Database Port: {db_name} ({port})",
                        "Medium",
                        f"The port for {db_name} is open. This could expose the database to the internet.",
                        "Ensure that database ports are not publicly accessible unless required. Use a firewall to restrict access."
                    )
        except socket.error:
            pass # Ignore connection errors
