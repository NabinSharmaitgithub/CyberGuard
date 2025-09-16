
import socket
from typing import List

def tcp_port_scan(target: str, ports: List[int], timeout: float) -> List[int]:
    """
    Performs a simple TCP connect scan on a list of ports.

    :param target: The target IP address.
    :param ports: A list of ports to scan.
    :param timeout: The socket timeout in seconds.
    :return: A list of open ports.
    """
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            try:
                s.connect((target, port))
                open_ports.append(port)
            except (socket.timeout, ConnectionRefusedError):
                pass
    return open_ports

def get_host_ip(target: str) -> str:
    """
    Resolves a hostname to an IP address.

    :param target: The target hostname or IP address.
    :return: The resolved IP address.
    """
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None
