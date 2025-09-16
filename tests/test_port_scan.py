
import socket
from unittest.mock import patch, MagicMock

from modules.port_scan import tcp_port_scan, get_host_ip

def test_tcp_port_scan():
    with patch('socket.socket') as mock_socket:
        mock_sock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_sock_instance

        # Simulate port 80 being open and 443 being closed
        def connect_side_effect(addr):
            if addr[1] == 80:
                return
            raise socket.timeout

        mock_sock_instance.connect.side_effect = connect_side_effect

        open_ports = tcp_port_scan("127.0.0.1", [80, 443], 1.0)
        assert open_ports == [80]

def test_get_host_ip():
    with patch('socket.gethostbyname') as mock_gethostbyname:
        mock_gethostbyname.return_value = "127.0.0.1"
        ip = get_host_ip("localhost")
        assert ip == "127.0.0.1"

def test_get_host_ip_fail():
    with patch('socket.gethostbyname') as mock_gethostbyname:
        mock_gethostbyname.side_effect = socket.gaierror
        ip = get_host_ip("nonexistent.host")
        assert ip is None
