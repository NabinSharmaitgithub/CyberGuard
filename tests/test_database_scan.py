
from unittest.mock import patch, MagicMock
from modules.database_scan import check_databases


def test_check_databases_open_port():
    findings = []
    with patch('socket.socket') as mock_socket:
        mock_socket.return_value.__enter__.return_value.connect_ex.return_value = 0
        check_databases("127.0.0.1", findings, 1.0)
        assert len(findings) == 6
        assert findings[0]["title"] == "Open Database Port: MySQL (3306)"

def test_check_databases_closed_port():
    findings = []
    with patch('socket.socket') as mock_socket:
        mock_socket.return_value.__enter__.return_value.connect_ex.return_value = 1
        check_databases("127.0.0.1", findings, 1.0)
        assert len(findings) == 0
