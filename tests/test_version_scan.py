
import requests_mock
from modules.version_scan import check_version

def test_check_version_no_server_header():
    findings = []
    with requests_mock.Mocker() as m:
        m.get("http://test.com", text="", headers={})
        check_version("http://test.com", findings, 1.0)
        assert len(findings) == 1
        assert findings[0]["title"] == "Server Version Check"

def test_check_version_vulnerable_apache():
    findings = []
    with requests_mock.Mocker() as m:
        m.get("http://test.com", text="", headers={"Server": "Apache/2.4.1"})
        check_version("http://test.com", findings, 1.0)
        assert len(findings) == 2
        assert findings[1]["title"] == "Outdated Server Version: Apache"

def test_check_version_vulnerable_nginx():
    findings = []
    with requests_mock.Mocker() as m:
        m.get("http://test.com", text="", headers={"Server": "nginx/1.10.0"})
        check_version("http://test.com", findings, 1.0)
        assert len(findings) == 2
        assert findings[1]["title"] == "Outdated Server Version: Nginx"

def test_check_version_not_vulnerable():
    findings = []
    with requests_mock.Mocker() as m:
        m.get("http://test.com", text="", headers={"Server": "Apache/2.4.54"})
        check_version("http://test.com", findings, 1.0)
        assert len(findings) == 1 # Only the info finding should be present

def test_check_version_unknown_software():
    findings = []
    with requests_mock.Mocker() as m:
        m.get("http://test.com", text="", headers={"Server": "MyAwesomeServer/1.0"})
        check_version("http://test.com", findings, 1.0)
        assert len(findings) == 1 # Only the info finding should be present
