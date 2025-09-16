
import requests_mock
from modules.admin_panel_scan import check_admin_panels, ADMIN_PATHS

def test_check_admin_panels_found():
    findings = []
    with requests_mock.Mocker() as m:
        for path in ADMIN_PATHS:
            m.get(f"http://test.com/{path}", text="Admin Login", status_code=200)
        check_admin_panels("http://test.com/", findings, 1.0)
        assert len(findings) == len(ADMIN_PATHS)
        assert findings[0]["title"] == "Admin Panel Found: http://test.com/admin/"

def test_check_admin_panels_not_found():
    findings = []
    with requests_mock.Mocker() as m:
        for path in ADMIN_PATHS:
            m.get(f"http://test.com/{path}", text="Not Found", status_code=404)
        check_admin_panels("http://test.com/", findings, 1.0)
        assert len(findings) == 0
