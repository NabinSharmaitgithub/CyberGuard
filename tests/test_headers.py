import requests_mock

from modules.headers import check_security_headers

def test_check_security_headers_missing():
    findings = []
    with requests_mock.Mocker() as m:
        m.get("http://test.com", text="", headers={})
        check_security_headers("http://test.com", findings, 1.0)
        assert len(findings) == 5
        assert findings[0]["title"] == "Missing Security Header: Content-Security-Policy"

def test_check_security_headers_present():
    findings = []
    with requests_mock.Mocker() as m:
        m.get("http://test.com", text="", headers={
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000",
            "Referrer-Policy": "no-referrer",
        })
        check_security_headers("http://test.com", findings, 1.0)
        assert len(findings) == 0