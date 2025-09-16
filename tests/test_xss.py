import requests_mock
from urllib.parse import urlencode
from modules.xss import check_xss, XSS_PAYLOADS

def test_check_xss_no_params():
    findings = []
    check_xss("http://test.com", findings, 1.0, True)
    assert len(findings) == 0

def test_check_xss_vulnerable():
    findings = []
    with requests_mock.Mocker() as m:
        for payload in XSS_PAYLOADS:
            query = {"param": payload}
            url = f"http://test.com?{urlencode(query)}"
            m.get(url, text=f"vulnerable input: {payload}")
        check_xss("http://test.com?param=test", findings, 1.0, True)
        assert len(findings) > 0
        assert findings[0]["title"] == "Potential Reflected XSS"

def test_check_xss_not_vulnerable():
    findings = []
    with requests_mock.Mocker() as m:
        for payload in XSS_PAYLOADS:
            query = {"param": payload}
            url = f"http://test.com?{urlencode(query)}"
            m.get(url, text="sanitized input")
        check_xss("http://test.com?param=test", findings, 1.0, True)
        assert len(findings) == 0