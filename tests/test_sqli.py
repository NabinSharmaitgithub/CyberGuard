import requests_mock
from urllib.parse import urlencode
from modules.sqli import check_sqli, SQLI_PAYLOADS

def test_check_sqli_no_params():
    findings = []
    check_sqli("http://test.com", findings, 1.0, True)
    assert len(findings) == 0

def test_check_sqli_vulnerable():
    findings = []
    with requests_mock.Mocker() as m:
        for payload in SQLI_PAYLOADS:
            query = {"param": "test" + payload}
            url = f"http://test.com?{urlencode(query)}"
            m.get(url, text="sql syntax error")
        check_sqli("http://test.com?param=test", findings, 1.0, True)
        assert len(findings) > 0
        assert findings[0]["title"] == "Potential SQL Injection"

def test_check_sqli_not_vulnerable():
    findings = []
    with requests_mock.Mocker() as m:
        for payload in SQLI_PAYLOADS:
            query = {"param": "test" + payload}
            url = f"http://test.com?{urlencode(query)}"
            m.get(url, text="ok")
        check_sqli("http://test.com?param=test", findings, 1.0, True)
        assert len(findings) == 0