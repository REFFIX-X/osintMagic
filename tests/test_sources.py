"""Fixture-based detection tests (no network)."""
from osintmagic.http_client import HttpResponse
from osintmagic.sources.email import EmailSiteSource
from osintmagic.sources.username import UsernameSiteSource


def _resp(status=200, text="", url="https://example.com/x", headers=None):
    return HttpResponse(status_code=status, text=text, url=url, headers=headers or {})


def test_username_status_code_found():
    src = UsernameSiteSource({"name": "x", "url_user": "https://x/{}", "errorType": "status_code", "errorCode": 404})
    assert src._classify(_resp(200), src.site)[0] == "found"


def test_username_status_code_not_found():
    src = UsernameSiteSource({"name": "x", "url_user": "https://x/{}", "errorType": "status_code", "errorCode": 404})
    assert src._classify(_resp(404), src.site)[0] == "not_found"


def test_username_status_code_blocked_is_error():
    src = UsernameSiteSource({"name": "x", "url_user": "https://x/{}", "errorType": "status_code", "errorCode": 404})
    assert src._classify(_resp(429), src.site)[0] == "error"


def test_username_message_not_found():
    src = UsernameSiteSource({"name": "hn", "url_user": "https://hn/{}", "errorType": "message", "errorMsg": "No such user"})
    assert src._classify(_resp(200, "No such user."), src.site)[0] == "not_found"


def test_email_regex_exists():
    src = EmailSiteSource({"name": "t", "detect": "regex", "exists_re": '"taken":\\s*true', "not_exists_re": '"taken":\\s*false'})
    assert src._classify(_resp(200, '{"taken":true}'), src.site)[0] == "found"


def test_email_regex_not_exists():
    src = EmailSiteSource({"name": "t", "detect": "regex", "exists_re": '"taken":\\s*true', "not_exists_re": '"taken":\\s*false'})
    assert src._classify(_resp(200, '{"taken":false}'), src.site)[0] == "not_found"


def test_email_cookie_detection():
    src = EmailSiteSource({"name": "g", "detect": "cookie", "cookie_name": "GX"})
    assert src._classify(_resp(204, "", headers={"set-cookie": "GX=abc; Path=/"}), src.site)[0] == "found"
    assert src._classify(_resp(204, "", headers={}), src.site)[0] == "not_found"


def test_email_inconclusive_is_error():
    src = EmailSiteSource({"name": "t", "detect": "regex", "exists_re": '"taken":\\s*true'})
    assert src._classify(_resp(200, '{"unexpected":1}'), src.site)[0] == "error"
