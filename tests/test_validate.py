from osintmagic.utils.validate import is_domain, is_email, is_ip, is_public_ip, is_username


def test_is_email():
    assert is_email("jane.doe@example.com")
    assert is_email("a@b.co")
    assert not is_email("not-an-email")
    assert not is_email("a@b")
    assert not is_email("a b@c.com")


def test_is_username():
    assert is_username("johndoe")
    assert is_username("john_doe-1.x")
    assert not is_username("has space")
    assert not is_username("-leading")
    assert not is_username("")


def test_is_domain():
    assert is_domain("example.com")
    assert is_domain("sub.example.co.uk")
    assert is_domain("example.com.")
    assert not is_domain("example")
    assert not is_domain("https://example.com")


def test_is_ip():
    assert is_ip("8.8.8.8")
    assert is_ip("2001:4860:4860::8888")
    assert not is_ip("999.1.1.1")
    assert not is_ip("not-an-ip")


def test_is_public_ip():
    assert is_public_ip("8.8.8.8")
    assert not is_public_ip("192.168.1.1")
    assert not is_public_ip("10.0.0.1")
    assert not is_public_ip("127.0.0.1")
    assert not is_public_ip("0.0.0.0")
