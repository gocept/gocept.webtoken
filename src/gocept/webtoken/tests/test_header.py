from gocept.webtoken import create_authorization_header, extract_token
import pytest


def test_header__create_authorization_header__1():
    """Creates bearer header for a given webtoken dict."""
    key, value = create_authorization_header({'token': b'<TOKEN>'})
    assert 'Authorization' == key
    assert 'Bearer <TOKEN>' == value


def test_header__create_authorization_header__2():
    """Creates bearer header for a given webtoken."""
    key, value = create_authorization_header(b'<TOKEN>')
    assert 'Authorization' == key
    assert 'Bearer <TOKEN>' == value


def test_header__extract_token__1():
    """Extracts token from given dict."""
    headers = dict(Authorization='Bearer <TOKEN>')
    assert b'<TOKEN>' == extract_token(headers)


def test_header__extract_token__2():
    """Raises ValueError if Authorization header is missing."""
    with pytest.raises(ValueError) as err:
        extract_token({})
    assert 'Missing Authorization header' == str(err.value)


def test_header__extract_token__3():
    """Raises ValueError if Authorization scheme is not Bearer."""
    headers = dict(Authorization='Foobar <TOKEN>')
    with pytest.raises(ValueError) as err:
        extract_token(headers)
    assert 'Authorization schema is not Bearer' == str(err.value)


def test_header__extract_token__4():
    """Raises ValueError if scheme is missing."""
    headers = dict(Authorization='<TOKEN>')
    with pytest.raises(ValueError) as err:
        extract_token(headers)
    assert 'Authorization schema is not Bearer' == str(err.value)
