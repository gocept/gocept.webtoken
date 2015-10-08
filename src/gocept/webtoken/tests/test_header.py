from gocept.webtoken import create_authorization_header, extract_token
import pytest


def test_header__create_authorization_header__1():
    """Function creates bearer header for a given webtoken dict."""
    key, value = create_authorization_header({'token': b'<TOKEN>'})
    assert 'Authorization' == key
    assert 'Bearer <TOKEN>' == value


def test_header__create_authorization_header__2():
    """Function creates bearer header for a given webtoken."""
    key, value = create_authorization_header(b'<TOKEN>')
    assert 'Authorization' == key
    assert 'Bearer <TOKEN>' == value


def test_header__extract_token__1():
    """`extract_token()` extracts token from given dict."""
    headers = dict(Authorization='Bearer <TOKEN>')
    assert b'<TOKEN>' == extract_token(headers)


def test_header__extract_token__2():
    """`extract_token()`  raises ValueError if Authorization key is missing."""
    with pytest.raises(ValueError) as err:
        extract_token({})
    assert 'Missing Authorization header' == str(err.value)


def test_header__extract_token__3():
    """`extract_token()`  raises ValueError on wrong Authorization scheme."""
    headers = dict(Authorization='Foobar <TOKEN>')
    with pytest.raises(ValueError) as err:
        extract_token(headers)
    assert 'Authorization schema is not Bearer' == str(err.value)


def test_header__extract_token__4():
    """`extract_token()`  raises ValueError if scheme is missing."""
    headers = dict(Authorization='<TOKEN>')
    with pytest.raises(ValueError) as err:
        extract_token(headers)
    assert 'Authorization schema is not Bearer' == str(err.value)
