def create_authorization_header(token_or_dict):
    """Create a Bearer Authorization header from token.

    Takes either a token_dict as returned by create_web_token or a token
    directly.
    """
    if isinstance(token_or_dict, dict):
        token = token_or_dict['token']
    else:
        token = token_or_dict
    return ('Authorization', 'Bearer {}'.format(token.decode('ascii')))


def extract_token(request_headers):
    """Extract token from Bearer Authorization header.

    Takes a dict containing the Authorization header.
    """
    header_value = request_headers.get('Authorization')
    if header_value is None:
        raise ValueError('Missing Authorization header')
    schema, _, encoded_token = header_value.partition(' ')
    if schema.lower() != 'bearer':
        raise ValueError('Authorization scheme is not Bearer')
    return encoded_token.encode('ascii')
