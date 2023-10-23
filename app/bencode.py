from app.utils import check_state


def decode_string(encoded_string: str | bytes) -> str:
    """
    >>> decode_string("5:hello")
    'hello'
    >>> decode_string("10:hello12345")
    'hello12345'
    """
    if isinstance(encoded_string, bytes):
        encoded_string = encoded_string.decode()
    length, string = encoded_string.split(":")
    decoded = string[: int(length)]
    check_state(
        len(decoded) == int(length),
        "Length of decoded string does not match length in encoded string",
    )
    return decoded
