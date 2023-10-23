from app.utils import check_state


def decode(encoded_value_bytes_or_str: bytes | str) -> str | int:
    encoded_value = (
        encoded_value_bytes_or_str.decode()
        if isinstance(encoded_value_bytes_or_str, bytes)
        else encoded_value_bytes_or_str
    )
    if encoded_value[0] == "i" and encoded_value[-1] == "e":
        return decode_integer(encoded_value)
    elif encoded_value[0].isdigit():
        return decode_string(encoded_value)
    else:
        raise NotImplementedError(f"Unknown encoded value {encoded_value}")


def decode_string(encoded_string: str) -> str:
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


def decode_integer(encoded_integer: str) -> int:
    """
    >>> decode_integer("i123e")
    123
    >>> decode_integer("i-123e")
    -123
    """
    if isinstance(encoded_integer, bytes):
        encoded_integer = encoded_integer.decode()
    check_state(
        encoded_integer[0] == "i" and encoded_integer[-1] == "e",
        "Encoded integer must start with 'i' and end with 'e'",
    )
    return int(encoded_integer[1:-1])
