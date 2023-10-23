from app.utils import check_state


def parse_out_integer(encoded_str: str) -> tuple[int, str]:
    check_state(encoded_str[0] == "i", "Encoded integer must start with 'i'")
    int_end_index = encoded_str.index("e", 0)
    return int(encoded_str[1:int_end_index]), encoded_str[int_end_index + 1 :]


def decode(encoded_value_bytes_or_str: bytes | str) -> str | int | list[int | str]:
    encoded_value = (
        encoded_value_bytes_or_str.decode()
        if isinstance(encoded_value_bytes_or_str, bytes)
        else encoded_value_bytes_or_str
    )
    if encoded_value[0] == "i" and encoded_value[-1] == "e":
        return decode_integer(encoded_value)
    elif encoded_value[0].isdigit():
        return decode_string(encoded_value)
    elif encoded_value[0] == "l":
        return decode_list(encoded_value)
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


def decode_list(encoded_list: str) -> list[int | str]:
    check_state(
        encoded_list[0] == "l" and encoded_list[-1] == "e",
        'Encoded list must start with "l" and end with "e"',
    )
    decoded_list = []
    encoded_value: str = encoded_list[1:-1]
    while encoded_value:
        if encoded_value[0] == "i":
            decoded_int, encoded_value = parse_out_integer(encoded_value)
            decoded_list.append(decoded_int)
        elif encoded_value[0].isdigit():
            num_chars = encoded_value.split(":", 1)[0]
            len_count = len(num_chars) + 1 + int(num_chars)
            decoded_str, encoded_value = (
                decode_string(encoded_value[:len_count]),
                encoded_value[len_count:],
            )
            decoded_list.append(decoded_str)
        elif encoded_value[0] == "l":
            decoded_list.append(decode_list(encoded_value))
            encoded_value = ""
        print(decoded_list, encoded_value)
    return decoded_list


if __name__ == "__main__":
    # import doctest
    #
    # doctest.testmod()
    decode(b"l4:spam4:eggse")
