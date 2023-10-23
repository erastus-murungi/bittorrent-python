from pprint import pprint

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
    elif encoded_value[0] == "d":
        return decode_dictionaries(encoded_value)
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
    length, string = encoded_string.split(":", maxsplit=1)
    decoded = string[: int(length)]
    # check_state(
    #     len(decoded) == int(length),
    #     "Length of decoded string does not match length in encoded string",
    # )
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


def parse_element(encoded_value: str) -> tuple[int | str | list[int | str], str]:
    if encoded_value[0] == "i":
        return parse_out_integer(encoded_value)
    elif encoded_value[0].isdigit():
        num_chars = encoded_value.split(":", 1)[0]
        len_count = len(num_chars) + 1 + int(num_chars)
        return decode_string(encoded_value[:len_count]), encoded_value[len_count:]
    elif encoded_value[0] == "l":
        return decode_list(encoded_value), ""
    elif encoded_value[0] == "d":
        return decode_dictionaries(encoded_value), ""
    else:
        raise NotImplementedError(f"Unknown encoded value {encoded_value}")


def decode_list(encoded_list: str) -> list[int | str]:
    check_state(
        encoded_list[0] == "l" and encoded_list[-1] == "e",
        'Encoded list must start with "l" and end with "e"',
    )
    decoded_list = []
    encoded_value: str = encoded_list[1:-1]
    while encoded_value:
        decoded, encoded_value = parse_element(encoded_value)
        decoded_list.append(decoded)
    return decoded_list


def decode_dictionaries(encoded_dict: str) -> dict[str, int | str | list[int | str]]:
    check_state(
        encoded_dict[0] == "d" and encoded_dict[-1] == "e",
        'Encoded dictionary must start with "d" and end with "e"',
    )
    decoded_dict = {}
    encoded_value: str = encoded_dict[1:-1]
    while encoded_value:
        key, encoded_value = parse_element(encoded_value)
        value, encoded_value = parse_element(encoded_value)
        decoded_dict[key] = value
    return decoded_dict


def parse_torrent(
    torrent_filename: str | bytes,
) -> dict[str, int | str | list[int | str]]:
    torrent_filename = (
        torrent_filename
        if isinstance(torrent_filename, str)
        else torrent_filename.decode()
    )
    with open(torrent_filename, "rb") as f:
        encoded_dict = f.read().decode(errors="replace")
        return decode_dictionaries(encoded_dict)


if __name__ == "__main__":
    # import doctest
    #
    # doctest.testmod()
    # print(decode(b"d3:foo3:bar5:helloi52ee"))
    pprint(parse_torrent(b"../sample.torrent"))
