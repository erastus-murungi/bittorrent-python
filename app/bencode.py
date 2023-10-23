import hashlib
from pathlib import Path
from pprint import pprint

from app.utils import check_state

BEncodedInteger = int
BEncodedString = str
BEncodedList = list[BEncodedInteger | BEncodedString]
BEncodedDictionary = dict[str, BEncodedInteger | BEncodedString | BEncodedList]
BEncodedValue = BEncodedInteger | BEncodedString | BEncodedList | BEncodedDictionary


def bencode_decode(encoded_value_bytes_or_str: bytes | str) -> BEncodedValue:
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


def parse_integer(encoded_str: str) -> tuple[BEncodedInteger, str]:
    check_state(encoded_str[0] == "i", "Encoded integer must start with 'i'")
    int_end_index = encoded_str.index("e", 0)
    return int(encoded_str[1:int_end_index]), encoded_str[int_end_index + 1 :]


def decode_string(encoded_string: str) -> BEncodedString:
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
    check_state(
        len(decoded) == int(length),
        "Length of decoded string does not match length in encoded string",
    )
    return decoded


def decode_integer(encoded_integer: str) -> BEncodedInteger:
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


def parse_string(encoded_value: str) -> tuple[str, BEncodedString]:
    """
    >>> parse_string("5:hello")
    ('hello', '')
    >>> parse_string("10:hello12345")
    ('hello12345', '')
    """
    check_state(encoded_value[0].isdigit(), "Encoded string must start with a digit")
    length, string = encoded_value.split(":", maxsplit=1)
    decoded = string[: int(length)]
    check_state(
        len(decoded) == int(length),
        "Length of decoded string does not match length in encoded string",
    )
    return decoded, string[int(length) :]


def parse_element(
    encoded_value: str,
) -> tuple[BEncodedValue, str]:
    if encoded_value[0] == "i":
        return parse_integer(encoded_value)
    elif encoded_value[0].isdigit():
        return parse_string(encoded_value)
    elif encoded_value[0] == "l":
        return decode_list(encoded_value), ""
    elif encoded_value[0] == "d":
        return decode_dictionaries(encoded_value), ""
    else:
        raise NotImplementedError(f"Unknown encoded value {encoded_value}")


def decode_list(encoded_list: str) -> BEncodedList:
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


def decode_dictionaries(encoded_dict: str) -> BEncodedDictionary:
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


def bencode_encode(value: BEncodedValue) -> str:
    if isinstance(value, int):
        return encode_integer(value)
    elif isinstance(value, str):
        return encode_string(value)
    elif isinstance(value, list):
        return encode_list(value)
    elif isinstance(value, dict):
        return encode_dict(value)
    else:
        raise NotImplementedError(f"Unknown value {value}")


def encode_integer(value: BEncodedInteger) -> str:
    return f"i{value}e"


def encode_string(value: BEncodedString) -> str:
    return f"{len(value)}:{value}"


def encode_list(value: BEncodedList) -> str:
    return "l" + "".join(map(bencode_encode, value)) + "e"


def encode_dict(value: BEncodedDictionary) -> str:
    return f'd{"".join(bencode_encode(key) + bencode_encode(value) for key, value in value.items())}e'


def parse_torrent(
    torrent_filename: str | bytes,
) -> BEncodedDictionary:
    torrent_filename = (
        torrent_filename
        if isinstance(torrent_filename, str)
        else torrent_filename.decode()
    )
    encoded_dict = Path(torrent_filename).read_bytes().decode("latin-1")
    check_state(
        encoded_dict[0] == "d" and encoded_dict[-1] == "e",
        'Encoded dictionary must start with "d" and end with "e"',
    )
    decoded_dict = {}
    encoded_value: str = encoded_dict[1:-1]
    while encoded_value:
        key, encoded_value = parse_string(encoded_value)
        value, encoded_value = parse_element(encoded_value)
        decoded_dict[key] = value
    return decoded_dict


def calc_info_hash(meta_info: BEncodedDictionary):
    info = meta_info["info"]
    info_bytes = bencode_encode(info).encode("latin-1")
    return hashlib.sha1(info_bytes).hexdigest()


def get_piece_hashes(meta_info: BEncodedDictionary):
    info: BEncodedDictionary = meta_info["info"]
    pieces = info["pieces"]
    piece_hashes = []
    for i in range(0, len(pieces), 20):
        piece_hashes.append(pieces[i : i + 20].encode("latin-1").hex())
    return piece_hashes


if __name__ == "__main__":
    # import doctest
    #
    # doctest.testmod()
    # print(decode(b"d3:foo3:bar5:helloi52ee"))
    metainfo = parse_torrent(b"../sample.torrent")
    pprint(metainfo)
    print(calc_info_hash(metainfo))
    print(get_piece_hashes(metainfo))
