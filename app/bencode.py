# import hashlib
# from pathlib import Path
# from pprint import pprint
#
import hashlib
from pathlib import Path

import requests

from app.utils import check_state

#
BEncodedInteger = int
BEncodedString = bytes
BEncodedList = list[BEncodedInteger | BEncodedString]
BEncodedDictionary = dict[str, BEncodedInteger | BEncodedString | BEncodedList]
BEncodedValue = BEncodedInteger | BEncodedString | BEncodedList | BEncodedDictionary


#
#

#
#
# #
# #
# # def pprint_metainfo(encoded_value: str):
# #     pprint(decode_dict(encoded_value))
#
#
# MY_PEER_ID = "DFYUIWdBtmfTePjL6adX"
# MY_PORT = 6881
#
#
# # def discover_peers(meta_info: BEncodedDictionary):
# #     tracker_url = meta_info["announce"]
# #     response = requests.get(
# #         tracker_url,
# #         params={
# #             "info_hash": calc_info_hash_for_request(meta_info),
# #             "peer_id": "00112233445566778899",
# #             "port": MY_PORT,
# #             "uploaded": 0,
# #             "downloaded": 0,
# #             "left": meta_info["info"]["length"],
# #             "compact": 1,
# #         },
# #     )
# #
# #     tracker_response1 = decode_dict(response.text)
# #     tracker_response2 = bencodepy.decode(response.content)
# #     print(tracker_response1["peers"].encode(response.encoding))
# #     print(tracker_response2[b"peers"])
# #     assert (
# #         tracker_response1["peers"].encode(response.encoding)
# #         == tracker_response2[b"peers"]
# #     )
# #     pprint(tracker_response1)
# #     pprint(tracker_response2)
# # check_state(b"interval" in tracker_response, "No interval in response")
# # check_state(b"peers" in tracker_response, "No peers in response")
# # peers = tracker_response[b"peers"]
# # check_state(len(peers) % 6 == 0, "Peers length is not a multiple of 6")
# # for i in range(0, len(peers), 6):
# #     peer_info = peers[i : i + 6]
# #     ip = ip_address(int.from_bytes(peer_info[:4], byteorder="big", signed=False))
# #     port = int.from_bytes(peer_info[4:], byteorder="big", signed=False)
# #     print(f"{ip}:{port}")
#
#


from typing import Generator, TypeAlias

BCGen: TypeAlias = Generator[bytes, None, bool]


class BencodeParser:
    """Decode and encode bencode"""

    def __init__(self):
        self._data: bytes = b""

    def decode(self, data: bytes) -> BEncodedValue:
        self._data = data
        return self._decode()

    def _decode(self) -> BEncodedValue:
        if self._data[:1] == b"i":
            return self._decode_integer()
        elif self._data[:1].isdigit():
            return self._decode_string()
        elif self._data[:1] == b"l":
            return self._decode_list()
        elif self._data[:1] == b"d":
            return self._decode_dict()
        else:
            raise NotImplementedError(f"Unknown encoded value {self._data}")

    def _decode_integer(self) -> BEncodedInteger:
        check_state(self._data[:1] == b"i", "Encoded integer must start with 'i'")
        int_end_index = self._data.index(b"e", 0)
        check_state(int_end_index != -1, "Encoded integer must end with 'e'")
        int_str, self._data = (
            self._data[1:int_end_index],
            self._data[int_end_index + 1 :],
        )
        return int(int_str)

    def _decode_string(self) -> BEncodedString:
        check_state(self._data[:1].isdigit(), "Encoded string must start with a digit")
        colon_pos = self._data.index(b":", 0)
        check_state(colon_pos != -1, "Encoded string must contain a colon")
        length = int(self._data[:colon_pos])
        self._data = self._data[colon_pos + 1 :]
        decoded = self._data[:length]
        self._data = self._data[length:]
        check_state(
            len(decoded) == int(length),
            "Length of decoded string does not match length in encoded string",
        )
        return decoded

    def _decode_list(self) -> BEncodedList:
        check_state(
            self._data[:1] == b"l" and self._data[-1:] == b"e",
            'Encoded list must start with "l" and end with "e"',
        )
        decoded_list = []
        self._data = self._data[1:]
        while self._data[:1] != b"e":
            decoded_list.append(self._decode())
        self._data = self._data[1:]
        return decoded_list

    def _decode_dict(self) -> BEncodedDictionary:
        check_state(
            self._data[:1] == b"d" and self._data[-1:] == b"e",
            'Encoded dictionary must start with "d" and end with "e"',
        )
        decoded_dict = {}
        self._data = self._data[1:]
        while self._data[:1] != b"e":
            key = self._decode_string()
            value = self._decode()
            decoded_dict[key.decode()] = value
        self._data = self._data[1:]
        return decoded_dict

    @staticmethod
    def decode_integer(encoded_integer: bytes) -> BEncodedInteger:
        """
        >>> BencodeParser.decode_integer(b"i123e")
        123
        >>> BencodeParser.decode_integer(b"i-123e")
        -123
        """
        check_state(
            encoded_integer[0:1] == b"i" and encoded_integer[-1:] == b"e",
            "Encoded integer must start with 'i' and end with 'e'",
        )
        return int(encoded_integer[1:-1])

    @staticmethod
    def decode_string(encoded_value: bytes) -> BEncodedValue:
        """
        >>> BencodeParser.decode_string(b"5:hello")
        b'hello'
        >>> BencodeParser.decode_string(b"10:hello12345")
        b'hello12345'
        """
        check_state(
            encoded_value[:1].isdigit(), "Encoded string must start with a digit"
        )
        length, string = encoded_value.split(b":", maxsplit=1)
        decoded = string[: int(length)]
        check_state(
            len(decoded) == int(length),
            "Length of decoded string does not match length in encoded string",
        )
        return decoded

    def encode(self, data: BEncodedValue | bytes) -> bytes:
        match data:
            case int():
                return f"i{data}e".encode()
            case str():
                return f"{len(data)}:{data}".encode()
            case bytes():
                return f"{len(data)}:".encode() + data
            case list():
                return b"l" + b"".join(self.encode(val) for val in data) + b"e"
            case dict():
                return (
                    b"d"
                    + b"".join(
                        self.encode(key) + self.encode(val) for key, val in data.items()
                    )
                    + b"e"
                )
            case _:
                raise ValueError(f"cannot encode {data} of type {type(data)}")


def bencode_decode(bencoded_value: bytes) -> BEncodedValue:
    """
    >>> bencode_decode(b"i123e")
    123
    >>> bencode_decode(b"5:hello")
    b'hello'
    >>> bencode_decode(b"li123e5:helloe")
    [123, b'hello']
    >>> bencode_decode(b"d3:foo3:bar5:helloi52ee")
    {'foo': b'bar', 'hello': 52}
    """
    return BencodeParser().decode(bencoded_value)


def bencode_encode(value: BEncodedValue) -> bytes:
    """
    >>> bencode_encode(123)
    b'i123e'
    >>> bencode_encode(b'hello')
    b'5:hello'
    >>> bencode_encode([123, b'hello'])
    b'li123e5:helloe'
    >>> bencode_encode({'foo': b'bar', 'hello': 52})
    b'd3:foo3:bar5:helloi52ee'
    """
    return BencodeParser().encode(value)


def parse_torrent(
    torrent_filename: str | bytes,
) -> BEncodedDictionary:
    torrent_filename = (
        torrent_filename
        if isinstance(torrent_filename, str)
        else torrent_filename.decode()
    )
    encoded_dict = Path(torrent_filename).read_bytes()
    return BencodeParser().decode(encoded_dict)


def calc_info_hash(meta_info: BEncodedDictionary):
    info = meta_info["info"]
    info_bytes = bencode_encode(info)
    return hashlib.sha1(info_bytes).hexdigest()


def calc_info_hash_for_request(meta_info: BEncodedDictionary):
    info = meta_info["info"]
    info_bytes = bencode_encode(info)
    return hashlib.sha1(info_bytes).digest()


def get_piece_hashes(meta_info: BEncodedDictionary):
    info: BEncodedDictionary = meta_info["info"]
    pieces = info["pieces"]
    piece_hashes = []
    for i in range(0, len(pieces), 20):
        piece_hashes.append(pieces[i : i + 20].hex())
    return piece_hashes


def discover_peers(torrent_filename: bytes | str):
    meta_info = parse_torrent(torrent_filename)
    tracker_response = requests.get(
        meta_info["announce"].decode(),
        params={
            "info_hash": calc_info_hash_for_request(meta_info),
            "peer_id": "00112233445566778899",
            "port": 6881,
            "uploaded": 0,
            "downloaded": 0,
            "left": meta_info["info"]["length"],
            "compact": 1,
        },
    )
    tracker_info = bencode_decode(tracker_response.content)
    check_state("interval" in tracker_info, "No interval in response")
    check_state("peers" in tracker_info, "No peers in response")
    return tracker_info


if __name__ == "__main__":
    import doctest

    doctest.testmod()
