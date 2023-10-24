from app.utils import check_state

BEncodedInteger = int
BEncodedString = bytes
BEncodedList = list[BEncodedInteger | BEncodedString]
BEncodedDictionary = dict[str, BEncodedInteger | BEncodedString | BEncodedList]
BEncodedValue = BEncodedInteger | BEncodedString | BEncodedList | BEncodedDictionary


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


if __name__ == "__main__":
    import doctest

    doctest.testmod()
