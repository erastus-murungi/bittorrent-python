from typing import Union

BEncodedInteger = int
BEncodedString = bytes
BEncodedList = list[Union[BEncodedInteger, BEncodedString]]
BEncodedDictionary = dict[str, Union[BEncodedInteger, BEncodedString, BEncodedList]]
BEncodedValue = Union[BEncodedInteger, BEncodedString, BEncodedList, BEncodedDictionary]


class _Decoder:
    """
    This class is used for decoding bencoded data.

    Attributes:
        _data (bytes): bencoded data to decode.

    Example usage:
        _decoder = _Decoder(b"i123e")
        print(_decoder.decode())  # 123
    """

    def __init__(self, data: bytes = b""):
        """Initializes the Decoder with optional data."""
        self._data = data

    def set_data(self, data: bytes):
        """Sets data to decode."""
        self._data = data

    def decode(self) -> BEncodedValue:
        """
        Decodes the data according to its BEncoded type.

        Raises:
            ValueError: If the data cannot be decoded.

        Returns:
            Decoded data.
        """
        data_start = self._data[:1]

        if data_start == b"i":
            return self._decode_integer()
        elif data_start.isdigit():
            return self._decode_string()
        elif data_start == b"l":
            return self._decode_list()
        elif data_start == b"d":
            return self._decode_dict()
        else:
            raise ValueError(f"Unknown encoded value {self._data}")

    def _decode_integer(self) -> BEncodedInteger:
        """
        Decodes an integer from the data.

        Returns:
            Decoded integer.
        """
        int_end_index = self._data.index(b"e")
        int_str, self._data = (
            self._data[1:int_end_index],
            self._data[int_end_index + 1 :],
        )
        return int(int_str)

    def _decode_string(self) -> BEncodedString:
        """
        Decodes a string from the data.

        Returns:
            Decoded string.
        """
        colon_pos = self._data.index(b":")
        length = int(self._data[:colon_pos])
        self._data = self._data[colon_pos + 1 :]
        decoded = self._data[:length]
        self._data = self._data[length:]
        assert len(decoded) == int(
            length
        ), "Length of decoded string does not match length in encoded string"
        return decoded

    def _decode_list(self) -> BEncodedList:
        """
        Decodes a list from the data.

        Returns:
            Decoded list.
        """
        decoded_list = []
        self._data = self._data[1:]
        while self._data[:1] != b"e":
            decoded_list.append(self.decode())
        self._data = self._data[1:]
        return decoded_list

    def _decode_dict(self) -> BEncodedDictionary:
        """
        Decodes a dictionary from the data.

        Returns:
            Decoded dictionary.
        """
        decoded_dict = {}
        self._data = self._data[1:]
        while self._data[:1] != b"e":
            key = self._decode_string()
            value = self.decode()
            decoded_dict[key.decode()] = value
        self._data = self._data[1:]
        return decoded_dict


def bencode_decode(bytestring: bytes) -> BEncodedValue:
    """
    Decodes a bytestring from bencode format into a Python data type.

    Args:
        bytestring (bytes): The bencoded data to decode.

    Returns:
        BEncodedValue: The decoded data.

    Example:
        >>> bencode_decode(b"i123e")
        123
        >>> bencode_decode(b"5:hello")
        b'hello'
    """
    decoder = _Decoder(bytestring)
    return decoder.decode()


def bencode_encode(value: BEncodedValue | str | bytes) -> bytes:
    """
    Encodes a Python data type into bencode format.

    Args:
        value (BEncodedValue | str | bytes): The data to encode.

    Returns:
        bytes: The encoded data.

    Raises:
        TypeError: If the data type cannot be encoded.

    Example:
        >>> bencode_encode(123)
        b'i123e'
        >>> bencode_encode(b'hello')
        b'5:hello'
        >>> bencode_encode([123, b'hello'])
        b'li123e5:helloe'
        >>> bencode_encode({'foo': b'bar', 'hello': 52})
        b'd3:foo3:bar5:helloi52ee'
    """
    match value:
        case int():
            return f"i{value}e".encode()
        case str():
            return f"{len(value)}:{value}".encode()
        case bytes():
            return f"{len(value)}:".encode() + value
        case list():
            return b"l" + b"".join(bencode_encode(val) for val in value) + b"e"
        case dict():
            return (
                b"d"
                + b"".join(
                    bencode_encode(key) + bencode_encode(val)
                    for key, val in value.items()
                )
                + b"e"
            )
        case _:
            raise TypeError(f"cannot encode {value} of type {type(value)}")


if __name__ == "__main__":
    import doctest

    doctest.testmod()
