from __future__ import annotations

import struct
from abc import abstractmethod, ABC
from asyncio import StreamReader, CancelledError
from dataclasses import dataclass
from typing import Final, Optional

from app.constants import HEADER_LENGTH, BLOCK_LENGTH
from app.utils import log


@dataclass
class PeerMessage(ABC):
    """
    Base class for all peer messages.

    Peer Messages are a part of the BitTorrent protocol and are used to facilitate
    communication between peers in a swarm.

    Attributes:
        len (int): The length prefix is a four byte big-endian value.
                   It represents the length of the message, not including the length prefix itself.
        id (int) : ID of the message.
    """

    len: int
    id: int

    @staticmethod
    def from_bytes(buffer: bytes) -> tuple[Optional[PeerMessage], bytes]:
        if len(buffer) < HEADER_LENGTH:
            return None, buffer

        message_length = int.from_bytes(buffer[:HEADER_LENGTH], "big")

        if message_length == 0:
            return KeepAlive.get(), buffer[message_length + HEADER_LENGTH :]

        if len(buffer) < message_length:
            return None, buffer

        message_id = int.from_bytes(
            buffer[HEADER_LENGTH : HEADER_LENGTH + 1],
            "big",
        )
        message_bytes, rest = (
            buffer[: message_length + HEADER_LENGTH],
            buffer[message_length + HEADER_LENGTH :],
        )
        match message_id:
            case Interested.id:
                return Interested.get(), rest
            case Choke.id:
                return Choke.get(), rest
            case Unchoke.id:
                return Unchoke.get(), rest
            case NotInterested.id:
                return NotInterested.get(), rest
            case Have.id:
                return Have.decode(message_bytes), rest
            case BitField.id:
                return BitField.decode(message_bytes), rest
            case Request.id:
                return Request.decode(message_bytes), rest
            case Piece.id:
                return Piece.decode(message_bytes), rest
            case Cancel.id:
                return Cancel.decode(message_bytes), rest
            case Port.id:
                return Port.decode(message_bytes), rest
            case _:
                raise ValueError(f"Invalid message id {message_id}")


class FixedLengthPeerMessage(PeerMessage, ABC):
    """
    Base class for fixed length peer messages.

    FixedLengthPeerMessage is a specialized type of PeerMessage where the message length is fixed.
    """

    @staticmethod
    @abstractmethod
    def pack() -> bytes:
        """
        Packs a message into bytes for transmission.

        Returns:
            bytes: Byte representation of the message.
        """
        pass

    @staticmethod
    @abstractmethod
    def get():
        """
        Returns an instance of a message.

        Returns:
            PeerMessage: An instance of a specific PeerMessage subclass.
        """
        pass


@dataclass
class KeepAlive(FixedLengthPeerMessage):
    """
    Keep-alive messages with length prefix set to zero are periodically (usually 2 minutes) sent to maintain the connection alive.

    BitTorrent Specification:
    keep-alive: <len=0000>
    """

    len: int = 0
    id: int = -1

    @staticmethod
    def pack():
        return struct.pack("!I", KeepAlive.len)

    @staticmethod
    def get():
        return KeepAlive()


@dataclass
class Choke(FixedLengthPeerMessage):
    """
    The choke message is used to tell the peer that it should stop sending requests.

    BitTorrent Specification:
    choke: <len=0001><id=0>
    """

    len: int = 1
    id: int = 0

    @staticmethod
    def pack() -> bytes:
        return struct.pack("!IB", Choke.len, Choke.id)

    @staticmethod
    def get():
        return Choke()


@dataclass
class Unchoke(FixedLengthPeerMessage):
    """
    The unchoke message is used to tell the peer that it may continue sending requests.

    BitTorrent Specification:
    unchoke: <len=0001><id=1>
    """

    len: int = 1
    id: int = 1

    @staticmethod
    def pack() -> bytes:
        return struct.pack("!IB", Unchoke.len, Unchoke.id)

    @staticmethod
    def get():
        return Unchoke()


@dataclass
class Interested(FixedLengthPeerMessage):
    """
    The interested message is used to tell the peer that the sender is interested in downloading.

    BitTorrent Specification:
    interested: <len=0001><id=2>
    """

    len: int = 1
    id: int = 2

    @staticmethod
    def pack() -> bytes:
        return struct.pack("!IB", Interested.len, Interested.id)

    @staticmethod
    def get():
        return Interested()


@dataclass
class NotInterested(FixedLengthPeerMessage):
    """
    The not interested message is used to tell the peer that the sender is not interested in downloading.

    BitTorrent Specification:
    not interested: <len=0001><id=3>
    """

    len: int = 1
    id: int = 3

    @staticmethod
    def pack() -> bytes:
        return struct.pack("!IB", NotInterested.len, NotInterested.id)

    @staticmethod
    def get():
        return NotInterested()


@dataclass(kw_only=True)
class Have(PeerMessage):
    """
    The "have" message is used by a peer to say that it has a specific piece.

    BitTorrent Specification:
    have: <len=0005><id=4><piece index>
    """

    piece_index: int
    len: int = 5
    id: int = 4

    def pack(self) -> bytes:
        return struct.pack("!IBI", Have.len, Have.id, self.piece_index)

    @staticmethod
    def decode(bytestring: bytes) -> Have:
        length, identifier, piece_index = struct.unpack("!IBI", bytestring)
        return Have(piece_index=piece_index, len=length, id=identifier)


@dataclass(kw_only=True)
class BitField(PeerMessage):
    """
    The bitfield message is used to exchange information about pieces that a peer has.

    BitTorrent Specification:
    bitfield: <len=0001+X><id=5><bitfield> where X is the length of the bitfield.
    """

    bitfield: bytes
    id: int = 5

    def pack(self):
        return struct.pack("!IB", BitField.len, BitField.id) + self.bitfield

    @staticmethod
    def decode(bytestring: bytes) -> BitField:
        length, identifier = struct.unpack("!IB", bytestring[:5])
        bitfield = bytestring[5:]
        assert len(bitfield) == length - 1
        return BitField(bitfield=bitfield, len=length, id=identifier)


@dataclass(kw_only=True)
class Request(PeerMessage):
    """
    The request message is used to request a block of a piece from a peer.

    BitTorrent Specification:
    request: <len=0013><id=6><index><begin><length>
    """

    index: int
    begin: int
    length: int
    id: int = 6
    len: int = 13

    def pack(self):
        """See base class."""
        return struct.pack(
            "!IBIII", Request.len, Request.id, self.index, self.begin, self.length
        )

    @staticmethod
    def decode(bytestring: bytes) -> Request:
        length, identifier, index, begin, length = struct.unpack("!IBIII", bytestring)
        return Request(
            index=index, begin=begin, length=length, len=length, id=identifier
        )


@dataclass(kw_only=True)
class Piece(PeerMessage):
    """
    The piece message is used to deliver a block of a piece that has been requested.

    BitTorrent Specification:
    piece: <len=0009+X><id=7><index><begin><block> where X is the length of the block.
    """

    index: int  # The zero-based piece index.
    begin: int  # The zero-based byte offset within the piece.
    block: bytes  # The actual data.
    id: int = 7

    def __post_init__(self):
        assert len(self.block) == self.len - 9

    def block_length(self):
        return len(self.block)

    @staticmethod
    def decode(bytestring: bytes) -> Piece:
        length, identifier, index, begin = struct.unpack("!IBII", bytestring[:13])
        block = bytestring[13:]
        return Piece(index=index, begin=begin, block=block, len=length, id=identifier)


@dataclass(kw_only=True)
class Cancel(PeerMessage):
    """
    The cancel message is used to cancel a block request.

    BitTorrent Specification:
    cancel: <len=0013><id=8><index><begin><length>
    """

    index: int
    begin: int
    length: int
    id: int = 8
    len: int = 13

    def pack(self):
        return struct.pack(
            "!IBIII", Cancel.len, Cancel.id, self.index, self.begin, self.length
        )

    @staticmethod
    def decode(bytestring: bytes) -> Cancel:
        length, identifier, index, begin, length = struct.unpack("!IBIII", bytestring)
        return Cancel(
            index=index, begin=begin, length=length, len=length, id=identifier
        )


@dataclass(kw_only=True)
class Port(PeerMessage):
    """
    The port message is used to tell the peer which port the sender is listening on.

    BitTorrent Specification:
    port: <len=0003><id=9><listen-port>
    """

    listen_port: int
    id: int = 9
    len: int = 3

    def pack(self):
        """See base class."""
        return struct.pack("!IBH", Port.len, Port.id, self.listen_port)

    @staticmethod
    def decode(bytestring: bytes) -> Port:
        length, identifier, listen_port = struct.unpack("!IBH", bytestring)
        return Port(listen_port=listen_port, len=length, id=identifier)


@dataclass(slots=True, kw_only=True)
class HandShake:
    """
    The handshake message is the first message sent and then received from a remote peer.

    BitTorrent Specification:
    handshake: <pstrlen><pstr><reserved><info_hash><peer_id>
    """

    peer_id: bytes
    info_hash: bytes
    reserved: bytes = 8 * b"\x00"
    pstr: bytes = b"BitTorrent protocol"
    pstrlen: Final[int] = 19

    def __post_init__(self):
        assert len(self.pstr) == self.pstrlen, "pstrlen does not match pstr length"
        assert len(self.reserved) == 8, "reserved does not match reserved length"
        assert len(self.info_hash) == 20, "info_hash is not 20 bytes"
        assert len(self.peer_id) == 20, "peer_id is not 20 bytes"

    def pack(self):
        return struct.pack(
            ">B19s8x20s20s", self.pstrlen, self.pstr, self.info_hash, self.peer_id
        )

    @staticmethod
    def decode(resp: bytes):
        (
            _,
            _,
            info_hash,
            peer_id,
        ) = struct.unpack(">B19s8x20s20s", resp)
        return HandShake(info_hash=info_hash, peer_id=peer_id)


@dataclass(slots=True)
class PeerStreamAsyncIterator:
    reader: StreamReader
    buffer: bytes = b""

    def __aiter__(self):
        return self

    def _check_buffer_and_get_message(self) -> Optional[PeerMessage]:
        if self.buffer:
            message, self.buffer = PeerMessage.from_bytes(self.buffer)
            if message:
                return message
        return None

    async def __anext__(self):
        try:
            while True:
                data = await self.reader.read(BLOCK_LENGTH)
                if data:
                    self.buffer += data
                else:
                    log("No data received from peer")
                message = self._check_buffer_and_get_message()
                if message:
                    return message
                if not data:
                    raise StopAsyncIteration
        except CancelledError:
            raise StopAsyncIteration()
        except Exception as exception:
            log(f"Error when iterating over stream! {exception}")
            raise StopAsyncIteration()


if __name__ == "__main__":
    import doctest

    doctest.testmod()
