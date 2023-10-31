from __future__ import annotations

import struct
from abc import abstractmethod
from dataclasses import dataclass
from typing import Final

from app.utils import check_state


@dataclass
class PeerMessage:
    # The length prefix is a four byte big-endian value
    len: int
    id: int


class FixedLengthPeerMessage(PeerMessage):
    @staticmethod
    @abstractmethod
    def get():
        pass


@dataclass
class KeepAlive(FixedLengthPeerMessage):
    # keep-alive: <len=0000>
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
    # choke: <len=0001><id=0>
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
    # unchoke: <len=0001><id=1>
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
    # interested: <len=0001><id=2>
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
    # not interested: <len=0001><id=3>
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
    # have: <len=0005><id=4><piece index>
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
    # bitfield: <len=0001+X><id=5><bitfield>
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
    # request: <len=0013><id=6><index><begin><length>

    # integer specifying the zero-based piece index
    index: int

    # integer specifying the zero-based byte offset within the piece
    begin: int

    # integer specifying the requested length
    length: int

    id: int = 6
    len: int = 13

    def pack(self):
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
    # piece: <len=0009+X><id=7><index><begin><block>
    index: int
    begin: int
    block: bytes

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
    # cancel: <len=0013><id=8><index><begin><length>
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
    # port: <len=0003><id=9><listen-port>
    listen_port: int

    id: int = 9
    len: int = 3

    def pack(self):
        return struct.pack("!IBH", Port.len, Port.id, self.listen_port)

    @staticmethod
    def decode(bytestring: bytes) -> Port:
        length, identifier, listen_port = struct.unpack("!IBH", bytestring)
        return Port(listen_port=listen_port, len=length, id=identifier)


@dataclass(slots=True, kw_only=True)
class HandShake:
    # pstr: string identifier of the protocol
    peer_id: bytes
    info_hash: bytes
    reserved: bytes = 8 * b"\x00"
    pstr: bytes = b"BitTorrent protocol"
    pstrlen: Final[int] = 19

    def __post_init__(self):
        check_state(
            len(self.pstr) == self.pstrlen, "pstrlen does not match pstr length"
        )
        check_state(len(self.reserved) == 8, "reserved does not match reserved length")
        check_state(len(self.info_hash) == 20, "info_hash is not 20 bytes")
        check_state(len(self.peer_id) == 20, "peer_id is not 20 bytes")

    def pack(self):
        # handshake: <pstrlen><pstr><reserved><info_hash><peer_id>
        # return (
        #     self.pstrlen.to_bytes(1, "big")
        #     + self.pstr
        #     + self.reserved
        #     + self.info_hash
        #     + self.peer_id
        # )

        return struct.pack(
            ">B19s8x20s20s", self.pstrlen, self.pstr, self.info_hash, self.peer_id
        )

    @staticmethod
    def decode(resp: bytes):
        # handshake: <pstrlen><pstr><reserved><info_hash><peer_id>
        (
            _,
            _,
            info_hash,
            peer_id,
        ) = struct.unpack(">B19s8x20s20s", resp)
        return HandShake(info_hash=info_hash, peer_id=peer_id)


if __name__ == "__main__":
    print(KeepAlive.id)
    print(Interested())
    print(Port(listen_port=3))
