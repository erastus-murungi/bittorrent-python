from collections import defaultdict
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

from app.torrent import Peer


class BlockState(IntEnum):
    PENDING = 1
    RECEIVED = 2
    MISSING = 3


@dataclass(slots=True)
class Block:
    index: int
    offset: int
    length: int
    state: BlockState = BlockState.MISSING
    data: bytes = b""

    def __hash__(self):
        return hash((self.index, self.offset))


class Piece(list[Block]):
    index: int
    length: int
    sha1_hash: bytes

    def __init__(self, index: int, length: int, blocks: list[Block], sha1_hash: bytes):
        super().__init__(blocks)
        self.index = index
        self.length = length
        self.sha1_hash = sha1_hash

    def is_complete(self) -> bool:
        return all(block.state == BlockState.RECEIVED for block in self)

    def has_missing_blocks(self) -> bool:
        return any(block.state == BlockState.MISSING for block in self)

    def get_next_pending_block(self) -> Optional[Block]:
        for block in self:
            if block.state == BlockState.MISSING:
                return block
        return None

    def get_data(self) -> bytes:
        return b"".join(
            block.data for block in sorted(self, key=lambda block: block.offset)
        )

    def __hash__(self):
        return hash(self.index)

    def __eq__(self, other):
        return self.index == other.index


class PiecesRegistry(list[Piece]):
    def __init__(self):
        super().__init__()
        self._peer2pieces: dict[Peer, set[Piece]] = defaultdict(set)
        self._piece2peers: dict[Piece, set[Peer]] = defaultdict(set)

    def get_peers(self):
        return self._peer2pieces.keys()

    def update_pieces_from_peer(self, peer: Peer, bitfield: bytes) -> None:
        pieces_available = set()
        for index, byte in enumerate(bitfield):
            for bit in range(8):
                if byte & (1 << (7 - bit)):
                    pieces_available.add(self[index * 8 + bit])
        self._peer2pieces[peer] |= pieces_available
        for piece in pieces_available:
            self._peer2pieces[peer].add(piece)

    def add_piece_index_for_peer(self, peer: Peer, piece_index: int) -> None:
        piece = self[piece_index]
        self._peer2pieces[peer].add(piece)
        self._piece2peers[piece].add(peer)

    def contains_peer(self, peer: Peer):
        return peer in self._peer2pieces

    def get_by_peer(self, peer: Peer) -> set[Piece]:
        return self._peer2pieces[peer]

    def get_peers_with_piece(self, piece: Piece) -> set[Peer]:
        return self._piece2peers[piece]
