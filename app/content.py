from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional, Sized

from math import ceil

from app.constants import BLOCK_LENGTH
from app.torrent import Peer, Info
from app.utils import log


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

    @staticmethod
    def from_info(info: Info, piece_index: int):
        if 0 < piece_index >= len(info.pieces):
            raise IndexError(f"Piece index {piece_index} is out of range")
        sha1_hash = info.pieces[piece_index]
        if piece_index < len(info.pieces) - 1:
            num_blocks_in_piece = ceil(info.piece_length / BLOCK_LENGTH)
            blocks = [
                Block(piece_index, block_index * BLOCK_LENGTH, BLOCK_LENGTH)
                for block_index in range(num_blocks_in_piece)
            ]
        else:
            last_length = info.get_total_size % info.piece_length
            num_blocks_in_piece = ceil(last_length / BLOCK_LENGTH)
            blocks = [
                Block(piece_index, block_index * BLOCK_LENGTH, BLOCK_LENGTH)
                for block_index in range(num_blocks_in_piece)
            ]
            if last_length % BLOCK_LENGTH != 0:
                blocks[-1].length = last_length % BLOCK_LENGTH

        return Piece(piece_index, info.piece_length, blocks, sha1_hash)


class PiecesRegistry(Sized, ABC):
    _peer2pieces: dict[Peer, set[Piece]]
    _piece2peers: dict[Piece, set[Peer]]

    def get_peers(self) -> set[Peer]:
        return set(self._peer2pieces.keys())

    def update_pieces_from_peer(self, peer: Peer, bitfield: bytes) -> None:
        for index, byte in enumerate(bitfield):
            for bit in range(8):
                if byte & (1 << (7 - bit)):
                    self.__update_dicts(peer, index * 8 + bit)

    def __update_dicts(self, peer: Peer, piece_index: int):
        if self.contains_piece_index(piece_index):
            piece = self[piece_index]
            self._peer2pieces[peer].add(piece)
            self._piece2peers[piece].add(peer)
            log(f"Peer {peer} has piece {piece_index}")
        else:
            log(f"Piece {piece_index} is not in the registry")

    def contains_peer(self, peer: Peer):
        return peer in self._peer2pieces

    def get_by_peer(self, peer: Peer) -> set[Piece]:
        return self._peer2pieces[peer]

    def get_peers_with_piece(self, piece: Piece) -> set[Peer]:
        return self._piece2peers[piece]

    def add_piece_index_for_peer(self, peer: Peer, piece_index: int) -> None:
        if piece_index >= len(self):
            raise IndexError(f"Piece index {piece_index} is out of range")
        self.__update_dicts(peer, piece_index)

    def __getitem__(self, item: int) -> Piece:
        raise NotImplementedError

    @abstractmethod
    def contains_piece_index(self, piece_index: int) -> bool:
        pass


class DensePiecesRegistry(list[Piece], PiecesRegistry):
    def __init__(self):
        super().__init__()
        self._peer2pieces: dict[Peer, set[Piece]] = defaultdict(set)
        self._piece2peers: dict[Piece, set[Peer]] = defaultdict(set)

    @staticmethod
    def from_info(info: Info):
        pieces = DensePiecesRegistry()
        for piece_index in range(len(info.pieces)):
            pieces.append(Piece.from_info(info, piece_index))
        return pieces

    def contains_piece_index(self, piece_index: int) -> bool:
        return 0 <= piece_index < len(self)


class SparsePiecesRegistry(dict[int, Piece], PiecesRegistry):
    def __init__(self, pieces: list[Piece]):
        super().__init__({piece.index: piece for piece in pieces})
        self._peer2pieces: dict[Peer, set[Piece]] = defaultdict(set)
        self._piece2peers: dict[Piece, set[Peer]] = defaultdict(set)

    @staticmethod
    def from_info(info: Info, desired_piece_indices: tuple[int, ...]):
        pieces = SparsePiecesRegistry([])
        for piece_index in desired_piece_indices:
            piece = Piece.from_info(info, piece_index)
            pieces[piece_index] = piece
        return pieces

    def contains_piece_index(self, piece_index: int) -> bool:
        return piece_index in self

    def __iter__(self):
        return iter(self.values())
