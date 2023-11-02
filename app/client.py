import asyncio
import hashlib
import time
import traceback
from asyncio import StreamReader, StreamWriter, CancelledError
from bisect import insort
from collections import defaultdict
from dataclasses import dataclass
from enum import IntEnum, IntFlag
from ipaddress import IPv4Address, IPv6Address
from typing import Optional

from math import ceil

from app.constants import (
    PEER_MESSAGE_LENGTH_SIZE,
    BLOCK_LENGTH,
    PEER_ID,
)
from app.messages import (
    Interested,
    KeepAlive,
    Choke,
    Unchoke,
    NotInterested,
    Have,
    BitField,
    Request,
    Piece,
    Cancel,
    Port,
    PeerMessage,
    HandShake,
)
from app.torrent import Peer, Torrent
from app.utils import log

IPAddress = IPv4Address | IPv6Address


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


class OnePiece(list[Block]):
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


@dataclass(kw_only=True)
class PendingBlockRequest:
    block: Block
    start_time_ns: int = 0
    max_pending_time_ns: int = 60_000 * 1_000_000

    def __post_init__(self):
        self.start_time_ns = time.monotonic_ns()

    def is_expired(self):
        return self.start_time_ns + self.max_pending_time_ns < time.monotonic_ns()


class PieceManager:
    def __init__(
        self,
        torrent_file: Torrent,
        *,
        max_pending_time_ms: int = 60_000,
        piece_indices: tuple[int, ...] = None,
    ):
        self.block_queue = asyncio.Queue[tuple[Peer, Piece]]()
        self.torrent_file = torrent_file

        self._peer_to_pieces_registry: dict[Peer, set[OnePiece]] = defaultdict(set)
        self._piece_to_peers_registry: dict[OnePiece, set[Peer]] = defaultdict(set)

        self.pending_block_requests: dict[
            Peer, dict[int, PendingBlockRequest]
        ] = defaultdict(dict)
        self.completed_pieces: list[OnePiece] = []
        self.pieces: list[OnePiece] = self._init_pieces(piece_indices)
        self.max_pending_time_ns = max_pending_time_ms * 1_000_000
        self.abort = False
        self.future = asyncio.ensure_future(self.save_block())
        self.piece_indices = piece_indices

    def close(self):
        self.abort = True

    def _init_pieces(self, piece_indices: tuple[int, ...] = None) -> list[OnePiece]:
        pieces = []
        num_blocks_in_piece = ceil(self.torrent_file.info.piece_length / BLOCK_LENGTH)
        for piece_index, sha1_hash in enumerate(self.torrent_file.info.pieces):
            if piece_index < len(self.torrent_file.info.pieces) - 1:
                blocks = [
                    Block(piece_index, block_index * BLOCK_LENGTH, BLOCK_LENGTH)
                    for block_index in range(num_blocks_in_piece)
                ]
            else:
                last_length = (
                    self.torrent_file.info.length % self.torrent_file.info.piece_length
                )
                num_blocks_in_piece = ceil(last_length / BLOCK_LENGTH)
                blocks = [
                    Block(piece_index, block_index * BLOCK_LENGTH, BLOCK_LENGTH)
                    for block_index in range(num_blocks_in_piece)
                ]
                if last_length % BLOCK_LENGTH != 0:
                    blocks[-1].length = last_length % BLOCK_LENGTH
            pieces.append(
                OnePiece(
                    piece_index, self.torrent_file.info.piece_length, blocks, sha1_hash
                )
            )
        if piece_indices:
            for piece_index, piece in enumerate(pieces):
                if piece_index not in piece_indices:
                    for block in piece:
                        block.state = BlockState.RECEIVED
                if piece.is_complete():
                    self.completed_pieces.append(piece)
        return pieces

    def update_pieces_from_peer(self, peer: Peer, bitfield: bytes) -> None:
        pieces_available = set()
        for index, byte in enumerate(bitfield):
            for bit in range(8):
                if byte & (1 << (7 - bit)):
                    pieces_available.add(self.pieces[index * 8 + bit])
        self._peer_to_pieces_registry[peer] |= pieces_available
        for piece in pieces_available:
            self._peer_to_pieces_registry[peer].add(piece)

    def add_piece_index_for_peer(self, peer: Peer, piece_index: int) -> None:
        piece = self.pieces[piece_index]
        self._peer_to_pieces_registry[peer].add(piece)
        self._peer_to_pieces_registry[peer].add(piece)

    def download_completed(self) -> bool:
        return all(piece.is_complete() for piece in self.pieces)

    @property
    def bytes_downloaded(self) -> int:
        return sum(piece.length for piece in self.pieces if piece.is_complete())

    @property
    def bytes_uploaded(self) -> int:
        return 0

    def get_next_request(self, peer: Peer) -> Optional[Block]:
        if peer not in self._peer_to_pieces_registry:
            log(f"Peer {peer} not managed by this piece manager")
            return None
        if expired_request := self._expired_requests(peer):
            return expired_request
        block = self._downloading_pieces(peer)
        if not block:
            block = self._next_rarest(peer).get_next_pending_block()
        if block:
            self.pending_block_requests[peer][block.offset] = PendingBlockRequest(
                block=block, max_pending_time_ns=self.max_pending_time_ns
            )
        return block

    def block_received(self, peer: Peer, piece_message: Piece) -> None:
        # remove from pending requests queue
        self.pending_block_requests[peer].pop(piece_message.begin)
        self.block_queue.put_nowait((peer, piece_message))

    def _expired_requests(self, peer) -> Optional[Block]:
        for pending_block_request in self.pending_block_requests[peer].values():
            if pending_block_request.is_expired():
                log(
                    "Re-requesting block {block} for "
                    "piece {piece}".format(
                        block=pending_block_request.block.offset,
                        piece=pending_block_request.block.index,
                    )
                )
                # Reset expiration timer
                pending_block_request.start_time_ns = time.monotonic_ns()
                return pending_block_request.block
        return None

    def _downloading_pieces(self, peer: Peer) -> Optional[Block]:
        for piece in self._peer_to_pieces_registry[peer]:
            if piece.has_missing_blocks():
                next_pending_block = piece.get_next_pending_block()
                return next_pending_block
        return None

    def _next_rarest(self, peer: Peer) -> Optional[OnePiece]:
        rarest_piece = None
        for piece in self._peer_to_pieces_registry[peer]:
            if rarest_piece is None or len(self._piece_to_peers_registry[piece]) < len(
                self._piece_to_peers_registry[rarest_piece]
            ):
                rarest_piece = piece
        return rarest_piece

    async def save_block(self):
        # async with tqdm(total=self.torrent_file.info.length) as t:
        while not self.abort:
            peer, piece_message = await self.block_queue.get()
            log(
                f"[{piece_message.index}/{len(self.pieces)}]:"
                f"[{piece_message.begin // BLOCK_LENGTH}/{len(self.pieces[piece_message.index])}]"
            )
            # await t.update(piece_message.block_length())

            # update piece
            piece = self.pieces[piece_message.index]
            piece[piece_message.begin // BLOCK_LENGTH].state = BlockState.RECEIVED
            piece[piece_message.begin // BLOCK_LENGTH].data = piece_message.block

            if piece.is_complete():
                log(f"Piece {piece_message.index} completed")
                # get expected sha1 hash of piece
                piece_hash = self.torrent_file.info.pieces[piece_message.index]

                # get actual sha1 hash of piece
                piece_data = piece.get_data()
                actual_piece_data_hash = hashlib.sha1(piece_data)
                if piece_hash.hex() != actual_piece_data_hash.hexdigest():
                    log(f"Piece {piece_message.index} hash mismatch")
                insort(self.completed_pieces, piece, key=lambda p: p.index)


@dataclass(slots=True)
class PeerStreamAsyncIterator:
    reader: StreamReader
    buffer: bytes = b""

    def __aiter__(self):
        return self

    async def __anext__(self):
        while True:
            try:
                data = await self.reader.read(BLOCK_LENGTH)
                if data:
                    self.buffer += data
                    message = self._parse_peer_message()
                    if message:
                        return message
                else:
                    log("No data received from peer")
                    if self.buffer:
                        message = self._parse_peer_message()
                        if message:
                            return message
                    raise StopAsyncIteration
            except ConnectionResetError:
                log("Connection closed by peer")
                raise StopAsyncIteration()
            except CancelledError:
                raise StopAsyncIteration()
            except StopAsyncIteration as e:
                raise e
            except Exception:
                log("Error when iterating over stream!")
                raise StopAsyncIteration()

    def _parse_peer_message(self) -> Optional[PeerMessage]:
        def consume(num_bytes: int) -> bytes:
            result = self.buffer[: num_bytes + PEER_MESSAGE_LENGTH_SIZE]
            self.buffer = self.buffer[num_bytes + PEER_MESSAGE_LENGTH_SIZE :]
            return result

        if len(self.buffer) >= PEER_MESSAGE_LENGTH_SIZE:
            message_length = int.from_bytes(
                self.buffer[:PEER_MESSAGE_LENGTH_SIZE], "big"
            )
            if message_length == 0:
                consume(message_length)
                return KeepAlive.get()
            if len(self.buffer) >= message_length:
                message_id = int.from_bytes(
                    self.buffer[
                        PEER_MESSAGE_LENGTH_SIZE : PEER_MESSAGE_LENGTH_SIZE + 1
                    ],
                    "big",
                )
                match message_id:
                    case Interested.id:
                        consume(message_length)
                        return Interested.get()
                    case Choke.id:
                        consume(message_length)
                        return Choke.get()
                    case Unchoke.id:
                        consume(message_length)
                        return Unchoke.get()
                    case NotInterested.id:
                        consume(message_length)
                        return NotInterested.get()
                    case Have.id:
                        return Have.decode(consume(message_length))
                    case BitField.id:
                        return BitField.decode(consume(message_length))
                    case Request.id:
                        return Request.decode(consume(message_length))
                    case Piece.id:
                        return Piece.decode(consume(message_length))
                    case Cancel.id:
                        return Cancel.decode(consume(message_length))
                    case Port.id:
                        return Port.decode(consume(message_length))
                    case _:
                        raise ValueError(f"Invalid message id {message_id}")


class PeerConnectionState(IntFlag):
    INTERESTED = 0b1
    CHOKED = 0b10
    COMPLETED = 0b100
    STOPPED = 0b1000
    PENDING_REQUEST = 0b10000
    INITIALIZED = 0b100000


class PeerConnection:
    def __init__(
        self,
        torrent: Torrent,
        available_peers: asyncio.Queue[Peer],
        piece_manager: PieceManager,
    ):
        self.torrent = torrent
        self.available_peers = available_peers
        self.piece_manager = piece_manager
        self.state = PeerConnectionState.INITIALIZED
        self.future = asyncio.ensure_future(self.connect())

    async def _handshake(self, peer):
        log(f"Connecting to peer {peer}")
        server_ip, server_port = peer.ip, peer.port

        reader, writer = await asyncio.open_connection(str(server_ip), server_port)
        handshake = HandShake(
            peer_id=PEER_ID, info_hash=self.torrent.info.compute_info_hash().digest()
        )
        writer.write(handshake.pack())
        await writer.drain()

        buffer = await reader.read(68)

        # ensure the handshake is valid
        peer_handshake = HandShake.decode(buffer)
        if peer_handshake.info_hash != handshake.info_hash:
            raise ValueError("Peer sent invalid info hash")

        log(f"Handshake successful with peer {server_ip}:{server_port}")
        self.state |= PeerConnectionState.CHOKED
        return reader, writer

    async def _send_interested(self, peer: Peer, writer: StreamWriter):
        writer.write(Interested.pack())
        await writer.drain()

        log(f"Sent interested to peer {peer}")
        self.state |= PeerConnectionState.INTERESTED

    async def connect(self):
        while PeerConnectionState.STOPPED not in self.state:
            peer = await self.available_peers.get()
            reader, writer = await self._handshake(peer)
            await self._send_interested(peer, writer)
            await self._download(peer, writer, reader)

    def has_pending_request(self):
        return self.state & PeerConnectionState.PENDING_REQUEST

    def clear_pending_request(self):
        self.state &= ~PeerConnectionState.PENDING_REQUEST

    def is_interested_and_not_choked(self):
        return (
            self.state & PeerConnectionState.INTERESTED
            and not self.state & PeerConnectionState.CHOKED
        )

    async def _download(self, peer: Peer, writer: StreamWriter, reader: StreamReader):
        try:
            async for message in PeerStreamAsyncIterator(reader, b""):
                match message:
                    case Choke():
                        log(f"Peer {peer} choked us")
                        self.state |= PeerConnectionState.CHOKED
                    case Unchoke():
                        log(f"Peer {peer} unchoked us")
                        self.state &= ~PeerConnectionState.CHOKED
                    case Interested():
                        log("Peer is interested")
                    case NotInterested():
                        log("Peer is not interested")
                    case Have(piece_index=piece_index):
                        log(f"Peer has piece {piece_index}")
                        self.piece_manager.add_piece_index_for_peer(peer, piece_index)
                    case BitField(bitfield=bitfield):
                        self.piece_manager.update_pieces_from_peer(peer, bitfield)
                    case Request(index=piece_index):
                        log(f"Peer requested piece {piece_index}")
                    case Piece() as piece_message:
                        self.clear_pending_request()
                        self.piece_manager.block_received(peer, piece_message)
                    case Cancel():
                        log(f"Add cancel logic for {message}")
                    case Port():
                        log(f"Add port logic for {message}")
                    case _:
                        log(f"Peer sent unknown message {message}")

                if self.has_pending_request():
                    log(f"Peer {peer} has a pending request")
                    continue

                if self.is_interested_and_not_choked():
                    await self._request_piece(peer, writer)
                else:
                    log(f"Peer {peer} is not interested or choked")
                    continue

        except Exception as e:
            log(traceback.format_exc())
            log(f"Failed to connect to {peer} with exception {e}")

    async def _request_piece(self, peer: Peer, writer: StreamWriter):
        next_piece = self.piece_manager.get_next_request(peer)
        if next_piece:
            next_piece.state = BlockState.PENDING
            message = Request(
                index=next_piece.index,
                begin=next_piece.offset,
                length=next_piece.length,
            ).pack()
            writer.write(message)
            self.state |= PeerConnectionState.PENDING_REQUEST
            await writer.drain()

    def close(self):
        self.state |= PeerConnectionState.STOPPED
        if not self.future.done():
            self.future.cancel()


class Client:
    def __init__(self, *, file_content: bytes, max_peer_connections: int = 50):
        self.max_peer_connections = max_peer_connections
        self.torrent = Torrent.from_file_content(file_content)
        self.available_peers: asyncio.Queue[Peer] = asyncio.Queue()
        self.peer_connections: list[PeerConnection] = []
        self.abort = False
        self.piece_manager: PieceManager | None = None

    @staticmethod
    async def perform_handshake(peer: Peer, info_hash) -> HandShake:
        server_ip, server_port = peer.ip, peer.port
        reader, writer = await asyncio.open_connection(str(server_ip), server_port)
        handshake = HandShake(peer_id=PEER_ID, info_hash=info_hash.digest())
        writer.write(handshake.pack())
        await writer.drain()

        buffer = await reader.read(68)

        # ensure the handshake is valid
        peer_handshake = HandShake.decode(buffer)
        if peer_handshake.info_hash != handshake.info_hash:
            raise ValueError("Peer sent invalid info hash")
        return peer_handshake

    def stop(self):
        self.abort = True
        for peer_connection in self.peer_connections:
            peer_connection.close()
        self.piece_manager.close()

    def get_downloaded_data(self) -> bytes:
        assert self.piece_manager.download_completed()
        return b"".join(
            piece.get_data()
            for piece in sorted(
                self.piece_manager.completed_pieces, key=lambda piece: piece.index
            )
        )

    def get_torrent(self) -> Torrent:
        return self.torrent

    async def start(self, piece_indices: tuple[int, ...] = None):
        self.piece_manager = PieceManager(self.torrent, piece_indices=piece_indices)
        self.peer_connections = [
            PeerConnection(self.torrent, self.available_peers, self.piece_manager)
            for _ in range(self.max_peer_connections)
        ]

        # The time we last made an announce call (timestamp)
        previous = None
        # Default interval between announce calls (in seconds)
        interval = 30 * 60

        while True:
            if self.piece_manager.download_completed():
                log(f"{self.torrent.info.name} fully downloaded!")
                break
            if self.abort:
                log("Aborting download...")
                break

            current = time.monotonic()
            if (not previous) or (previous + interval < current):
                response = await self.torrent.discover_peers(
                    first=previous if previous else False,
                    uploaded=self.piece_manager.bytes_uploaded,
                    downloaded=self.piece_manager.bytes_downloaded,
                )

                if response:
                    previous = current
                    interval = response.interval
                    self._empty_queue()
                    for peer in response.peers:
                        log(f"Adding peer {peer} to queue")
                        self.available_peers.put_nowait(peer)
            else:
                await asyncio.sleep(0)
        self.stop()
        return self.piece_manager.completed_pieces

    def _empty_queue(self):
        while not self.available_peers.empty():
            self.available_peers.get_nowait()
