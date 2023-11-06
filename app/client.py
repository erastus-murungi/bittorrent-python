import asyncio
import hashlib
import time
import traceback
from abc import ABC, abstractmethod
from asyncio import StreamReader, StreamWriter
from collections import defaultdict
from enum import IntFlag
from ipaddress import IPv4Address, IPv6Address
from typing import Optional

from math import ceil

from app.constants import (
    BLOCK_LENGTH,
    PEER_ID,
    DEFAULT_MAX_PENDING_TIME_MS,
    HANDSHAKE_BUFFER_SIZE,
    DEFAULT_SLEEP_SECONDS_BEFORE_CALLING_TRACKER,
)
from app.content import Block, Piece, PiecesRegistry, BlockState
from app.messages import (
    Interested,
    Choke,
    Unchoke,
    NotInterested,
    Have,
    BitField,
    Request,
    Piece as PiecePeerMessage,
    Cancel,
    Port,
    HandShake,
    PeerStreamAsyncIterator,
)
from app.progress_manager import ProgressManager
from app.torrent import Peer, Torrent
from app.utils import log, Heap

IPAddress = IPv4Address | IPv6Address


class PendingRequestsRegistry(defaultdict[Peer, Heap[Block]]):
    def __init__(
        self,
        max_pending_time_ns,
        received_blocks_queue: asyncio.Queue[tuple[Peer, PiecePeerMessage]]
        | None = None,
    ):
        super().__init__(Heap)
        self.received_blocks_queue = received_blocks_queue or asyncio.Queue()
        self.max_pending_time_ns = max_pending_time_ns

    def on_block_received(
        self, peer: Peer, peer_message: PiecePeerMessage, block: Block
    ):
        self[peer].delete(block)
        self.received_blocks_queue.put_nowait((peer, peer_message))

    def is_expired(self, pending_request: tuple[float, Block]) -> bool:
        start_time_ns, _ = pending_request
        return start_time_ns + self.max_pending_time_ns < time.monotonic_ns()

    def add_pending_request(self, peer: Peer, block: Block):
        self[peer].enqueue(block, priority=time.monotonic_ns())

    def get_earliest_expired_request(self, peer: Peer):
        pending_requests = self[peer]
        if pending_requests:
            pending_request = pending_requests.dequeue()
            if self.is_expired(pending_request):
                return pending_request
        return None


class PieceDownloadStrategy(ABC):
    def __init__(self, piece_registry: PiecesRegistry):
        self.pieces: PiecesRegistry = piece_registry

    @abstractmethod
    def get_next_block_to_request(self, peer: Peer) -> Optional[Block]:
        pass


class RarestPieceStrategy(PieceDownloadStrategy):
    def __init__(
        self,
        piece_registry: PiecesRegistry,
        pending_requests_registry: PendingRequestsRegistry,
    ):
        super().__init__(piece_registry)
        self.pending_requests = pending_requests_registry

    def compute_next_pending_block_of_first_ongoing_piece(
        self, peer: Peer
    ) -> Optional[Block]:
        for piece in self.pieces.get_by_peer(peer):
            if piece.has_missing_blocks():
                return piece.get_next_pending_block()
        return None

    def get_next_block_to_request(self, peer: Peer) -> Optional[Block]:
        if not self.pieces.contains_peer(peer):
            log(f"Peer {peer} not managed by this piece manager")
            return None
        if expired_request := self.pending_requests.get_earliest_expired_request(peer):
            _, block = expired_request
            return block
        if block := self.compute_next_pending_block_of_first_ongoing_piece(peer):
            return block
        return self.compute_next_pending_block_of_rarest_piece(peer)

    def compute_next_pending_block_of_rarest_piece(self, peer: Peer) -> Optional[Block]:
        rarest_piece = None
        for piece in self.pieces.get_by_peer(peer):
            if rarest_piece is None or len(
                self.pieces.get_peers_with_piece(piece)
            ) < len(self.pieces.get_peers_with_piece(rarest_piece)):
                rarest_piece = piece
        return rarest_piece and rarest_piece.get_next_pending_block()


class PieceManager:
    def __init__(
        self,
        torrent_file: Torrent,
        *,
        max_pending_time_ms: int = DEFAULT_MAX_PENDING_TIME_MS,
        piece_indices: tuple[int, ...] | None = None,
        piece_download_strategy: PieceDownloadStrategy | None = None,
    ):
        self.torrent_file = torrent_file
        self.piece_indices = piece_indices
        self.abort = False
        self.pending_block_requests: PendingRequestsRegistry = PendingRequestsRegistry(
            max_pending_time_ms * 1_000_000
        )
        self.completed_pieces: list[Piece] = []
        self.pieces: PiecesRegistry = self._init_pieces()
        self.piece_download_strategy: PieceDownloadStrategy = (
            piece_download_strategy
            or RarestPieceStrategy(self.pieces, self.pending_block_requests)
        )
        self.progress_manager = ProgressManager(torrent_file.info)
        self.future = asyncio.ensure_future(self.save_block())

    def get_next_block_to_request(self, peer: Peer):
        return self.piece_download_strategy.get_next_block_to_request(peer)

    def close(self):
        self.abort = True

    def _init_pieces(self) -> PiecesRegistry:
        info = self.torrent_file.info
        pieces = PiecesRegistry()
        num_blocks_in_piece = ceil(info.piece_length / BLOCK_LENGTH)
        for piece_index, sha1_hash in enumerate(info.pieces):
            if piece_index < len(info.pieces) - 1:
                blocks = [
                    Block(piece_index, block_index * BLOCK_LENGTH, BLOCK_LENGTH)
                    for block_index in range(num_blocks_in_piece)
                ]
            else:
                last_length = info.length % info.piece_length
                num_blocks_in_piece = ceil(last_length / BLOCK_LENGTH)
                blocks = [
                    Block(piece_index, block_index * BLOCK_LENGTH, BLOCK_LENGTH)
                    for block_index in range(num_blocks_in_piece)
                ]
                if last_length % BLOCK_LENGTH != 0:
                    blocks[-1].length = last_length % BLOCK_LENGTH
            pieces.append(Piece(piece_index, info.piece_length, blocks, sha1_hash))
        if self.piece_indices:
            for piece_index, piece in enumerate(pieces):
                if piece_index not in self.piece_indices:
                    for block in piece:
                        block.state = BlockState.RECEIVED
                if piece.is_complete():
                    self.completed_pieces.append(piece)
        return pieces

    def update_pieces_from_peer(self, peer: Peer, bitfield: bytes) -> None:
        self.pieces.update_pieces_from_peer(peer, bitfield)

    def add_piece_index_for_peer(self, peer: Peer, piece_index: int) -> None:
        self.pieces.add_piece_index_for_peer(peer, piece_index)

    def download_completed(self) -> bool:
        return all(piece.is_complete() for piece in self.pieces)

    @property
    def bytes_downloaded(self) -> int:
        return sum(piece.length for piece in self.pieces if piece.is_complete())

    @property
    def bytes_uploaded(self) -> int:
        return 0

    def block_received(self, peer: Peer, piece_message: PiecePeerMessage) -> None:
        # remove from pending requests queue
        block = self.pieces[piece_message.index][piece_message.begin // BLOCK_LENGTH]
        self.pending_block_requests.on_block_received(peer, piece_message, block)

    def get_peers(self):
        return self.pieces.get_peers()

    async def save_block(self):
        # async with tqdm(total=self.torrent_file.info.length) as t:
        while not self.abort:
            (
                peer,
                piece_message,
            ) = await self.pending_block_requests.received_blocks_queue.get()
            log(
                f"[{piece_message.index + 1}/{len(self.pieces)}]:"
                f"[{(piece_message.begin // BLOCK_LENGTH) + 1}/{len(self.pieces[piece_message.index])}]"
            )
            # await t.update(piece_message.block_length())

            # update piece
            piece = self.pieces[piece_message.index]
            piece[piece_message.begin // BLOCK_LENGTH].state = BlockState.RECEIVED
            piece[piece_message.begin // BLOCK_LENGTH].data = piece_message.block

            if piece.is_complete():
                log(f"Piece {piece.index + 1} completed")
                # get expected sha1 hash of piece
                piece_hash = self.torrent_file.info.pieces[piece.index]

                # get actual sha1 hash of piece
                piece_data = piece.get_data()
                actual_piece_data_hash = hashlib.sha1(piece_data)
                if piece_hash.hex() != actual_piece_data_hash.hexdigest():
                    log(f"Piece {piece.index} hash mismatch")
                self.progress_manager.received_pieces.put_nowait(piece)


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

    async def _handshake(self, peer: Peer) -> tuple[StreamReader, StreamWriter]:
        log(f"Connecting to peer {peer}")
        server_ip, server_port = peer.ip, peer.port

        reader, writer = await asyncio.open_connection(str(server_ip), server_port)
        handshake = HandShake(
            peer_id=PEER_ID, info_hash=self.torrent.info.compute_info_hash().digest()
        )
        writer.write(handshake.pack())
        await writer.drain()

        buffer = await reader.read(HANDSHAKE_BUFFER_SIZE)

        # ensure the handshake is valid
        peer_handshake = HandShake.decode(buffer)
        if peer_handshake.info_hash != handshake.info_hash:
            # TODO: ignore and/or retry the peer up to a number of times
            raise ValueError(
                f"The info hash from the peer {peer} does not match the expected info hash"
            )
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
                    case PiecePeerMessage() as piece_message:
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
        next_block = self.piece_manager.get_next_block_to_request(peer)
        if next_block:
            next_block.state = BlockState.PENDING
            message = Request(
                index=next_block.index,
                begin=next_block.offset,
                length=next_block.length,
            ).pack()
            writer.write(message)
            self.piece_manager.pending_block_requests.add_pending_request(
                peer, next_block
            )
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

        buffer = await reader.read(HANDSHAKE_BUFFER_SIZE)

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
                    previous, interval = current, response.interval
                    self._empty_queue()
                    for peer in response.peers:
                        log(f"Adding peer {peer} to queue")
                        self.available_peers.put_nowait(peer)
            else:
                await asyncio.sleep(DEFAULT_SLEEP_SECONDS_BEFORE_CALLING_TRACKER)
        self.stop()
        return self.piece_manager.completed_pieces

    def _empty_queue(self):
        while not self.available_peers.empty():
            self.available_peers.get_nowait()
