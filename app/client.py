import asyncio
import hashlib
import signal
import sys
import time
import traceback
from abc import ABC, abstractmethod
from asyncio import StreamReader, StreamWriter
from bisect import insort
from collections import defaultdict
from enum import IntFlag
from ipaddress import IPv4Address, IPv6Address
from itertools import cycle
from typing import Optional, TextIO

import resource
from humanfriendly import format_timespan, format_size
from math import ceil
from more_itertools import quantify
from termcolor import colored

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
from app.peer_discovery import discover_peers
from app.torrent import Peer, Torrent
from app.utils import log, Heap

IPAddress = IPv4Address | IPv6Address

ANSI_ERASE_CURRENT_LINE = "\u001b[2K"
ANSI_MOVE_CURSOR_UP_ONE_LINE = "\x1b[1A"
ANSI_HIDE_CURSOR = "\x1b[?25l"
ANSI_SHOW_CURSOR = "\x1b[?25h"

PROGRESS_SPINNER_SEQUENCE = cycle("◐ ◓ ◑ ◒".split())

COMPLETED_JOBS_REFRESH_TIME = 3
FRAMES_PER_CYCLE = 1.0 / 10.0

MAX_NUMBER_CHARACTERS_HEADER_PROGRESS_BAR = 30

INDENT = "    "
DOTS = "...." * 5


def get_green_bold_colored(text: str) -> str:
    return colored(f"{text}", "green", attrs=["bold"])


class File:
    def __init__(self, file_path: str, file_size: int):
        self.file_path = file_path
        self.file_size = file_size
        self.start_time: float | None = None
        self.finish_time: float | None = None
        self.downloaded: list[Piece] = []
        self.downloaded_size: int = 0
        self.queue = asyncio.Queue[Piece]()
        self.future = asyncio.ensure_future(self.start())

    @property
    def is_completed(self) -> bool:
        return self.downloaded_size == self.file_size

    def start_progress(self):
        self.start_time = time.monotonic()

    @property
    def is_not_completed(self):
        return not self.is_completed

    async def start(self):
        while self.is_not_completed:
            piece = await self.queue.get()
            insort(self.downloaded, piece, key=lambda p: p.index)
            self.downloaded_size += len(piece.get_data())
        self.finish_time = time.monotonic()

    def cleanup(self):
        if self.future:
            self.future.cancel()

    def get_progress_item_title(self) -> str:
        """
        Return a title to display

        """
        return f"{self.file_path}"

    def get_normalized_progress(self) -> float:
        """
        Returns the progress of this time with 1 being complete

        :return: The progress from 0 to 1
        """
        if self.file_size is None:
            return 0.0
        progress = self.downloaded_size / self.file_size
        return min(progress, 1.0)

    def get_percentage_progress(self) -> float:
        return self.get_normalized_progress() * 100

    def pretty_print_progress(self, text_io: TextIO = sys.stdout) -> None:
        progress_item_title = colored(self.get_progress_item_title(), "white")
        progress_spinner_code_point = next(PROGRESS_SPINNER_SEQUENCE)
        if self.is_completed:
            # we define done_str because f-strings do not allow `\`
            done_str = "\u2714"
            text_io.write(
                f"{INDENT}{get_green_bold_colored(done_str)} {progress_item_title} {DOTS} finished in "
                f"{format_timespan(self.finish_time - self.start_time)}\n"
            )
        else:
            text_io.write(
                f"{INDENT}{progress_spinner_code_point} {progress_item_title} {DOTS} "
                f"{format_timespan(time.monotonic() - self.start_time)}    ({self.get_percentage_progress():04.2f} %)\n"
            )


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

    async def on_block_received(
        self, peer: Peer, piece_message: PiecePeerMessage, block: Block, piece: Piece
    ):
        self[peer].delete(block)
        # update piece
        piece[piece_message.begin // BLOCK_LENGTH].state = BlockState.RECEIVED
        piece[piece_message.begin // BLOCK_LENGTH].data = piece_message.block

        if piece.is_complete():
            log(f"Piece {piece.index + 1} completed")
            # get expected sha1 hash of piece
            piece_hash = piece.sha1_hash
            # get actual sha1 hash of piece
            piece_data = piece.get_data()
            actual_piece_data_hash = hashlib.sha1(piece_data)
            if piece_hash.hex() != actual_piece_data_hash.hexdigest():
                log(f"Piece {piece.index} hash mismatch")
            return True
        else:
            return False

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
        progress_bar_header_title: str = "Downloading",
        text_io: TextIO = sys.stdout,
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
        self.start_time: Optional[float] = None
        self.files: tuple[File, ...] = tuple(
            map(
                lambda file_info: File(
                    file_path=file_info["path"], file_size=file_info["length"]
                ),
                torrent_file.info.get_files(),
            )
        )
        self.header_print_state: tuple[int, int, int] = (
            0,
            MAX_NUMBER_CHARACTERS_HEADER_PROGRESS_BAR,
            0,
        )
        self.progress_bar_header_title = progress_bar_header_title
        self.downloading_files = self.files
        self.abort = False
        self.received_pieces: asyncio.Queue[Piece] = asyncio.Queue()
        self.future = asyncio.ensure_future(self.start(text_io))

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
                last_length = info.get_total_size % info.piece_length
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
    def bytes_uploaded(self) -> int:
        return 0

    async def block_received(self, peer: Peer, piece_message: PiecePeerMessage) -> None:
        # remove from pending requests queue
        piece = self.pieces[piece_message.index]
        block = piece[piece_message.begin // BLOCK_LENGTH]

        log(
            f"[{piece_message.index + 1}/{len(self.pieces)}]:"
            f"[{(piece_message.begin // BLOCK_LENGTH) + 1}/{len(piece)}]"
        )

        piece_completed = await self.pending_block_requests.on_block_received(
            peer, piece_message, block, piece
        )
        if piece_completed:
            await self.update_correct_file(piece)

    def get_peers(self):
        return self.pieces.get_peers()

    @staticmethod
    def delete_ascii_terminal_line(text_io: TextIO = sys.stdout):
        text_io.write(ANSI_ERASE_CURRENT_LINE + "\r" + ANSI_MOVE_CURSOR_UP_ONE_LINE)

    def update_header_print_state(self):
        n_jobs_completed = quantify(self.files, lambda p: p.is_completed)
        n_filled = ceil(
            n_jobs_completed
            / len(self.files)
            * MAX_NUMBER_CHARACTERS_HEADER_PROGRESS_BAR
        )
        n_left = MAX_NUMBER_CHARACTERS_HEADER_PROGRESS_BAR - n_filled
        self.header_print_state = (n_filled, n_left, n_jobs_completed)

    def downloading_speed(self):
        return self.downloaded_size() / (time.monotonic() - self.start_time)

    def downloaded_size(self):
        return sum(downloading_file.downloaded_size for downloading_file in self.files)

    def total_size(self):
        return sum(downloading_file.file_size for downloading_file in self.files)

    def pretty_print_progress_bar_header(self, text_io: TextIO):
        n_filled, n_left, n_jobs_completed = self.header_print_state
        text_io.write(
            f"\r{INDENT}{get_green_bold_colored(self.progress_bar_header_title)}  "
            f'[{"=" * (n_filled - 1) + ">"}{" " * n_left}] '
            f"[{self.downloaded_size()} / {self.total_size()} downloaded] ... "
            f"{format_timespan(time.monotonic() - self.start_time, detailed=False)} "
            f"[{format_size(self.downloading_speed())} / sec]\n"
        )

    def initialize_all_progress_items(self):
        for progress_item in self.files:
            progress_item.start_progress()

    def cleanup_all_progress_items(self):
        for progress_item in self.files:
            if not progress_item.is_completed:
                raise RuntimeError(f"{progress_item} is not completed")
        for progress_item in self.files:
            progress_item.cleanup()

    def cleanup(self):
        self.abort = True
        if self.future:
            self.future.cancel()

    async def pretty_print_all_progress_items(
        self,
        text_io: TextIO = sys.stdout,
    ):
        progress_items = tuple(
            sorted(
                self.downloading_files,
                key=lambda p: p.get_normalized_progress(),
                reverse=True,
            )
        )
        for progress_item in progress_items:
            progress_item.pretty_print_progress()
        await asyncio.sleep(FRAMES_PER_CYCLE)
        for _ in range(len(progress_items)):
            self.delete_ascii_terminal_line()
        text_io.write("\r")
        text_io.write(ANSI_ERASE_CURRENT_LINE)

    def get_incomplete_progress_items_state(
        self,
    ) -> tuple[tuple[File, ...], float]:
        return (
            tuple(filter(lambda p: p.is_not_completed, self.downloading_files)),
            time.monotonic(),
        )

    async def update_correct_file(self, piece: Piece):
        await self.files[0].queue.put(piece)

    async def start(self, text_io: TextIO):
        self.start_time = time.monotonic()
        self.initialize_all_progress_items()

        (
            self.downloading_files,
            incomplete_progress_items_update_time,
        ) = self.get_incomplete_progress_items_state()
        while self.downloading_files:
            text_io.write(ANSI_HIDE_CURSOR)

            while (
                time.monotonic() - incomplete_progress_items_update_time
                < COMPLETED_JOBS_REFRESH_TIME
            ):
                self.pretty_print_progress_bar_header(text_io)
                await self.pretty_print_all_progress_items(text_io)
                self.delete_ascii_terminal_line()
                self.update_header_print_state()

            piece = await self.received_pieces.get()
            await self.update_correct_file(piece)
            (
                self.downloading_files,
                incomplete_progress_items_update_time,
            ) = self.get_incomplete_progress_items_state()
        text_io.write(ANSI_ERASE_CURRENT_LINE)
        text_io.write("\r")
        self.cleanup_all_progress_items()
        rusage = resource.getrusage(resource.RUSAGE_SELF)
        text_io.write(
            f"Finished successfully\n"
            f"     Time ─────────────────────── {format_timespan(time.monotonic() - self.start_time)}\n"
            f"     Peak RAM use ─────────────── {format_size(rusage.ru_maxrss)}\n"
        )
        sys.stdout.write(ANSI_SHOW_CURSOR)


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
                        await self.piece_manager.block_received(peer, piece_message)
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
        _bytes = []
        for _file in self.piece_manager.files:
            for _piece in _file.downloaded:
                _bytes.append(_piece.get_data())
        return b"".join(_bytes)

    async def start(
        self, piece_indices: tuple[int, ...] = None, text_io: TextIO = sys.stdout
    ):
        self.piece_manager = PieceManager(
            self.torrent, piece_indices=piece_indices, text_io=text_io
        )
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
                text_io.write(ANSI_ERASE_CURRENT_LINE)
                text_io.write("\r")
                self.piece_manager.cleanup_all_progress_items()
                rusage = resource.getrusage(resource.RUSAGE_SELF)
                text_io.write(
                    f"Download to {self.torrent.info.get_directory()} successfully\n"
                    f"     Time ───────────────────────"
                    f" {format_timespan(time.monotonic() - self.piece_manager.start_time)}\n"
                    f"     Peak RAM use ─────────────── {format_size(rusage.ru_maxrss)}\n"
                )
                text_io.write(ANSI_SHOW_CURSOR)
                break
            if self.abort:
                log("Aborting download...")
                break

            current = time.monotonic()
            if (not previous) or (previous + interval < current):
                response = await discover_peers(
                    self.torrent,
                    first=previous if previous else False,
                    uploaded=self.piece_manager.bytes_uploaded,
                    downloaded=self.piece_manager.downloaded_size(),
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


def signal_handler(signum, frame):
    sys.stdout.write(ANSI_SHOW_CURSOR)
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    import doctest

    doctest.testmod()
