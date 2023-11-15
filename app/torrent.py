from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from functools import cached_property
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import TypedDict, Literal, NotRequired, ClassVar, Required

from more_itertools import chunked

from app.bencode import BEncodedDictionary, bencode_encode, bencode_decode
from app.constants import SHA1_HASH_LENGTH


@dataclass(slots=True, frozen=True)
class Peer:
    ip: IPv4Address | IPv6Address
    port: int

    NUM_BYTES_IN_PEER: ClassVar[int] = 6
    NUM_BYTES_IN_IP: ClassVar[int] = 4
    NUM_BYTES_IN_PORT: ClassVar[int] = 2

    def __str__(self):
        return f"{self.ip}:{self.port}"


@dataclass(slots=True)
class TrackerGetResponse:
    # The interval in seconds that the client should wait between sending regular requests to the tracker
    interval: int

    # The number of peers with the entire file, i.e. seeders
    complete: int

    # The number of non-seeder peers, aka "leechers"
    incomplete: int

    # A list of peers
    peers: list[Peer]

    dict_: BEncodedDictionary

    def __post_init__(self):
        # validate attributes
        if not isinstance(self.interval, int) or self.interval <= 0:
            raise ValueError("interval must be a positive integer")
        if not isinstance(self.complete, int) or self.complete < 0:
            raise ValueError("complete must be a non-negative integer")
        if not isinstance(self.incomplete, int) or self.incomplete < 0:
            raise ValueError("incomplete must be a non-negative integer")
        if not isinstance(self.peers, list):
            raise ValueError("peers must be a list")
        for peer in self.peers:
            if not isinstance(peer, Peer):
                raise ValueError("peer must be a Peer")


class TrackerGetRequestParams(TypedDict):
    # The 20 byte sha1 hash of the bencoded form of the info value from the metainfo file.
    # This value will almost certainly have to be escaped.
    # Note that this is a substring of the metainfo file.
    # The info-hash must be the hash of the encoded form as found in the .torrent file,
    # which is identical to bdecoding the metainfo file,
    # extracting the info dictionary and encoding it if and only if the bdecoder fully validated the input
    # (e.g. key ordering, absence of leading zeros).
    # Conversely, that means clients must either reject invalid metainfo files or extract the substring directly.
    # They must not perform a decode-encode roundtrip on invalid data.
    info_hash: bytes

    # A string of length 20 which this downloader uses as its id.
    # Each downloader generates its own id at random at the start of a new download.
    # This value will also almost certainly have to be escaped.
    peer_id: bytes

    # The port number this peer is listening on.
    # Common behavior is for a downloader to try to listen on port 6881 and if that port
    # is taken try 6882, then 6883, etc. and give up after 6889.
    port: int

    # The total amount uploaded so far, encoded in base ten ascii.
    uploaded: int

    # The total amount downloaded so far, encoded in base ten ascii.
    downloaded: int

    # The number of bytes this peer still has to download, encoded in base ten ascii.
    # Note that this can't be computed from downloaded and the file length since it might be a resume,
    # and there's a chance that some of the downloaded data failed an integrity check and had to be re-downloaded.
    left: int

    # whether the peer list should use the compact representation
    # should be set to 1 if the client accepts a compact response, or 0 otherwise
    # this implementation has it set to 1 by default
    compact: Literal[1] | Literal[0]

    # An optional parameter giving the IP (or dns name) which this peer is at.
    # Generally used for the origin if it's on the same machine as the tracker.
    ip: NotRequired[IPv4Address | IPv6Address]

    # If specified, must be one of started, completed, stopped, (or empty which is the same as not being specified).
    # If not specified, then this request is one performed at regular intervals.
    #   started: The first request to the tracker must include the event key with this value.
    #   stopped: Must be sent to the tracker if the client is shutting down gracefully.
    #   completed:  Must be sent to the tracker when the download completes.
    #               However, must not be sent if the download was already 100% complete when the client started.
    #               Presumably, this is to allow the tracker to increment
    #               the "completed downloads" metric based solely on this event.
    event: NotRequired[Literal["started", "completed", "stopped"]]


class FileInfo(TypedDict):
    # length of the file in bytes (integer)
    length: Required[int]

    # the path to store the file in
    path: Required[Path]


@dataclass(slots=True, frozen=True)
class Info(ABC):
    # piece length maps to the number of bytes in each piece the file is split into.
    # For the purposes of transfer, files are split into fixed-size pieces which are all the same length
    # except for possibly the last one which may be truncated.
    # piece length is almost always a power of two, most commonly 2 18 = 256 K
    # (BitTorrent prior to version 3.2 uses 2 20 = 1 M as default).
    piece_length: int

    # sha1 hashes of each piece
    pieces: list[bytes]

    # The original dictionary, for debugging and idempotency purposes.
    # This implementation does not implement key ordering checks yet.
    # we use this so that we can be correct when re-encoding the info dictionary
    dict_: BEncodedDictionary

    def compute_info_hash(self):
        info_bytes = bencode_encode(self.dict_)
        return hashlib.sha1(info_bytes)

    @abstractmethod
    def get_directory(self) -> Path:
        raise NotImplemented

    @abstractmethod
    def get_files(self) -> tuple[FileInfo, ...]:
        raise NotImplemented

    @abstractmethod
    @cached_property
    def get_total_size(self) -> int:
        raise NotImplemented


@dataclass(frozen=True)
class SingleFileInfo(Info):
    # The name key maps to a UTF-8 encoded string which is the suggested name
    # to save the file (or directory) as. It is purely advisory.
    name: str

    # size of the file in bytes, for single-file torrents
    length: int

    def get_directory(self):
        return Path(self.name)

    def get_files(self):
        return (FileInfo(length=self.length, path=Path(self.name)),)

    @cached_property
    def get_total_size(self) -> int:
        return self.length


@dataclass(frozen=True)
class MultiFileInfo(Info):
    # the name of the directory in which to store all the files.
    # This is purely advisory. (string)
    name: str

    # files
    files: list[FileInfo]

    def get_directory(self):
        return Path(self.name)

    def get_files(self):
        return self.files

    @cached_property
    def get_total_size(self) -> int:
        return sum(file_info["length"] for file_info in self.files)


@dataclass(slots=True)
class Torrent:
    # The URL of the tracker.
    announce: str
    # The info of the torrent
    info: Info
    # The original dictionary, for debugging and idempotency purposes
    dict_: BEncodedDictionary

    @staticmethod
    def from_file_content(torrent_file_content: bytes) -> Torrent:
        metainfo_dict: BEncodedDictionary = bencode_decode(torrent_file_content)

        announce = metainfo_dict["announce"]
        info = metainfo_dict["info"]
        name = info["name"]
        piece_length = info["piece length"]
        pieces_str = info["pieces"]

        if not isinstance(announce, bytes):
            raise ValueError("announce must be a byte string")
        if not isinstance(name, bytes):
            raise ValueError("name must be a byte string")
        if not isinstance(piece_length, int) or piece_length <= 0:
            raise ValueError("piece length must be a positive integer")
        if not isinstance(pieces_str, bytes) or len(pieces_str) % SHA1_HASH_LENGTH != 0:
            raise ValueError(
                f"pieces must be a byte string with length divisible by {SHA1_HASH_LENGTH}"
            )
        pieces = [bytes(piece) for piece in chunked(pieces_str, SHA1_HASH_LENGTH)]
        if "length" in info:
            length = info["length"]
            if not isinstance(length, int) or length <= 0:
                raise ValueError("length must be a positive integer")
            info = SingleFileInfo(
                name=name.decode(),
                length=length,
                piece_length=piece_length,
                pieces=pieces,
                dict_=metainfo_dict["info"],
            )
            return Torrent(
                announce=announce.decode(),
                info=info,
                dict_=metainfo_dict,
            )
        else:
            if "files" not in info:
                raise ValueError("expected to find either `length` or `files`")
            files = []
            for file_info in info["files"]:
                length = file_info["length"]
                if not isinstance(length, int) or length <= 0:
                    raise ValueError("length must be a positive integer")
                path = Path(
                    *[path_component.decode() for path_component in file_info["path"]]
                )
                files.append(FileInfo(length=length, path=path))
            return Torrent(
                announce=announce.decode(),
                info=MultiFileInfo(
                    name=name.decode(),
                    files=files,
                    piece_length=piece_length,
                    pieces=pieces,
                    dict_=metainfo_dict["info"],
                ),
                dict_=metainfo_dict,
            )

    @staticmethod
    def _extract_and_validate_info_dict_values(metainfo_dict: BEncodedDictionary):
        info = metainfo_dict["info"]
        if "length" in info:
            return {**info, **metainfo_dict["announce"]}
        else:
            if "files" not in info:
                raise ValueError("expected to find either `length` or `files`")
            return {**info, **metainfo_dict["announce"]}

    @staticmethod
    def _validate_info_dict_values(announce, name, piece_length, length, pieces_str):
        if not isinstance(announce, bytes):
            raise ValueError("announce must be a byte string")
        if not isinstance(name, bytes):
            raise ValueError("name must be a byte string")
        if not isinstance(piece_length, int) or piece_length <= 0:
            raise ValueError("piece length must be a positive integer")
        if not isinstance(length, int) or length <= 0:
            raise ValueError("length must be a positive integer")
        if not isinstance(pieces_str, bytes) or len(pieces_str) % SHA1_HASH_LENGTH != 0:
            raise ValueError(
                f"pieces must be a byte string with length divisible by {SHA1_HASH_LENGTH}"
            )
