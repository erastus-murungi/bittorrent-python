from __future__ import annotations

import hashlib
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import TypedDict, Literal, NotRequired, ClassVar
from urllib.parse import urlencode

import aiohttp
from more_itertools import chunked

from app.bencode import BEncodedDictionary, bencode_encode, bencode_decode
from app.constants import PEER_ID, SHA1_HASH_LENGTH


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

    event: NotRequired[Literal["started", "completed", "stopped"]]


@dataclass(slots=True)
class Info:
    # size of the file in bytes, for single-file torrents
    length: int

    # The name key maps to a UTF-8 encoded string which is the suggested name
    # to save the file (or directory) as. It is purely advisory.
    name: str

    # piece length maps to the number of bytes in each piece the file is split into.
    # For the purposes of transfer, files are split into fixed-size pieces which are all the same length
    # except for possibly the last one which may be truncated.
    # piece length is almost always a power of two, most commonly 2 18 = 256 K
    # (BitTorrent prior to version 3.2 uses 2 20 = 1 M as default).
    piece_length: int

    # sha1 hashes of each piece
    pieces: []

    # The original dictionary, for debugging and idempotency purposes.
    # This implementation does not implement key ordering checks yet.
    # we use this so that we can be correct when re-encoding the info dictionary
    dict_: BEncodedDictionary

    def compute_info_hash(self):
        info_bytes = bencode_encode(self.dict_)
        return hashlib.sha1(info_bytes)


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
        (
            announce,
            name,
            piece_length,
            length,
            pieces_str,
        ) = Torrent._extract_info_dict_values(metainfo_dict)

        Torrent._validate_info_dict_values(
            announce, name, piece_length, length, pieces_str
        )

        pieces = [bytes(piece) for piece in chunked(pieces_str, SHA1_HASH_LENGTH)]

        info = Info(
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

    @staticmethod
    def _extract_info_dict_values(metainfo_dict):
        return (
            metainfo_dict["announce"],
            metainfo_dict["info"]["name"],
            metainfo_dict["info"]["piece length"],
            metainfo_dict["info"]["length"],
            metainfo_dict["info"]["pieces"],
        )

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

    def _create_tracker_request_params(
        self, first: bool = False, uploaded: int = 0, downloaded: int = 0
    ) -> TrackerGetRequestParams:
        req_params = {
            "info_hash": self.info.compute_info_hash().digest(),
            "peer_id": PEER_ID,
            "port": 6881,
            "uploaded": uploaded,
            "downloaded": downloaded,
            "left": self.info.length,
            "compact": 1,
        }
        if first:
            req_params["event"] = "started"
        return req_params

    async def discover_peers(
        self, first: bool = False, uploaded: int = 0, downloaded: int = 0
    ) -> TrackerGetResponse:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                self.announce
                + "?"
                + urlencode(
                    self._create_tracker_request_params(first, uploaded, downloaded)
                )
            ) as tracker_response:
                if tracker_response.status != 200:
                    raise ConnectionError(
                        f"Tracker returned status code {tracker_response.status}"
                    )
                tracker_content = await tracker_response.read()
                tracker_info = bencode_decode(tracker_content)
                if "failure reason" in tracker_info:
                    raise ValueError(
                        f'Failure reason: {tracker_info["failure reason"].decode()}'
                    )
                return TrackerGetResponse(
                    interval=tracker_info["interval"],
                    complete=tracker_info["complete"],
                    incomplete=tracker_info["incomplete"],
                    peers=[
                        Peer(
                            ip=ip_address(peer_info[: Peer.NUM_BYTES_IN_IP]),
                            port=int.from_bytes(
                                peer_info[Peer.NUM_BYTES_IN_IP :], "big", signed=False
                            ),
                        )
                        for peer_info in map(
                            bytes,
                            chunked(
                                tracker_info["peers"],
                                Peer.NUM_BYTES_IN_PEER,
                                strict=True,  # we want to raise an error if the last chunk is not the right size
                            ),
                        )
                    ],
                    dict_=tracker_info,
                )
