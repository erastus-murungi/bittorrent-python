from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import Literal, ClassVar, TypedDict, NotRequired

from app.bencode import BEncodedDictionary


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
    peer_id: str

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


@dataclass(slots=True)
class Peer:
    ip: IPv4Address | IPv6Address
    port: int

    NUM_BYTES_IN_PEER: ClassVar[int] = 6
    NUM_BYTES_IN_IP: ClassVar[int] = 4
    NUM_BYTES_IN_PORT: ClassVar[int] = 2


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


@dataclass(slots=True)
class TorrentFile:
    # The URL of the tracker.
    announce: str
    # The info of the torrent
    info: Info
    # The original dictionary, for debugging and idempotency purposes
    dict_: BEncodedDictionary
