from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import Literal, ClassVar, TypedDict, NotRequired, Final

from app.bencode import BEncodedDictionary, Info
from app.utils import check_state


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


@dataclass(slots=True)
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

    def to_str(self):
        # handshake: <pstrlen><pstr><reserved><info_hash><peer_id>
        return (
            self.pstrlen.to_bytes(1, "big")
            + self.pstr
            + self.reserved
            + self.info_hash
            + self.peer_id
        )

    @staticmethod
    def parse_from_response(resp: bytes):
        # handshake: <pstrlen><pstr><reserved><info_hash><peer_id>
        return HandShake(
            peer_id=resp[48:68],
            info_hash=resp[28:48],
            reserved=resp[20:28],
            pstr=resp[1:20],
            pstrlen=int.from_bytes(resp[0:1], "big"),
        )
