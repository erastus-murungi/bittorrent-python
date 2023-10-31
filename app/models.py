from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Literal, ClassVar, TypedDict, NotRequired
from urllib.parse import urlencode

import aiohttp

from app.bencode import BEncodedDictionary, Info, bencode_decode
from app.constants import PEER_ID
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


@dataclass(slots=True)
class Torrent:
    # The URL of the tracker.
    announce: str
    # The info of the torrent
    info: Info
    # The original dictionary, for debugging and idempotency purposes
    dict_: BEncodedDictionary

    async def get_peers(self) -> list[Peer]:
        pass

    def _get_tracker_request_params(
        self, first: bool = False, uploaded: int = 0, downloaded: int = 0
    ) -> TrackerGetRequestParams:
        req_params = {
            "info_hash": self.info.info_hash().digest(),
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
                    self._get_tracker_request_params(first, uploaded, downloaded)
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
                check_state("interval" in tracker_info, "No interval in response")
                check_state("peers" in tracker_info, "No peers in response")

                interval = tracker_info["interval"]
                check_state(interval > 0, "Interval is not a positive integer")
                peer_str = tracker_info["peers"]
                check_state(
                    len(peer_str) % Peer.NUM_BYTES_IN_PEER == 0,
                    f"Peers length is not a multiple of {Peer.NUM_BYTES_IN_PEER}",
                )

                peers = []
                for i in range(0, len(peer_str), Peer.NUM_BYTES_IN_PEER):
                    peer_info = peer_str[i : i + Peer.NUM_BYTES_IN_PEER]
                    peer_ip = ip_address(peer_info[: Peer.NUM_BYTES_IN_IP])
                    peer_port = int.from_bytes(
                        peer_info[Peer.NUM_BYTES_IN_IP :], "big", signed=False
                    )
                    peers.append(Peer(peer_ip, peer_port))

                return TrackerGetResponse(
                    interval=interval,
                    complete=tracker_info["complete"],
                    incomplete=tracker_info["incomplete"],
                    peers=peers,
                    dict_=tracker_info,
                )
