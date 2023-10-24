from ipaddress import ip_address
from pathlib import Path

import requests

from app.bencode import bencode_decode
from app.models import (
    TorrentFile,
    Info,
    TrackerGetResponse,
    TrackerGetRequestParams,
    Peer,
)
from app.utils import check_state


def parse_torrent(
    torrent_filename: str | bytes,
) -> TorrentFile:
    def get_piece_hashes(pieces_str: bytes):
        piece_hashes = []
        for i in range(0, len(pieces_str), 20):
            piece_hashes.append(pieces_str[i : i + 20])
        return piece_hashes

    torrent_filename = (
        torrent_filename
        if isinstance(torrent_filename, str)
        else torrent_filename.decode()
    )
    metainfo_dict = bencode_decode(Path(torrent_filename).read_bytes())
    # first extract the tracker URL
    announce = metainfo_dict["announce"]
    check_state(isinstance(announce, bytes), "announce must be a byte string")
    # then extract the info dictionary
    info_dict = metainfo_dict["info"]
    name = info_dict["name"]
    check_state(isinstance(name, bytes), "name must be a byte string")
    # then extract the piece length
    piece_length = info_dict["piece length"]
    check_state(
        isinstance(piece_length, int) and piece_length > 0,
        "piece length must be a positive integer",
    )
    # then extract the pieces
    check_state(
        isinstance(info_dict["pieces"], bytes) and len(info_dict["pieces"]) % 20 == 0,
        "pieces must be a byte string with length divisible by 20",
    )
    length = info_dict["length"]
    check_state(
        isinstance(length, int) and length > 0,
        "length must be a positive integer",
    )

    pieces = get_piece_hashes(info_dict["pieces"])
    info = Info(
        name=name.decode(),
        length=length,
        piece_length=piece_length,
        pieces=pieces,
        dict_=info_dict,
    )

    return TorrentFile(
        announce=announce.decode(),
        info=info,
        dict_=metainfo_dict,
    )


def get_tracker_request_params(meta_info: TorrentFile) -> TrackerGetRequestParams:
    return {
        "info_hash": meta_info.info.info_hash().digest(),
        "peer_id": "00112233445566778899",
        "port": 6881,
        "uploaded": 0,
        "downloaded": 0,
        "left": meta_info.info.length,
        "compact": 1,
    }


def discover_peers(torrent_file: TorrentFile) -> TrackerGetResponse:
    tracker_response = requests.get(
        torrent_file.announce,
        params=get_tracker_request_params(torrent_file),
    )
    tracker_info = bencode_decode(tracker_response.content)
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
