import ipaddress
import json
import sys

from app.bencode import (
    bencode_decode,
    parse_torrent,
    calc_info_hash,
    get_piece_hashes,
    discover_peers,
)
from app.utils import check_state

PEER_NUM_BYTES = 6


def main():
    # sys.argv = ["", "peers", "../sample.torrent"]
    command = sys.argv[1]

    def bytes_to_str(data):
        if isinstance(data, bytes):
            return data.decode()

        raise TypeError(f"Type not serializable: {type(data)}")

    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        # Uncomment this block to pass the first stage
        print(json.dumps(bencode_decode(bencoded_value), default=bytes_to_str))
    elif command == "info":
        torrent_file = sys.argv[2].encode()
        metainfo = parse_torrent(torrent_file)
        print(
            f'Tracker URL: {metainfo["announce"].decode()}\n'
            f'Length: {metainfo["info"]["length"]}\n'
            f"Info Hash: {calc_info_hash(metainfo)}\n"
            f"Piece Length: {metainfo['info']['piece length']}"
        )
        print("Piece hashes: ", *get_piece_hashes(metainfo), sep="\n")
    elif command == "peers":
        torrent_file = sys.argv[2].encode()
        tracker_info = discover_peers(torrent_file)
        peers = tracker_info["peers"]
        check_state(
            len(peers) % PEER_NUM_BYTES == 0, "Peers length is not a multiple of 6"
        )
        for i in range(0, len(peers), PEER_NUM_BYTES):
            peer_info = peers[i : i + PEER_NUM_BYTES]
            peer_ip = ipaddress.ip_address(peer_info[:4])
            peer_port: int = int.from_bytes(peer_info[4:], "big", signed=False)
            print(f"{peer_ip}:{peer_port}")
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
