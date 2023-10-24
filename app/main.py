import json
import sys

from app.bencode import (
    bencode_decode,
)
from app.peers import parse_torrent, calc_info_hash, discover_peers

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
            f"Tracker URL: {metainfo.announce}\n"
            f"Length: {metainfo.info.length}\n"
            f"Info Hash: {calc_info_hash(metainfo)}\n"
            f"Piece Length: {metainfo.info.piece_length}"
        )
        print(
            "Piece hashes: ",
            *[piece_hash.hex() for piece_hash in metainfo.info.pieces],
            sep="\n",
        )
    elif command == "peers":
        torrent_file = sys.argv[2].encode()
        metainfo = parse_torrent(torrent_file)
        tracker_info = discover_peers(metainfo)
        print("\n".join(f"{peer.ip}:{peer.port}" for peer in tracker_info.peers))
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
