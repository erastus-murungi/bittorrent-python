import json
import sys
from ipaddress import ip_address

from app.bencode import (
    bencode_decode,
)
from app.handshake import create_tcp_handshake
from app.models import HandShake
from app.peers import parse_torrent, discover_peers

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
            f"Info Hash: {metainfo.info.info_hash().hexdigest()}\n"
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
    elif command == "handshake":
        torrent_file = sys.argv[2].encode()
        metainfo = parse_torrent(torrent_file)
        peer_ip_str, peer_port_str = sys.argv[3].split(":", maxsplit=1)
        peer_ip = ip_address(peer_ip_str)
        peer_port = int(peer_port_str)
        # peer_ip = ip_address("165.232.33.77")
        # peer_port = 51467
        handshake = HandShake(
            b"00112233445566778899", metainfo.info.info_hash().digest()
        )
        resp = create_tcp_handshake(peer_ip, peer_port, handshake)
        peer_resp = HandShake.parse_from_response(resp)
        print(f"Peer ID: {peer_resp.peer_id.hex()}")

    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
