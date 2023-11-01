import asyncio
import io
import json
from ipaddress import ip_address
from pathlib import Path
from typing import Literal

import click

from app.bencode import (
    bencode_decode,
)
from app.client import Client
from app.models import Peer

PEER_NUM_BYTES = 6


def b_encode(string: bytes):
    def bytes_to_str(data):
        if isinstance(data, bytes):
            return data.decode("latin-1")
        raise TypeError(f"Type not serializable: {type(data)}")

    print(json.dumps(bencode_decode(string), default=bytes_to_str))


async def async_download_piece(
    file_content: bytes,
    output_file: io.BytesIO,
    piece_index: int,
):
    client = Client(file_content=file_content)
    await client.start((piece_index,))
    output_file.write(client.piece_manager.pieces[piece_index].get_data())
    print(f"Piece {piece_index} downloaded to {output_file.name}")
    return None


async def async_download_full_file(
    file_content: bytes,
    output_file: io.BytesIO,
):
    client = Client(file_content=file_content)
    await client.start()
    output_file.write(client.get_downloaded_data())
    print(f"Downloaded {client.get_torrent().info.name} to {output_file.name}")


async def async_main(
    command: Literal["handshake", "info", "peers", "download"],
    file_content: bytes,
    *args,
):
    match command:
        case "info":
            client = Client(file_content=file_content)
            print(
                f"Tracker URL: {client.get_torrent().announce}\n"
                f"Length: {client.get_torrent().info.length}\n"
                f"Info Hash: {client.get_torrent().info.info_hash().hexdigest()}\n"
                f"Piece Length: {client.get_torrent().info.piece_length}"
            )
            print(
                "Piece hashes: ",
                *[piece_hash.hex() for piece_hash in client.get_torrent().info.pieces],
                sep="\n",
            )
        case "peers":
            client = Client(file_content=file_content)
            metainfo = client.get_torrent()
            tracker_info = await metainfo.discover_peers()
            print("\n".join(f"{peer.ip}:{peer.port}" for peer in tracker_info.peers))

        case "handshake":
            torrent_file = Client.parse_torrent_file(file_content)
            peer_id = args[0]
            peer_ip, peer_port = peer_id.split(":")
            peer_handshake = await Client.perform_handshake(
                Peer(ip=ip_address(peer_ip), port=int(peer_port)),
                torrent_file.info.info_hash(),
            )
            print(f"Peer ID: {peer_handshake.peer_id.hex()}")
        case _:
            raise NotImplementedError(f"Unknown command {command}")


@click.command(
    name="BitTorrent Client",
    help="A BitTorrent client that can download single files from the BitTorrent network.",
)
@click.argument(
    "command",
    type=click.Choice(
        ["handshake", "decode", "info", "peers", "download", "download_piece"]
    ),
    required=True,
)
@click.option(
    "output_file",
    "-o",
    "--output-file",
    type=click.File("wb"),
    required=False,
)
@click.argument("args", nargs=-1)
def main(
    command: Literal["handshake", "decode", "info", "peers", "download"],
    output_file: io.BytesIO,
    args,
):
    if command == "decode":
        to_be_decoded = args[0]
        b_encode(to_be_decoded.encode("utf-8"))
    elif command == "download":
        (torrent_file_path,) = args
        asyncio.run(
            async_download_full_file(Path(torrent_file_path).read_bytes(), output_file)
        )
    elif command == "download_piece":
        torrent_file_path, piece_index = args
        asyncio.run(
            async_download_piece(
                Path(torrent_file_path).read_bytes(), output_file, int(piece_index)
            )
        )
    else:
        asyncio.run(async_main(command, Path(args[0]).read_bytes(), *args[1:]))


if __name__ == "__main__":
    main()
