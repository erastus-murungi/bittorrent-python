import asyncio
import io
import json
from ipaddress import ip_address
from pathlib import Path
from typing import Literal, Tuple, Union

import click

from app.bencode import bencode_decode
from app.client import Client, Peer
from app.peer_discovery import discover_peers
from app.torrent import Torrent

PEER_NUM_BYTES = 6


def decode_and_print(bytestring: bytes) -> None:
    """Encode the string using bencode"""

    def bytes_to_str(data):
        if isinstance(data, bytes):
            try:
                return data.decode("utf-8")
            except UnicodeDecodeError:
                return data.decode("latin-1")
        raise TypeError(f"Type not serializable: {type(data)}")

    print(json.dumps(bencode_decode(bytestring), default=bytes_to_str))


async def async_download_piece(
    file_content: bytes, output_file: io.BytesIO, piece_index: int
) -> None:
    """Download a piece of the file"""
    client = Client(file_content=file_content)
    await client.start(desired_piece_indices=(piece_index,))
    output_file.write(client.piece_manager.pieces[piece_index].get_data())


async def async_download_full_file(
    file_content: bytes, output_file: io.BytesIO
) -> None:
    """Download the full file"""
    client = Client(file_content=file_content)
    await client.start()
    output_file.write(client.get_downloaded_data())


async def async_main(
    command: Literal["handshake", "info", "peers", "download"],
    file_content: bytes,
    *args: Union[str, int],
) -> None:
    """Main function to handle various commands"""
    match command:
        case "info":
            print_info(file_content)
        case "peers":
            await print_peers(file_content)
        case "handshake":
            await perform_handshake(file_content, args)
        case _:
            raise ValueError(f"Unknown command {command}")


def print_info(file_content: bytes) -> None:
    """Print torrent info"""
    torrent = Torrent.from_file_content(file_content)
    print(
        f"Tracker URL: {torrent.announce}\n"
        f"Length: {torrent.info.length}\n"
        f"Info Hash: {torrent.info.compute_info_hash().hexdigest()}\n"
        f"Piece Length: {torrent.info.piece_length}"
    )
    print(
        "Piece hashes: ",
        *[piece_hash.hex() for piece_hash in torrent.info.pieces],
        sep="\n",
    )


async def print_peers(file_content: bytes) -> None:
    """Print peers"""
    client = Client(file_content=file_content)
    metainfo = client.torrent
    tracker_info = await discover_peers(metainfo)
    print("\n".join(f"{peer.ip}:{peer.port}" for peer in tracker_info.peers))


async def perform_handshake(file_content: bytes, args: Tuple[str, ...]) -> None:
    """Perform handshake"""
    torrent_file = Torrent.from_file_content(file_content)
    peer_id = args[0]
    peer_ip, peer_port = peer_id.split(":")
    peer_handshake = await Client.perform_handshake(
        Peer(ip=ip_address(peer_ip), port=int(peer_port)),
        torrent_file.info.compute_info_hash(),
    )
    print(f"Peer ID: {peer_handshake.peer_id.hex()}")


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
    "output_file", "-o", "--output-file", type=click.File("wb"), required=False
)
@click.argument("args", nargs=-1)
def main(
    command: Literal[
        "handshake", "decode", "info", "peers", "download", "download_piece"
    ],
    output_file: io.BytesIO,
    args: Tuple[str, ...],
) -> None:
    match command:
        case "decode":
            bytestring = args[0].encode("utf-8")
            decode_and_print(bytestring)
        case "download":
            (torrent_file_path,) = args
            asyncio.run(
                async_download_full_file(
                    Path(torrent_file_path).read_bytes(), output_file
                )
            )
        case "download_piece":
            torrent_file_path, piece_index = args
            asyncio.run(
                async_download_piece(
                    Path(torrent_file_path).read_bytes(), output_file, int(piece_index)
                )
            )
        case _:
            file_path = args[0]
            asyncio.run(async_main(command, Path(file_path).read_bytes(), *args[1:]))


if __name__ == "__main__":
    main()
