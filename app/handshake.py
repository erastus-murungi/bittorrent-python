import asyncio
from ipaddress import IPv4Address, IPv6Address

from app.models import HandShake
from app.utils import log

IPAddress = IPv4Address | IPv6Address


async def _download(server_ip: IPAddress, server_port: int, handshake: HandShake):
    try:
        reader, writer = await asyncio.open_connection(str(server_ip), server_port)
        writer.write(handshake.to_str())
        await writer.drain()

        data = await reader.read(68)

        # ensure the handshake is valid
        peer_handshake = HandShake.parse_from_response(data)
        if peer_handshake.info_hash != handshake.info_hash:
            raise ValueError("Peer sent invalid info hash")
        if peer_handshake.peer_id == handshake.peer_id:
            raise ValueError("Peer sent invalid peer id")

        log(f"Handshake successful with peer {server_ip}:{server_port}")

        # send an interested message
    except Exception as e:
        log(f"Failed to connect to {server_ip}:{server_port} with exception {e}")
