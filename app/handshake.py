import socket
import sys
from ipaddress import IPv4Address, IPv6Address

from app.models import HandShake

IPAddress = IPv4Address | IPv6Address


def create_tcp_handshake(server_ip: IPAddress, server_port: int, handshake: HandShake):
    # Create a TCP/IP socket
    socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (str(server_ip), server_port)
    print(f"Connecting to {server_ip} port {server_port}", file=sys.stderr)
    socket_obj.connect(server_address)

    resp = b""
    try:
        # Send data
        message = handshake.to_str()
        print(f"Sending {message}", file=sys.stderr)
        socket_obj.sendall(message)

        # Look for the response
        amount_received = 0
        amount_expected = len(message)

        while amount_received < amount_expected:
            data = socket_obj.recv(1024)
            amount_received += len(data)
            resp += data

    finally:
        print("Closing socket", file=sys.stderr)
        socket_obj.close()
        return resp
