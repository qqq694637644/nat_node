"""Shared RSX1 wire protocol. Keep in sync with x-ui/reverseexit/protocol.go."""

import ipaddress
import struct

MAGIC = b"RSX1"
HEADER = struct.Struct("!BII")
MAX_PAYLOAD = 65535
TCP_CHUNK = 16384

OPEN_TCP = 1
TCP_RESULT = 2
TCP_DATA = 3
TCP_FIN = 4
TCP_RST = 5
OPEN_UDP = 6
UDP_DATA = 7
UDP_CLOSE = 8
PING = 9
PONG = 10


def encode_address(host: str, port: int) -> bytes:
    if not 0 <= port <= 65535:
        raise ValueError("invalid port")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        name = host.encode("idna")
        if not name or len(name) > 255:
            raise ValueError("invalid domain")
        address = bytes((3, len(name))) + name
    else:
        address = bytes((1 if ip.version == 4 else 4,)) + ip.packed
    return address + struct.pack("!H", port)


def decode_address(data: bytes, offset: int = 0) -> tuple[str, int, int]:
    if offset >= len(data):
        raise ValueError("missing address type")
    atyp = data[offset]
    offset += 1
    if atyp == 1:
        length = 4
        if len(data) < offset + length + 2:
            raise ValueError("short IPv4 address")
        host = str(ipaddress.IPv4Address(data[offset:offset + length]))
    elif atyp == 4:
        length = 16
        if len(data) < offset + length + 2:
            raise ValueError("short IPv6 address")
        host = str(ipaddress.IPv6Address(data[offset:offset + length]))
    elif atyp == 3:
        if offset >= len(data):
            raise ValueError("short domain length")
        length = data[offset]
        offset += 1
        if length == 0 or len(data) < offset + length + 2:
            raise ValueError("short domain address")
        host = data[offset:offset + length].decode("ascii")
    else:
        raise ValueError("unsupported address type")
    offset += length
    port = struct.unpack_from("!H", data, offset)[0]
    return host, port, offset + 2


def udp_packet(host: str, port: int, payload: bytes) -> bytes:
    packet = b"\x00\x00\x00" + encode_address(host, port) + payload
    if len(packet) > MAX_PAYLOAD:
        raise ValueError("UDP payload exceeds frame limit")
    return packet


def parse_udp_packet(packet: bytes) -> tuple[str, int, bytes]:
    if len(packet) < 4 or packet[:3] != b"\x00\x00\x00":
        # FRAG != 0 and nonzero RSV are intentionally unsupported.
        raise ValueError("invalid or fragmented SOCKS UDP packet")
    host, port, offset = decode_address(packet, 3)
    return host, port, packet[offset:]
