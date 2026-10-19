"""Loopback SOCKS5 CONNECT / UDP ASSOCIATE fake WARP for RSX3 integration.

This is deliberately a *test proxy*, not an alternative egress implementation:
the Go agent must use it to reach the TCP/UDP echo targets.
"""

import asyncio
import socket

from reverse_socks import protocol as p
from reverse_socks.node import read_socks_address


class FakeWarpRelay(asyncio.DatagramProtocol):
    def __init__(self, owner):
        self.owner = owner
        self.client = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if self.client is None:
            try:
                p.parse_udp_packet(data)
            except ValueError:
                return
            self.client = addr
        if addr == self.client:
            try:
                host, port, payload = p.parse_udp_packet(data)
            except ValueError:
                return
            self.owner.udp_packets += 1
            if host == "127.0.0.1":
                self.transport.sendto(payload, (host, port))
        else:
            self.transport.sendto(p.udp_packet(addr[0], addr[1], data), self.client)


class FakeWarp:
    def __init__(self):
        self.server = None
        self.tcp_connects = 0
        self.udp_associates = 0
        self.udp_packets = 0
        self.connections = set()
        self.delay_seconds = 0

    async def start(self):
        self.server = await asyncio.start_server(self._client, "127.0.0.1", 0)
        return self

    @property
    def port(self):
        return self.server.sockets[0].getsockname()[1]

    async def close_listener(self):
        self.server.close()
        await self.server.wait_closed()

    async def stop(self):
        await self.close_listener()
        for w in tuple(self.connections):
            w.close()
        await asyncio.gather(*(w.wait_closed() for w in tuple(self.connections)),
                             return_exceptions=True)

    async def _client(self, reader, writer):
        self.connections.add(writer)
        relay = None
        try:
            greeting = await reader.readexactly(2)
            if greeting[0] != 5:
                return
            methods = await reader.readexactly(greeting[1])
            if 0 not in methods:
                writer.write(b"\x05\xff")
                await writer.drain()
                return
            writer.write(b"\x05\x00")
            await writer.drain()
            ver, cmd, rsv, atyp = await reader.readexactly(4)
            if (ver, rsv) != (5, 0):
                return
            host, port = await read_socks_address(reader, atyp)
            if cmd == 1:
                self.tcp_connects += 1
                dest_reader, dest_writer = await asyncio.open_connection(host, port)
                writer.write(b"\x05\x00\x00" + p.encode_address("127.0.0.1", 0))
                await writer.drain()

                async def pump(src, dst):
                    try:
                        while data := await src.read(16384):
                            if self.delay_seconds:
                                await asyncio.sleep(self.delay_seconds)
                            dst.write(data)
                            await dst.drain()
                        if dst.can_write_eof():
                            dst.write_eof()
                            await dst.drain()
                    except (ConnectionError, OSError):
                        pass

                try:
                    await asyncio.gather(pump(reader, dest_writer),
                                         pump(dest_reader, writer))
                finally:
                    dest_writer.close()
                    await dest_writer.wait_closed()
            elif cmd == 3:
                self.udp_associates += 1
                loop = asyncio.get_running_loop()
                relay, _ = await loop.create_datagram_endpoint(
                    lambda: FakeWarpRelay(self), local_addr=("127.0.0.1", 0),
                    family=socket.AF_INET)
                bind = relay.get_extra_info("sockname")[1]
                writer.write(b"\x05\x00\x00" + p.encode_address("127.0.0.1", bind))
                await writer.drain()
                await reader.read()
            else:
                writer.write(b"\x05\x07\x00" + p.encode_address("0.0.0.0", 0))
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            if relay:
                relay.close()
            writer.close()
            self.connections.discard(writer)
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass


class FakeFrpcDatagram(asyncio.DatagramProtocol):
    def __init__(self, target):
        self.target = target
        self.partner = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        # Preserve unreliable datagram boundaries, as QUIC DATAGRAM does.
        self.partner.transport.sendto(data, self.partner.target)
