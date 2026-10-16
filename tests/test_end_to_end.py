"""Runs against the real Go agent when REVERSE_SOCKS_EXIT_BIN is set.

All traffic stays on 127.0.0.1: this verifies the Python/Go wire protocol,
TCP duplex streams, UDP ASSOCIATE, DNS-style UDP, concurrency and reconnect,
without requiring frps or WARP on the CI host.
"""

import asyncio
import os
from pathlib import Path
import socket
import struct
import time
import unittest

from reverse_socks import protocol as p
from reverse_socks.node import Node

EXIT_BIN = os.environ.get("REVERSE_SOCKS_EXIT_BIN", "")
TOKEN = "test-secret-longer-than-sixteen-chars"


class EchoUDP(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.transport.sendto(data, addr)


@unittest.skipUnless(EXIT_BIN and Path(EXIT_BIN).is_file(),
                     "set REVERSE_SOCKS_EXIT_BIN to the compiled Go agent")
class GoPythonIntegration(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.node = await Node(TOKEN, socks_port=0, mux_port=0).start()
        self.tcp = await asyncio.start_server(self._tcp_echo, "127.0.0.1", 0)
        loop = asyncio.get_running_loop()
        self.udp_transport, _ = await loop.create_datagram_endpoint(
            EchoUDP, local_addr=("127.0.0.1", 0))
        self.go = None
        await self.start_agent()

    async def asyncTearDown(self):
        await self.stop_agent()
        self.udp_transport.close()
        self.tcp.close()
        await self.tcp.wait_closed()
        await self.node.stop()

    async def _tcp_echo(self, reader, writer):
        try:
            while data := await reader.read(16384):
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    async def start_agent(self):
        env = dict(os.environ, REVERSE_SOCKS_TOKEN=TOKEN)
        self.go = await asyncio.create_subprocess_exec(
            EXIT_BIN, "-visitor", f"127.0.0.1:{self.node.mux_port}",
            "-retry", "100ms", env=env,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL)
        for _ in range(100):
            if self.node.tunnel and self.node.tunnel.alive:
                return
            await asyncio.sleep(0.05)
        self.fail("Go agent never authenticated")

    async def stop_agent(self):
        if self.go and self.go.returncode is None:
            self.go.terminate()
            try:
                await asyncio.wait_for(self.go.wait(), 5)
            except asyncio.TimeoutError:
                self.go.kill()
                await self.go.wait()
        self.go = None
        for _ in range(100):
            if self.node.tunnel is None:
                break
            await asyncio.sleep(0.02)

    async def socks(self, command: int, host: str, port: int):
        reader, writer = await asyncio.open_connection("127.0.0.1",
                                                       self.node.socks_port)
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        self.assertEqual(await reader.readexactly(2), b"\x05\x00")
        writer.write(b"\x05" + bytes((command, 0)) + p.encode_address(host, port))
        await writer.drain()
        header = await asyncio.wait_for(reader.readexactly(4), 12)
        self.assertEqual(header[:1], b"\x05")
        self.assertEqual(header[1], 0, f"SOCKS command {command} failed: {header.hex()}")
        self.assertEqual(header[3], 1)
        addr = await reader.readexactly(6)
        bind, bindport, _ = p.decode_address(bytes((1,)) + addr)
        return reader, writer, bind, bindport

    async def echo_tcp(self, body: bytes):
        port = self.tcp.sockets[0].getsockname()[1]
        reader, writer, _, _ = await self.socks(1, "127.0.0.1", port)
        try:
            writer.write(body)
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(len(body)), 15),
                             body)
            writer.write_eof()
            self.assertEqual(await asyncio.wait_for(reader.read(), 5), b"")
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_tcp_concurrent_and_throughput(self):
        body = bytes(range(256)) * 4096  # 1 MiB
        start = time.monotonic()
        await self.echo_tcp(body)
        elapsed = time.monotonic() - start
        self.assertGreater(len(body) / elapsed, 0)
        print(f"loopback TCP mux throughput: {len(body) / elapsed / 1048576:.1f} MiB/s")
        await asyncio.gather(*(self.echo_tcp(f"session-{i}".encode() * 1000)
                               for i in range(20)))

    async def test_udp_associate(self):
        reader, writer, bind, bindport = await self.socks(3, "0.0.0.0", 0)
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        dst = self.udp_transport.get_extra_info("sockname")[1]
        try:
            for index in range(25):
                body = f"udp-{index}".encode()
                packet = p.udp_packet("127.0.0.1", dst, body)
                await loop.sock_sendto(sock, packet, (bind, bindport))
                data, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 65535), 5)
                src_host, src_port, echoed = p.parse_udp_packet(data)
                self.assertEqual((src_host, src_port, echoed),
                                 ("127.0.0.1", dst, body))
        finally:
            writer.close()
            await writer.wait_closed()
            sock.close()

    async def test_reconnect(self):
        await self.echo_tcp(b"before")
        await self.stop_agent()
        await self.start_agent()
        await self.echo_tcp(b"after")
