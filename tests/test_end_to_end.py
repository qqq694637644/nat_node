"""Python node -> fake frpc QUIC DATAGRAM -> Go Agent -> fake WARP SOCKS5.

The fake WARP SOCKS5 endpoint performs real TCP and UDP loopback forwarding.
There is no direct-to-target path available to the Go exit agent.
"""

import asyncio
import os
from pathlib import Path
import socket
import time
import unittest

from reverse_socks import protocol as p
from reverse_socks.node import Node
from tests.mock_warp import FakeWarp, FakeFrpcDatagram

EXIT_BIN = os.environ.get("REVERSE_SOCKS_EXIT_BIN", "")
TOKEN = "test-secret-longer-than-sixteen-chars"


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class EchoUDP(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.transport.sendto(data, addr)


@unittest.skipUnless(EXIT_BIN and Path(EXIT_BIN).is_file(),
                     "set REVERSE_SOCKS_EXIT_BIN to the compiled Go agent")
class GoPythonIntegration(unittest.IsolatedAsyncioTestCase):
    PROTOCOL = "rsx3"

    async def asyncSetUp(self):
        self.node_app_port = free_udp_port()
        self.node_frpc_port = free_udp_port()
        self.exit_app_port = free_udp_port()
        self.exit_frpc_port = free_udp_port()
        self.node = await Node(
            TOKEN, socks_port=0, mux_port=0,
            udp_port=self.node_app_port, frpc_udp_port=self.node_frpc_port,
            protocol=self.PROTOCOL).start()
        self.tcp = await asyncio.start_server(self._tcp_echo, "127.0.0.1", 0)
        loop = asyncio.get_running_loop()
        self.udp_transport, _ = await loop.create_datagram_endpoint(
            EchoUDP, local_addr=("127.0.0.1", 0))
        self.node_frpc, node_frpc_protocol = await loop.create_datagram_endpoint(
            lambda: FakeFrpcDatagram(("127.0.0.1", self.node_app_port)),
            local_addr=("127.0.0.1", self.node_frpc_port))
        self.exit_frpc, exit_frpc_protocol = await loop.create_datagram_endpoint(
            lambda: FakeFrpcDatagram(("127.0.0.1", self.exit_app_port)),
            local_addr=("127.0.0.1", self.exit_frpc_port))
        # The two fake frpc endpoints forward across the same logical P2P link.
        # Override target send method to emulate cross-site QUIC DATAGRAM:
        node_frpc_protocol.partner = exit_frpc_protocol
        exit_frpc_protocol.partner = node_frpc_protocol
        self.warp = await FakeWarp().start()
        self.go = None
        await self.start_agent()

    async def asyncTearDown(self):
        await self.stop_agent()
        self.udp_transport.close()
        self.node_frpc.close()
        self.exit_frpc.close()
        await self.warp.stop()
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
            "-protocol", self.PROTOCOL,
            "-udp-bind", f"127.0.0.1:{self.exit_app_port}",
            "-udp-frpc", f"127.0.0.1:{self.exit_frpc_port}",
            "-warp-socks", f"127.0.0.1:{self.warp.port}",
            "-warp-probe", f"127.0.0.1:{self.tcp.sockets[0].getsockname()[1]}",
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

    async def socks(self, command: int, host: str, port: int, expected=0):
        reader, writer = await asyncio.open_connection("127.0.0.1",
                                                       self.node.socks_port)
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        self.assertEqual(await reader.readexactly(2), b"\x05\x00")
        writer.write(b"\x05" + bytes((command, 0)) + p.encode_address(host, port))
        await writer.drain()
        header = await asyncio.wait_for(reader.readexactly(4), 12)
        self.assertEqual(header[:1], b"\x05")
        self.assertEqual(header[1], expected, f"unexpected SOCKS reply: {header.hex()}")
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
        self.assertGreaterEqual(self.warp.tcp_connects, 21)

    async def test_large_tcp_download_and_control_isolation(self):
        # Ten megabytes crossing the fake local WARP and Go/Python stack.
        # This checks correct copy-backpressure at bulk sizes, rather than
        # counting successful tiny IP-discovery requests as throughput.
        payload = bytes(range(256)) * (10 * 1024 * 1024 // 256)
        await asyncio.wait_for(asyncio.gather(
            self.echo_tcp(payload),
            *(self.echo_tcp(f"small-{i}".encode() * 128) for i in range(10)),
        ), 35)

    async def test_empty_visitor_keepalive_does_not_replace_control_agent(self):
        original = self.node.tunnel
        _, writer = await asyncio.open_connection("127.0.0.1", self.node.mux_port)
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.05)
        self.assertIs(self.node.tunnel, original)
        await self.echo_tcp(b"after-keepalive")

    async def test_invalid_data_stream_does_not_replace_authenticated_agent(self):
        if self.PROTOCOL != "rsx3":
            self.skipTest("RSX3 preface is not supported by RSX2")
        original = self.node.tunnel
        _, writer = await asyncio.open_connection("127.0.0.1", self.node.mux_port)
        writer.write(b"R3D1" + b"Z" * 16 + (1).to_bytes(4, "big"))
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.05)
        self.assertIs(self.node.tunnel, original)
        await self.echo_tcp(b"after-bad-stream")

    async def test_slow_warp_stream_uses_backpressure_not_reset(self):
        # 10ms per 16KiB chunk on both directions exceeds the original
        # 32-frame queue under continuous echo load. RSX2 now waits for
        # receiver-granted credits instead of terminating the TCP session.
        self.warp.delay_seconds = 0.01
        large = bytes(range(256)) * 8192  # 2 MiB
        await asyncio.wait_for(asyncio.gather(
            self.echo_tcp(large),
            self.echo_tcp(b"independent-fast-stream" * 1000),
        ), 60)

    async def test_delayed_browser_reader_keeps_tcp_alive(self):
        reader, writer, _, _ = await self.socks(
            1, "127.0.0.1", self.tcp.sockets[0].getsockname()[1])
        payload = bytes(range(256)) * 4096  # 1 MiB
        try:
            writer.write(payload)
            await writer.drain()
            await asyncio.sleep(0.5)  # browser temporarily stops reading
            echoed = await asyncio.wait_for(reader.readexactly(len(payload)), 35)
            self.assertEqual(echoed, payload)
        finally:
            writer.close()
            await writer.wait_closed()

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
            # The independent WARP health probe opens an additional
            # UDP ASSOCIATE; neither it nor the SOCKS session sends data
            # directly to a target.
            self.assertGreaterEqual(self.warp.udp_associates, 1)
            self.assertEqual(self.warp.udp_packets, 25)
            # No automatic UDP-to-TCP fallback for oversized datagrams.
            await loop.sock_sendto(sock, p.udp_packet("127.0.0.1", dst, b"X" * 1500),
                                   (bind, bindport))
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(loop.sock_recvfrom(sock, 65535), 0.5)
            self.assertEqual(self.warp.udp_packets, 25)
        finally:
            writer.close()
            await writer.wait_closed()
            sock.close()

    async def test_reconnect(self):
        await self.echo_tcp(b"before")
        await self.stop_agent()
        await self.start_agent()
        await self.echo_tcp(b"after")

    async def test_warp_failure_never_dials_target(self):
        before = self.warp.tcp_connects
        await self.warp.close_listener()
        _, writer, _, _ = await self.socks(
            1, "127.0.0.1", self.tcp.sockets[0].getsockname()[1], expected=5)
        writer.close()
        await writer.wait_closed()
        self.assertEqual(self.warp.tcp_connects, before)
        _, writer, _, _ = await self.socks(3, "0.0.0.0", 0, expected=5)
        writer.close()
        await writer.wait_closed()


@unittest.skipUnless(EXIT_BIN and Path(EXIT_BIN).is_file(),
                      "set REVERSE_SOCKS_EXIT_BIN to the compiled Go agent")
class LegacyGoPythonIntegration(GoPythonIntegration):
    PROTOCOL = "rsx2"
