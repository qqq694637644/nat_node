"""Real frps 0.69.0 + two real frpc QUIC instances + RSX3 + fake WARP.

When the three binary environment variables are provided this test verifies
that independent TCP proxy sessions are carried through a *real* XTCP QUIC
connection, not merely through a local fake TCP tunnel. The overseas visitor
uses SOCKS5 for all STUN/XTCP traffic and WARP SOCKS5 for all target egress.
"""
import asyncio
import os
from pathlib import Path
import shutil
import socket
import struct
import tempfile
import time
import unittest

from reverse_socks import protocol as p
from reverse_socks.node import Node
from tests.mock_warp import FakeWarp

FRPS_BIN = os.getenv("RSX3_TEST_FRPS_BIN", "")
FRPC_BIN = os.getenv("RSX3_TEST_FRPC_BIN", "")
EXIT_BIN = os.getenv("REVERSE_SOCKS_EXIT_BIN", "")
TOKEN = "rsx3-integration-only-secret-long-enough"
XTCP_SECRET = "rsx3-local-frps-p2p-test-secret"
AUTH = "integration-frps-token"


def free_tcp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class LocalSTUN(asyncio.DatagramProtocol):
    def __init__(self):
        self.peer_port = 0

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, source):
        if len(data) < 20 or data[:2] != b"\x00\x01":
            return
        if data[4:8] != b"\x21\x12\xa4\x42":
            return
        src_ip, src_port = source
        cookie = 0x2112A442
        x_port = src_port ^ (cookie >> 16)
        x_ip = bytes(a ^ b for a, b in zip(socket.inet_aton(src_ip),
                                           struct.pack("!I", cookie)))
        mapped = struct.pack("!HHBBH", 0x0020, 8, 0, 1, x_port) + x_ip
        other = (struct.pack("!HHBBH", 0x802c, 8, 0, 1, self.peer_port)
                 + socket.inet_aton("127.0.0.1"))
        attrs = mapped + other
        response = struct.pack("!HHI", 0x0101, len(attrs), cookie) + data[8:20] + attrs
        self.transport.sendto(response, source)


@unittest.skipUnless(FRPS_BIN and FRPC_BIN and EXIT_BIN and
                      all(Path(p).is_file() for p in (FRPS_BIN, FRPC_BIN, EXIT_BIN)),
                      "set RSX3_TEST_FRPS_BIN, RSX3_TEST_FRPC_BIN and REVERSE_SOCKS_EXIT_BIN")
class RealFrpRSX3Integration(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="rsx3-real-frps-")
        self.base = Path(self.tmp.name)
        self.processes = []
        self.process_names = []
        self.log_files = []
        self.stun_a = self.stun_b = None
        self.node = None
        self.warp = None
        self.echo = None
        self.udp_fake = None

    async def asyncTearDown(self):
        for process in reversed(self.processes):
            if process.returncode is None:
                process.terminate()
        for process in reversed(self.processes):
            try:
                await asyncio.wait_for(process.wait(), 5)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
        for f in self.log_files:
            f.close()
        if self.node:
            try:
                await asyncio.wait_for(self.node.stop(), 5)
            except asyncio.TimeoutError:
                print("real-frpc integration: node shutdown exceeded 5s", flush=True)
        if self.warp:
            try:
                await asyncio.wait_for(self.warp.stop(), 5)
            except asyncio.TimeoutError:
                print("real-frpc integration: fake WARP shutdown exceeded 5s", flush=True)
        if self.echo:
            self.echo.close()
            try:
                await asyncio.wait_for(self.echo.wait_closed(), 5)
            except asyncio.TimeoutError:
                # A failed large QUIC burst can leave a SOCKS5/TCP handler
                # waiting for an already-disconnected remote peer. Preserve
                # its failure output instead of hanging CI teardown forever.
                print("real-frpc integration: TCP echo shutdown exceeded 5s", flush=True)
        for t in (self.stun_a, self.stun_b):
            if t:
                t.close()
        # Only integration-generated fixtures and traces are collected; no
        # production credentials or traffic are used in this test.
        if os.getenv("RSX3_DIAG_DIR"):
            shutil.copytree(self.base, os.environ["RSX3_DIAG_DIR"], dirs_exist_ok=True)
        self.tmp.cleanup()

    async def spawn(self, name, *args, env=None):
        log = (self.base / f"{name}.log").open("wb")
        self.log_files.append(log)
        process = await asyncio.create_subprocess_exec(*map(str, args),
                                                       stdout=log, stderr=log, env=env)
        self.processes.append(process)
        self.process_names.append(name)
        return process

    def write_config(self, name, contents):
        path = self.base / name
        path.write_text(contents, encoding="utf-8")
        return path

    async def _echo(self, reader, writer):
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
            if writer.can_write_eof():
                writer.write_eof()
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    async def _wait_online(self, seconds=55):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.node.tunnel is not None and self.node.tunnel.alive:
                return
            for name, process in zip(self.process_names, self.processes):
                if process.returncode is not None:
                    logs = "\n".join(
                        f"{path.name}:\n{path.read_text(errors='replace')[-4500:]}"
                        for path in self.base.glob("*.log"))
                    self.fail(f"{name} exited early with code {process.returncode}:\n{logs}")
            await asyncio.sleep(0.2)
        logs = "\n".join(f"{path.name}:\n{path.read_text(errors='replace')[-3000:]}"
                         for path in self.base.glob("*.log"))
        self.fail("real frps/frpc RSX3 control failed to connect:\n" + logs)

    async def _socks_echo(self, payload):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.node.socks_port)
        try:
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            self.assertEqual(await reader.readexactly(2), b"\x05\x00")
            writer.write(b"\x05\x01\x00" + p.encode_address("127.0.0.1", self.echo_port))
            await writer.drain()
            reply = await asyncio.wait_for(reader.readexactly(10), 25)
            self.assertEqual(reply[1], 0, f"SOCKS CONNECT failed: {reply.hex()}")
            async def send():
                for pos in range(0, len(payload), 65536):
                    writer.write(payload[pos:pos + 65536])
                    await writer.drain()
                writer.write_eof()
            push = asyncio.create_task(send())
            data = await asyncio.wait_for(reader.readexactly(len(payload)), 80)
            self.assertEqual(data, payload)
            await push
            self.assertEqual(await asyncio.wait_for(reader.read(), 10), b"")
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_official_frps_two_frpc_xp2p_and_rsx3_bulk(self):
        loop = asyncio.get_running_loop()
        self.stun_a, protocol_a = await loop.create_datagram_endpoint(
            LocalSTUN, local_addr=("127.0.0.1", 0))
        self.stun_b, protocol_b = await loop.create_datagram_endpoint(
            LocalSTUN, local_addr=("127.0.0.1", 0))
        port_a = self.stun_a.get_extra_info("sockname")[1]
        port_b = self.stun_b.get_extra_info("sockname")[1]
        protocol_a.peer_port = port_b
        protocol_b.peer_port = port_a

        self.warp = await FakeWarp().start()
        self.echo = await asyncio.start_server(self._echo, "127.0.0.1", 0)
        self.echo_port = self.echo.sockets[0].getsockname()[1]
        node_to_frpc, frpc_to_node = free_udp_port(), free_udp_port()
        exit_to_frpc, frpc_to_exit = free_udp_port(), free_udp_port()
        self.node = await Node(TOKEN, socks_port=0, mux_port=0,
                               udp_port=node_to_frpc, frpc_udp_port=frpc_to_node,
                               protocol="rsx3").start()
        visitor_port = free_tcp_port()
        server_port = free_tcp_port()
        nat_port = free_udp_port()
        self.write_config("frps.toml", f"""
bindAddr = "127.0.0.1"
bindPort = {server_port}
auth.method = "token"
auth.token = "{AUTH}"
log.to = "console"
log.level = "info"
""")
        common = f"""
serverAddr = "127.0.0.1"
serverPort = {server_port}
user = "compat_test"
natHoleSTUNServer = "127.0.0.1:{port_a}"
transport.wireProtocol = "v1"
auth.method = "token"
auth.token = "{AUTH}"
log.to = "console"
log.level = "info"
"""
        brutal = os.getenv("RSX3_TEST_BRUTAL", "") == "1"
        if brutal:
            target_mbps = int(os.getenv("RSX3_TEST_BRUTAL_TARGET_MBPS", "16"))
            max_mbps = int(os.getenv("RSX3_TEST_BRUTAL_MAX_MBPS", "24"))
            # Both independently paced XTCP QUIC senders, not the
            # frpc-to-frps control channel and not native VPS UDP.
            common += f"""
transport.quic.congestionMode = "brutal"
transport.quic.targetMbps = {target_mbps}
transport.quic.maxMbps = {max_mbps}
"""
        proxy = common + f"""
[[proxies]]
name = "rsx3_node"
type = "xtcp"
secretKey = "{XTCP_SECRET}"
localIP = "127.0.0.1"
localPort = {self.node.mux_port}
[proxies.natTraversal]
bindPort = {nat_port}
[proxies.datagram]
listenAddr = "127.0.0.1:{frpc_to_node}"
peerAddr = "127.0.0.1:{node_to_frpc}"
"""
        visitor = common + f"""
transport.protocol = "tcp"
transport.proxyURL = "socks5://127.0.0.1:{self.warp.port}"
[[visitors]]
name = "rsx3_outside"
type = "xtcp"
serverName = "rsx3_node"
secretKey = "{XTCP_SECRET}"
protocol = "quic"
bindAddr = "127.0.0.1"
bindPort = {visitor_port}
keepTunnelOpen = true
minRetryInterval = 2
maxRetriesAnHour = 300
[visitors.datagram]
listenAddr = "127.0.0.1:{frpc_to_exit}"
peerAddr = "127.0.0.1:{exit_to_frpc}"
[visitors.natTraversal]
disableAssistedAddrs = true
udpProxyURL = "socks5://127.0.0.1:{self.warp.port}"
"""
        # Prefix-level transport field must precede the first [[visitors]]
        # table; placing it at the end of common avoids TOML nesting errors.
        self.write_config("proxy.toml", proxy)
        self.write_config("visitor.toml", visitor)
        qlogdir = self.base / "qlog"
        qlogdir.mkdir(mode=0o700)
        qlogenv = dict(os.environ, QLOGDIR=str(qlogdir))
        await self.spawn("frps", FRPS_BIN, "-c", self.base / "frps.toml")
        await asyncio.sleep(0.4)
        await self.spawn("inside-frpc", FRPC_BIN, "-c", self.base / "proxy.toml",
                         env=qlogenv)
        await asyncio.sleep(0.4)
        await self.spawn("outside-frpc", FRPC_BIN, "-c", self.base / "visitor.toml",
                         env=qlogenv)
        await asyncio.sleep(0.4)
        await self.spawn("go-agent", EXIT_BIN,
                         "-protocol", "rsx3",
                         "-visitor", f"127.0.0.1:{visitor_port}",
                         "-udp-bind", f"127.0.0.1:{exit_to_frpc}",
                         "-udp-frpc", f"127.0.0.1:{frpc_to_exit}",
                         "-warp-socks", f"127.0.0.1:{self.warp.port}",
                         "-warp-probe", f"127.0.0.1:{self.echo_port}",
                         "-retry", "250ms",
                         env=dict(os.environ, REVERSE_SOCKS_TOKEN=TOKEN))
        await self._wait_online()
        start = time.monotonic()
        bytes_to_test = int(os.getenv("RSX3_BULK_BYTES", "1048576"))
        extra_streams = int(os.getenv("RSX3_TEST_EXTRA_STREAMS", "12"))
        large = bytes(range(256)) * (bytes_to_test // 256)
        await asyncio.wait_for(asyncio.gather(
            self._socks_echo(large),
            *(self._socks_echo(f"stream-{i}".encode() * 1024) for i in range(extra_streams)),
        ), 85)
        elapsed = time.monotonic() - start
        print(f"REAL_FRPS_069_RSX3_{len(large)}B_AND_{extra_streams}_EXTRA_STREAMS_PASS elapsed={elapsed:.2f}s")
        self.assertGreaterEqual(self.warp.tcp_connects, extra_streams + 1)
        self.assertTrue(any(qlogdir.iterdir()), "quic-go must emit RTT/recovery qlog traces")
        outside = (self.base / "outside-frpc.log").read_text(errors="replace")
        self.assertIn("assistedAddresses: []", outside)
        self.assertIn("XTCP tunnel handshake ready", outside)
        if brutal:
            inside = (self.base / "inside-frpc.log").read_text(errors="replace")
            self.assertIn(
                f"XTCP Proxy QUIC congestion=brutal targetMbps={target_mbps} maxMbps={max_mbps}", inside
            )
            self.assertIn(
                f"XTCP Visitor QUIC congestion=brutal targetMbps={target_mbps} maxMbps={max_mbps}", outside
            )
            print(f"BOUNDED_BRUTAL_BOTH_XTCP_ENDPOINTS_CONFIRMED_{target_mbps}_{max_mbps}")
        print("QUIC_QLOG_CREATED_AND_WARP_ONLY_PUBLIC_FALLBACK_DISABLED")
