"""Cross-language test fixture; stdout is JSON, stdin controls shutdown.

Optional real upstream frps plus two private frpc processes. All UDP traffic
stays on localhost; a fake WARP handles STUN/QUIC and local DNS test replies.
This is deliberately not a production proxy or a throughput claim.
"""
import asyncio
import json
import logging
import os
from pathlib import Path
import sys
import tempfile

from reverse_socks import protocol as p
from reverse_socks.diagnostics import local_token
from reverse_socks.node import Node
from tests.mock_warp import FakeWarp, FakeWarpRelay, FakeFrpcDatagram
from tests.test_real_frps_rsx3 import LocalSTUN, free_tcp_port, free_udp_port

TOKEN = "diagnostics-cross-language-test-secret-32"


# DNS is answered locally by the fake WARP; never sends CI test traffic to
# a public resolver. QUIC/STUN localhost datagrams still use the original relay.
original_datagram = FakeWarpRelay.datagram_received

def local_dns(self, data, addr):
    try:
        host, port, payload = p.parse_udp_packet(data)
        if host == "1.1.1.1" and port == 53 and len(payload) >= 12:
            if self.client is None:
                self.client = addr
            if self.client != addr:
                return
            self.owner.udp_packets += 1
            response = payload[:2] + b"\x81\x80" + payload[4:]
            self.transport.sendto(p.udp_packet("1.1.1.1", 53, response), addr)
            return
    except ValueError:
        pass
    original_datagram(self, data, addr)

FakeWarpRelay.datagram_received = local_dns


async def main():
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    temp = tempfile.TemporaryDirectory(prefix="rsxdiag-integration-")
    root = Path(temp.name)
    processes, logs, transports = [], [], []
    writers = set()
    node = warp = echo = None
    try:
        warp = await FakeWarp().start()
        async def handle_echo(reader, writer):
            writers.add(writer)
            try:
                while data := await reader.read(65536):
                    writer.write(data)
                    await writer.drain()
                if writer.can_write_eof():
                    writer.write_eof()
            except (ConnectionError, OSError):
                pass
            finally:
                writer.close(); writers.discard(writer)
        echo = await asyncio.start_server(handle_echo, "127.0.0.1", 0)
        echo_port = echo.sockets[0].getsockname()[1]
        inside_diag, outside_diag = free_tcp_port(), free_tcp_port()
        app_udp, proxy_udp = free_udp_port(), free_udp_port()
        exit_udp, visitor_udp = free_udp_port(), free_udp_port()
        diag_enabled = os.getenv("RSX_DIAG_NODE_DISABLED") != "1"
        node = await Node(TOKEN, socks_port=0, mux_port=0, udp_port=app_udp,
                          frpc_udp_port=proxy_udp, protocol="rsx3",
                          diagnostics=diag_enabled,
                          frpc_diagnostics_addr=f"127.0.0.1:{inside_diag}").start()
        real = bool(os.getenv("RSX_DIAG_FRPC_BIN") and os.getenv("RSX_DIAG_FRPS_BIN"))
        visitor_port = node.mux_port
        if real:
            loop = asyncio.get_running_loop()
            ta, pa = await loop.create_datagram_endpoint(LocalSTUN, local_addr=("127.0.0.1", 0))
            tb, pb = await loop.create_datagram_endpoint(LocalSTUN, local_addr=("127.0.0.1", 0))
            transports.extend((ta, tb))
            pa.peer_port = tb.get_extra_info("sockname")[1]
            pb.peer_port = ta.get_extra_info("sockname")[1]
            stun = ta.get_extra_info("sockname")[1]
            server_port, visitor_port, nat_port = free_tcp_port(), free_tcp_port(), free_udp_port()
            (root / "frps.toml").write_text(f'''bindAddr = "127.0.0.1"
bindPort = {server_port}
auth.method = "token"
auth.token = "local-diagnostics-frps-token"
log.to = "console"
log.level = "info"
''')
            common = f'''serverAddr = "127.0.0.1"
serverPort = {server_port}
user = "diagnostics_fixture"
auth.method = "token"
auth.token = "local-diagnostics-frps-token"
transport.wireProtocol = "v1"
natHoleSTUNServer = "127.0.0.1:{stun}"
log.to = "console"
log.level = "info"
transport.quic.congestionMode = "brutal"
transport.quic.targetMbps = 64
transport.quic.maxMbps = 64
'''
            diagnostic = f'''diagnostics.enabled = true
diagnostics.token = "{local_token(TOKEN)}"
'''
            proxy = common + diagnostic + f'''diagnostics.listenAddr = "127.0.0.1:{inside_diag}"
[[proxies]]
name = "node"
type = "xtcp"
secretKey = "private-diagnostics-xtcp-secret"
localIP = "127.0.0.1"
localPort = {node.mux_port}
[proxies.natTraversal]
bindPort = {nat_port}
[proxies.datagram]
listenAddr = "127.0.0.1:{proxy_udp}"
peerAddr = "127.0.0.1:{app_udp}"
'''
            visitor = common + diagnostic + f'''diagnostics.listenAddr = "127.0.0.1:{outside_diag}"
transport.protocol = "tcp"
transport.proxyURL = "socks5://127.0.0.1:{warp.port}"
[[visitors]]
name = "outside"
type = "xtcp"
serverName = "node"
secretKey = "private-diagnostics-xtcp-secret"
protocol = "quic"
bindAddr = "127.0.0.1"
bindPort = {visitor_port}
keepTunnelOpen = true
minRetryInterval = 2
maxRetriesAnHour = 300
[visitors.natTraversal]
disableAssistedAddrs = true
udpProxyURL = "socks5://127.0.0.1:{warp.port}"
[visitors.datagram]
listenAddr = "127.0.0.1:{visitor_udp}"
peerAddr = "127.0.0.1:{exit_udp}"
'''
            (root / "proxy.toml").write_text(proxy)
            (root / "visitor.toml").write_text(visitor)
            for name, binary, config in (
                ("frps", os.environ["RSX_DIAG_FRPS_BIN"], "frps.toml"),
                ("inside", os.environ["RSX_DIAG_FRPC_BIN"], "proxy.toml"),
                ("outside", os.environ["RSX_DIAG_FRPC_BIN"], "visitor.toml"),
            ):
                log = (root / f"{name}.log").open("wb")
                logs.append(log)
                process = await asyncio.create_subprocess_exec(binary, "-c", str(root / config),
                                                                stdout=log, stderr=log)
                processes.append(process)
                await asyncio.sleep(.25)
                if process.returncode is not None:
                    raise RuntimeError(f"{name} exited early: {(root / f'{name}.log').read_text(errors='replace')}")
        else:
            loop = asyncio.get_running_loop()
            ta, a = await loop.create_datagram_endpoint(lambda: FakeFrpcDatagram(("127.0.0.1", app_udp)),
                                                        local_addr=("127.0.0.1", proxy_udp))
            tb, b = await loop.create_datagram_endpoint(lambda: FakeFrpcDatagram(("127.0.0.1", exit_udp)),
                                                        local_addr=("127.0.0.1", visitor_udp))
            a.partner, b.partner = b, a
            transports.extend((ta, tb))
        print(json.dumps({"ready": True, "token": TOKEN, "socks_port": node.socks_port,
                          "visitor_port": visitor_port, "warp_port": warp.port,
                          "probe_port": echo_port, "exit_udp": exit_udp,
                          "visitor_udp": visitor_udp, "frpc_diagnostics_port": outside_diag,
                          "node_frpc_diagnostics_port": inside_diag, "real_frpc": real,
                          "logs_dir": str(root)}), flush=True)
        while True:
            line = await asyncio.to_thread(sys.stdin.readline)
            if not line:
                break
            command = json.loads(line)
            if command.get("command") == "stop":
                break
            if command.get("command") == "snapshot":
                print(json.dumps(node.metrics.snapshot() if node.metrics else {"enabled": False}), flush=True)
            if command.get("command") == "close_warp":
                await warp.close_listener()
                print('{"closed":true}', flush=True)
    finally:
        for process in reversed(processes):
            if process.returncode is None:
                process.terminate()
        for process in reversed(processes):
            try:
                await asyncio.wait_for(process.wait(), 5)
            except asyncio.TimeoutError:
                process.kill(); await process.wait()
        for log in logs:
            log.close()
        if node:
            try:
                await asyncio.wait_for(node.stop(), 5)
            except asyncio.TimeoutError:
                pass
        for w in tuple(writers):
            w.close()
        if echo:
            echo.close()
            try:
                await asyncio.wait_for(echo.wait_closed(), 2)
            except asyncio.TimeoutError:
                pass
        if warp:
            try:
                await asyncio.wait_for(warp.stop(), 3)
            except asyncio.TimeoutError:
                pass
        for transport in transports:
            transport.close()
        if os.getenv("RSX_DIAG_KEEP_FIXTURE"):
            import shutil
            shutil.copytree(root, os.environ["RSX_DIAG_KEEP_FIXTURE"], dirs_exist_ok=True)
        temp.cleanup()

if __name__ == "__main__":
    asyncio.run(main())
