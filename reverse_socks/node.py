"""Local SOCKS5 endpoint and multiplexed reverse channel for the outside Go agent."""

import argparse
import asyncio
import ipaddress
import logging
import os
import socket

from . import protocol as p
from . import diagnostics as diag
from .rsx3 import TunnelV3, accept_control, accept_data, bridge_tcp

LOG = logging.getLogger("reverse_socks")
MAX_SESSIONS = 1024


async def read_socks_address(reader: asyncio.StreamReader, atyp: int) -> tuple[str, int]:
    if atyp == 1:
        raw = await reader.readexactly(4 + 2)
    elif atyp == 4:
        raw = await reader.readexactly(16 + 2)
    elif atyp == 3:
        length = (await reader.readexactly(1))[0]
        raw = bytes((length,)) + await reader.readexactly(length + 2)
    else:
        raise ValueError("unsupported address type")
    host, port, _ = p.decode_address(bytes((atyp,)) + raw)
    return host, port


async def socks_reply(writer: asyncio.StreamWriter, status: int, host="0.0.0.0", port=0):
    writer.write(bytes((5, status, 0)) + p.encode_address(host, port))
    await writer.drain()


class UDPSession:
    def __init__(self, sid: int, relay):
        self.sid = sid
        self.relay = relay
        self.closed = asyncio.Event()
        self.result = asyncio.get_running_loop().create_future()

    def fail(self):
        self.closed.set()
        if not self.result.done():
            self.result.set_exception(ConnectionError("UDP association closed"))

    def ready(self, data: bytes):
        if self.result.done():
            return
        if data == b"\x00":
            self.result.set_result(None)
        else:
            self.result.set_exception(ConnectionError("WARP UDP ASSOCIATE failed"))


class UDPRelay(asyncio.DatagramProtocol):
    def __init__(self, tunnel: TunnelV3, allowed_ip: str):
        self.tunnel = tunnel
        self.allowed_ip = ipaddress.ip_address(allowed_ip)
        self.transport = None
        self.peer = None
        self.session = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if (not self.session or self.session.closed.is_set()
                or ipaddress.ip_address(addr[0]) != self.allowed_ip):
            return
        if self.peer is None:
            self.peer = addr
        if addr != self.peer:
            return
        try:
            p.parse_udp_packet(data)
            self.tunnel.node.send_udp(self.session.sid, data)
        except ValueError:
            pass  # Drop an oversized/fragmented datagram; NEVER send over TCP.

    def forward(self, data: bytes):
        if not self.transport or self.peer is None:
            return
        try:
            p.parse_udp_packet(data)
        except ValueError:
            return
        self.transport.sendto(data, self.peer)

class DatagramLink(asyncio.DatagramProtocol):
    def __init__(self, node, allowed_peer):
        self.node = node
        self.allowed_peer = allowed_peer

    def datagram_received(self, data, addr):
        if addr != self.allowed_peer:
            if self.node.metrics: self.node.metrics.udp_drops["wrong_local_peer"] += 1
            return
        try:
            sid, packet = p.decode_link_datagram(data)
        except ValueError:
            if self.node.metrics: self.node.metrics.udp_drops["invalid_or_oversize"] += 1
            return
        tunnel = self.node.tunnel
        if not tunnel or not tunnel.alive:
            return
        session = tunnel.sessions.get(sid)
        if isinstance(session, UDPSession) and not session.closed.is_set():
            session.relay.forward(packet)
            if self.node.metrics: self.node.metrics.counters["udp_received"] += 1


class Node:
    def __init__(self, token: str, socks_host="127.0.0.1", socks_port=1080,
                 mux_host="127.0.0.1", mux_port=9312,
                  udp_port=9314, frpc_udp_port=9313, protocol="rsx3",
                  diagnostics=False, frpc_diagnostics_addr="127.0.0.1:9320"):
        if len(token) < 16:
            raise ValueError("REVERSE_SOCKS_TOKEN must contain at least 16 characters")
        if protocol != "rsx3":
            raise ValueError("RSX3 is the only supported reverse SOCKS5 protocol")
        self.token = token.encode()
        self.metrics = diag.Metrics() if diagnostics else None
        self.frpc_diagnostics_addr = frpc_diagnostics_addr
        if self.metrics:
            diag.LocalFRPC(frpc_diagnostics_addr, diag.local_token(token))
            LOG.addHandler(self.metrics)
        self.protocol = protocol
        self.socks_addr = (socks_host, socks_port)
        self.mux_addr = (mux_host, mux_port)
        if socks_host != "127.0.0.1" or mux_host != "127.0.0.1":
            raise ValueError("SOCKS and XTCP service must remain on 127.0.0.1")
        if not 0 <= udp_port <= 65535 or not 1 <= frpc_udp_port <= 65535:
            raise ValueError("invalid UDP endpoints")
        self.udp_port_config = udp_port
        self.frpc_udp_port = frpc_udp_port
        self.tunnel = None
        self.socks_server = None
        self.mux_server = None
        self.udp_transport = None

    async def start(self):
        # The mux port is an internal frpc destination; do not expose it publicly.
        self.mux_server = await asyncio.start_server(self._accept_agent, *self.mux_addr)
        self.socks_server = await asyncio.start_server(self._socks_client, *self.socks_addr)
        loop = asyncio.get_running_loop()
        self.udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: DatagramLink(self, ("127.0.0.1", self.frpc_udp_port)),
            local_addr=("127.0.0.1", self.udp_port_config),
            family=socket.AF_INET)
        return self

    async def stop(self):
        if self.metrics: LOG.removeHandler(self.metrics)
        for server in (self.socks_server, self.mux_server):
            if server:
                server.close()
        if self.udp_transport:
            self.udp_transport.close()
        if self.tunnel:
            self.tunnel.writer.close()
            try:
                await asyncio.wait_for(self.tunnel.writer.wait_closed(), 3)
            except (ConnectionError, OSError, asyncio.TimeoutError):
                pass
        for server in (self.socks_server, self.mux_server):
            if server:
                try:
                    await asyncio.wait_for(server.wait_closed(), 3)
                except asyncio.TimeoutError:
                    LOG.warning("local listener shutdown still has closing connections")

    @property
    def socks_port(self):
        return self.socks_server.sockets[0].getsockname()[1]

    @property
    def mux_port(self):
        return self.mux_server.sockets[0].getsockname()[1]

    @property
    def udp_port(self):
        return self.udp_transport.get_extra_info("sockname")[1]

    def send_udp(self, sid: int, packet: bytes):
        try:
            data = p.encode_link_datagram(sid, packet)
        except ValueError:
            if self.metrics: self.metrics.udp_drops["invalid_or_oversize"] += 1
            raise
        self.udp_transport.sendto(data, ("127.0.0.1", self.frpc_udp_port))
        if self.metrics: self.metrics.counters["udp_sent"] += 1

    async def _accept_agent(self, reader, writer):
        try:
            # Each XTCP QUIC stream must identify its RSX3 purpose.
            preface = await asyncio.wait_for(reader.readexactly(4), 5)
            if preface == b"RSX3":
                await accept_control(self, reader, writer)
            elif preface == b"R3D1":
                await accept_data(self, reader, writer)
            elif preface == diag.PREFACE:
                await diag.accept_diagnostics(self, reader, writer)
            else:
                raise PermissionError("unsupported RSX3 stream preface / protocol version")
        except asyncio.IncompleteReadError:
            pass  # Empty XTCP keepalive stream.
        except (PermissionError, ConnectionError, asyncio.TimeoutError,
                OSError, ValueError) as exc:
            LOG.warning("RSX3 connection rejected: %s", exc)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    async def _socks_client(self, reader, writer):
        try:
            header = await asyncio.wait_for(reader.readexactly(2), 10)
            if header[0] != 5:
                return
            methods = await reader.readexactly(header[1])
            if 0 not in methods:
                writer.write(b"\x05\xff")
                await writer.drain()
                return
            writer.write(b"\x05\x00")
            await writer.drain()
            ver, command, reserved, atyp = await reader.readexactly(4)
            if ver != 5 or reserved:
                return
            try:
                host, port = await read_socks_address(reader, atyp)
            except ValueError:
                await socks_reply(writer, 8)
                return
            tunnel = self.tunnel
            if not tunnel or not tunnel.alive:
                await socks_reply(writer, 1)
            elif command == 1:
                await self._tcp_client(tunnel, host, port, reader, writer)
            elif command == 3:
                await self._udp_client(tunnel, reader, writer)
            else:
                await socks_reply(writer, 7)
        except (asyncio.IncompleteReadError, ConnectionError, OSError,
                asyncio.TimeoutError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    async def _tcp_client(self, tunnel, host, port, reader, writer):
        try:
            session = await tunnel.open_tcp(host, port)
        except (ConnectionError, OSError, asyncio.TimeoutError):
            await socks_reply(writer, 5)
            return
        try:
            await socks_reply(writer, 0)
            await bridge_tcp(session, reader, writer)
        finally:
            await tunnel.close_session(session)

    async def _udp_client(self, tunnel, reader, writer):
        allowed_ip = writer.get_extra_info("peername")[0]
        relay = UDPRelay(tunnel, allowed_ip)
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: relay, local_addr=("127.0.0.1", 0), family=socket.AF_INET)
        session = None
        replied = False
        try:
            session = await tunnel.open_udp(relay)
            relay.session = session
            await socks_reply(writer, 0, "127.0.0.1", transport.get_extra_info("sockname")[1])
            replied = True
            control = asyncio.create_task(reader.read(1))
            closed = asyncio.create_task(session.closed.wait())
            done, pending = await asyncio.wait((control, closed),
                                               return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            for task in done:
                task.result()
        except (ConnectionError, OSError, asyncio.TimeoutError):
            if not replied:
                await socks_reply(writer, 5)
        finally:
            if session:
                await tunnel.close_session(session)
            transport.close()


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="RSX3 per-TCP-stream QUIC + DATAGRAM SOCKS5 NAT node")
    parser.add_argument("--protocol", choices=("rsx3",), default="rsx3",
                        help="RSX3 independent XTCP/QUIC streams (only supported protocol)")
    parser.add_argument("--diagnostics", action="store_true", help="enable bounded diagnostics on a separate authenticated RSX3 stream")
    parser.add_argument("--log-level", choices=("debug", "info", "warning", "error"),
                        type=str.lower, default="warning",
                        help="console log verbosity (default: warning); independent of --diagnostics")
    parser.add_argument("--frpc-diagnostics", default="127.0.0.1:9320")
    parser.add_argument("--print-diagnostics-config", action="store_true", help="print local frpc diagnostics TOML; do not start listeners")
    parser.add_argument("--socks", default="127.0.0.1:1080", help="local SOCKS5 bind")
    parser.add_argument("--mux", default="127.0.0.1:9312", help="frpc XTCP proxy target")
    parser.add_argument("--udp-bind", default="127.0.0.1:9314",
                        help="Python RSX3 QUIC DATAGRAM socket (frpc datagram.peerAddr)")
    parser.add_argument("--udp-frpc", default="127.0.0.1:9313",
                        help="frpc datagram.listenAddr")
    return parser.parse_args(argv)


async def run(args=None):
    if args is None:
        args = parse_args()
    token = os.environ.get("REVERSE_SOCKS_TOKEN", "")
    if not token:
        raise SystemExit("set REVERSE_SOCKS_TOKEN")
    if args.print_diagnostics_config:
        diag.LocalFRPC(args.frpc_diagnostics, diag.local_token(token))
        print('diagnostics.enabled = true')
        print('diagnostics.listenAddr = ' + __import__('json').dumps(args.frpc_diagnostics))
        print('diagnostics.token = ' + __import__('json').dumps(diag.local_token(token)))
        return
    socks_host, socks_port = args.socks.rsplit(":", 1)
    mux_host, mux_port = args.mux.rsplit(":", 1)
    udp_host, udp_port = args.udp_bind.rsplit(":", 1)
    frpc_host, frpc_port = args.udp_frpc.rsplit(":", 1)
    if udp_host != "127.0.0.1" or frpc_host != "127.0.0.1":
        raise SystemExit("UDP endpoints must be 127.0.0.1")
    node = await Node(token, socks_host, int(socks_port),
                      mux_host, int(mux_port), int(udp_port),
                      int(frpc_port), protocol=args.protocol, diagnostics=args.diagnostics,
                      frpc_diagnostics_addr=args.frpc_diagnostics).start()
    LOG.info("%s SOCKS5 %s:%d; XTCP TCP %s:%d; DATAGRAM UDP 127.0.0.1:%d -> %d",
             args.protocol.upper(),
             socks_host, node.socks_port, mux_host, node.mux_port,
             node.udp_port, node.frpc_udp_port)
    async with node.socks_server, node.mux_server:
        await asyncio.gather(node.socks_server.serve_forever(),
                             node.mux_server.serve_forever())


def configure_logging(level="warning", diagnostics=False):
    """Keep console noise independent of optional in-memory Diagnostics.

    INFO/DEBUG records are preserved in Diagnostics reports when enabled,
    even when the console is configured to print WARNING and above.
    """
    console_level = getattr(logging, level.upper())
    console = logging.StreamHandler()
    console.setLevel(console_level)
    console.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logging.basicConfig(level=console_level, handlers=[console], force=True)
    LOG.setLevel(logging.DEBUG if diagnostics else console_level)


def main():
    args = parse_args()
    configure_logging(args.log_level, diagnostics=args.diagnostics)
    try:
        if os.name == "nt":
            # Python 3.13 Proactor's TCP shutdown callback can raise
            # WinError 10054 after a peer RST and skip socket cleanup.
            # Keep IOCP/Proactor capacity; patch only this loop's TCP teardown.
            from .windows_asyncio import RSX3WindowsProactorEventLoop
            with asyncio.Runner(loop_factory=RSX3WindowsProactorEventLoop) as runner:
                runner.run(run(args))
        else:
            asyncio.run(run(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
