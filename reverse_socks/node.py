"""Local SOCKS5 endpoint and multiplexed reverse channel for the outside Go agent."""

import argparse
import asyncio
import hashlib
import hmac
import ipaddress
import logging
import os
import secrets
import socket
import struct
import time

from . import protocol as p
from .scheduler import FairFrameWriter
from .rsx3 import TCPSessionV3, TunnelV3, accept_control, accept_data, bridge_tcp

LOG = logging.getLogger("reverse_socks")
MAX_SESSIONS = 1024
TCP_QUEUE = 32
TCP_WINDOW = 32
TCP_WINDOW_BATCH = 8


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


class TCPSession:
    def __init__(self, sid: int):
        self.sid = sid
        # 32 outstanding DATA frames plus room for FIN/RST.
        self.queue = asyncio.Queue(maxsize=TCP_QUEUE + 2)
        self.credits = asyncio.BoundedSemaphore(TCP_WINDOW)
        self.result = asyncio.get_running_loop().create_future()
        self.closed = False

    def fail(self, reason="tunnel disconnected"):
        if self.closed:
            return
        self.closed = True
        if not self.result.done():
            self.result.set_exception(ConnectionError(reason))
        # Never block the entire mux on a stalled SOCKS client.
        while not self.queue.empty():
            self.queue.get_nowait()
        self.queue.put_nowait((p.TCP_RST, b""))

    def deliver(self, kind: int, data: bytes):
        if self.closed:
            return
        if kind == p.TCP_RESULT:
            if not self.result.done():
                if data == b"\x00":
                    self.result.set_result(None)
                else:
                    self.result.set_exception(ConnectionError("remote TCP dial failed"))
            return
        if kind == p.TCP_RST:
            self.fail("remote reset")
            return
        if kind == p.TCP_WINDOW:
            if len(data) != 2:
                self.fail("invalid TCP window update")
                return
            count = struct.unpack("!H", data)[0]
            if not 1 <= count <= TCP_WINDOW:
                self.fail("invalid TCP window credit count")
                return
            try:
                for _ in range(count):
                    self.credits.release()
            except ValueError:
                self.fail("unexpected TCP window update")
            return
        try:
            self.queue.put_nowait((kind, data))
        except asyncio.QueueFull:
            self.fail("peer violated TCP receive window")


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


class Tunnel:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 node):
        self.reader = reader
        self.writer = writer
        self.node = node
        self.sender = FairFrameWriter(writer)
        self.sessions: dict[int, TCPSession | UDPSession] = {}
        self.next_id = secrets.randbelow(0xFFFFFFFF - 1)
        self.alive = True

    def register(self, session_type, *args):
        if not self.alive or len(self.sessions) >= MAX_SESSIONS:
            raise ConnectionError("tunnel unavailable or session limit reached")
        self.next_id = (self.next_id % 0xFFFFFFFF) + 1
        while self.next_id in self.sessions:
            self.next_id = (self.next_id % 0xFFFFFFFF) + 1
        session = session_type(self.next_id, *args)
        self.sessions[session.sid] = session
        return session

    async def send(self, kind: int, sid: int, data=b""):
        if not self.alive:
            raise ConnectionError("tunnel closed")
        await self.sender.send(kind, sid, data)

    async def open_tcp(self, host: str, port: int):
        session = self.register(TCPSession)
        started = time.monotonic()
        try:
            await self.send(p.OPEN_TCP, session.sid, p.encode_address(host, port))
            await asyncio.wait_for(session.result, 12)
            LOG.info("RSX2 metric open_tcp sid=%d confirm_ms=%.1f",
                     session.sid, (time.monotonic() - started) * 1000)
            return session
        except BaseException:
            await self.close_session(session, notify=True)
            raise

    async def open_udp(self, relay):
        session = self.register(UDPSession, relay)
        try:
            await self.send(p.OPEN_UDP, session.sid)
            await asyncio.wait_for(session.result, 12)
            return session
        except BaseException:
            await self.close_session(session)
            raise

    async def close_session(self, session, notify: bool = True):
        if self.sessions.pop(session.sid, None) is not session:
            return
        if isinstance(session, TCPSession):
            session.fail("session closed")
        else:
            session.fail()
        if notify and self.alive:
            try:
                await self.send(p.TCP_RST if isinstance(session, TCPSession) else p.UDP_CLOSE,
                                session.sid)
            except (ConnectionError, OSError):
                pass

    async def read_loop(self):
        try:
            while self.alive:
                header = await self.reader.readexactly(p.HEADER.size)
                kind, sid, length = p.HEADER.unpack(header)
                if length > p.MAX_PAYLOAD:
                    raise ValueError("frame length exceeds limit")
                data = await self.reader.readexactly(length)
                if kind == p.PING:
                    await self.send(p.PONG, sid, data)
                    continue
                session = self.sessions.get(sid)
                if isinstance(session, TCPSession) and kind in (p.TCP_RESULT, p.TCP_DATA,
                                                                 p.TCP_FIN, p.TCP_RST, p.TCP_WINDOW):
                    session.deliver(kind, data)
                    if session.closed:
                        self.sessions.pop(sid, None)
                elif isinstance(session, UDPSession):
                    if kind == p.UDP_RESULT:
                        session.ready(data)
                    elif kind == p.UDP_CLOSE:
                        session.fail()
                        self.sessions.pop(sid, None)
        except (asyncio.IncompleteReadError, ConnectionError, OSError, ValueError) as exc:
            LOG.info("exit agent disconnected: %s", exc)
        finally:
            self.alive = False
            for session in list(self.sessions.values()):
                session.fail()
            self.sessions.clear()
            await self.sender.close()
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except (ConnectionError, OSError):
                pass


class UDPRelay(asyncio.DatagramProtocol):
    def __init__(self, tunnel: Tunnel, allowed_ip: str):
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
            return
        try:
            sid, packet = p.decode_link_datagram(data)
        except ValueError:
            return
        tunnel = self.node.tunnel
        if not tunnel or not tunnel.alive:
            return
        session = tunnel.sessions.get(sid)
        if isinstance(session, UDPSession) and not session.closed.is_set():
            session.relay.forward(packet)


class Node:
    def __init__(self, token: str, socks_host="127.0.0.1", socks_port=1080,
                 mux_host="127.0.0.1", mux_port=9312,
                  udp_port=9314, frpc_udp_port=9313, protocol="rsx3"):
        if len(token) < 16:
            raise ValueError("REVERSE_SOCKS_TOKEN must contain at least 16 characters")
        self.token = token.encode()
        if protocol not in ("rsx2", "rsx3"):
            raise ValueError("protocol must be rsx2 or rsx3")
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
        for server in (self.socks_server, self.mux_server):
            if server:
                server.close()
                await server.wait_closed()
        if self.udp_transport:
            self.udp_transport.close()
        if self.tunnel:
            self.tunnel.writer.close()
            try:
                await asyncio.wait_for(self.tunnel.writer.wait_closed(), 3)
            except (ConnectionError, OSError, asyncio.TimeoutError):
                pass

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
        data = p.encode_link_datagram(sid, packet)
        self.udp_transport.sendto(data, ("127.0.0.1", self.frpc_udp_port))

    async def _accept_agent(self, reader, writer):
        if self.protocol == "rsx3":
            try:
                # A real RSX3 connection identifies its purpose first.
                # The frpc QUIC keepalive opens and closes an empty stream,
                # which must not flood the logs with false auth failures.
                preface = await asyncio.wait_for(reader.readexactly(4), 5)
                if preface == b"RSX3":
                    await accept_control(self, reader, writer)
                elif preface == b"R3D1":
                    await accept_data(self, reader, writer)
                else:
                    raise PermissionError("unrecognized RSX3 stream preface")
            except asyncio.IncompleteReadError:
                pass  # frpc's zero-byte keepalive test, not an Agent failure
            except (PermissionError, ConnectionError, asyncio.TimeoutError,
                    OSError, ValueError) as exc:
                LOG.warning("RSX3 connection rejected: %s", exc)
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionError, OSError):
                    pass
            return
        challenge = secrets.token_bytes(32)
        try:
            writer.write(p.MAGIC + challenge)
            await writer.drain()
            supplied = await asyncio.wait_for(reader.readexactly(32), 5)
            expected = hmac.digest(self.token, challenge, hashlib.sha256)
            if not hmac.compare_digest(supplied, expected):
                raise PermissionError("invalid agent token")
            if self.tunnel is not None and self.tunnel.alive:
                raise ConnectionError("agent already connected")
            tunnel = Tunnel(reader, writer, self)
            self.tunnel = tunnel
            LOG.info("exit agent connected")
            await tunnel.read_loop()
        except (PermissionError, ConnectionError, asyncio.TimeoutError,
                asyncio.IncompleteReadError, OSError) as exc:
            LOG.warning("reject/close agent: %s", exc)
        finally:
            if self.tunnel is not None and self.tunnel.writer is writer:
                self.tunnel = None
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
            if isinstance(session, TCPSessionV3):
                await bridge_tcp(session, reader, writer)
                return

            async def client_to_exit():
                while True:
                    # Keep application reads behind the opposite endpoint's
                    # actual drain rate; don't reset legitimate slow streams.
                    started_wait = time.monotonic()
                    await session.credits.acquire()
                    waited = time.monotonic() - started_wait
                    if waited > 0.100:
                        LOG.warning("RSX2 metric window_wait sid=%d wait_ms=%.1f",
                                    session.sid, waited * 1000)
                    data = await reader.read(p.TCP_CHUNK)
                    if not data:
                        break
                    await tunnel.send(p.TCP_DATA, session.sid, data)
                await tunnel.send(p.TCP_FIN, session.sid)

            async def exit_to_client():
                credits_ready = 0
                while True:
                    kind, data = await session.queue.get()
                    if kind == p.TCP_RST:
                        raise ConnectionError("remote TCP stream reset")
                    if kind == p.TCP_FIN:
                        if credits_ready:
                            await tunnel.send(p.TCP_WINDOW, session.sid,
                                              struct.pack("!H", credits_ready))
                        if writer.can_write_eof():
                            writer.write_eof()
                            await writer.drain()
                        return
                    writer.write(data)
                    drain_started = time.monotonic()
                    await writer.drain()
                    drain_waited = time.monotonic() - drain_started
                    if drain_waited > 0.100:
                        LOG.warning("RSX2 metric browser_drain sid=%d drain_ms=%.1f",
                                    session.sid, drain_waited * 1000)
                    credits_ready += 1
                    if credits_ready >= TCP_WINDOW_BATCH:
                        await tunnel.send(p.TCP_WINDOW, session.sid,
                                          struct.pack("!H", credits_ready))
                        credits_ready = 0

            tasks = [asyncio.create_task(client_to_exit()),
                     asyncio.create_task(exit_to_client())]
            try:
                await asyncio.gather(*tasks)
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        except (ConnectionError, OSError, asyncio.IncompleteReadError):
            pass
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


async def run():
    parser = argparse.ArgumentParser(description="RSX3 per-TCP-stream QUIC + DATAGRAM SOCKS5 NAT node")
    parser.add_argument("--protocol", choices=("rsx3", "rsx2"), default="rsx3",
                        help="RSX3 independent XTCP/QUIC streams (default), RSX2 legacy control mux")
    parser.add_argument("--socks", default="127.0.0.1:1080", help="local SOCKS5 bind")
    parser.add_argument("--mux", default="127.0.0.1:9312", help="frpc XTCP proxy target")
    parser.add_argument("--udp-bind", default="127.0.0.1:9314",
                        help="Python RSX2 datagram socket (frpc datagram.peerAddr)")
    parser.add_argument("--udp-frpc", default="127.0.0.1:9313",
                        help="frpc datagram.listenAddr")
    args = parser.parse_args()
    token = os.environ.get("REVERSE_SOCKS_TOKEN", "")
    if not token:
        parser.error("set REVERSE_SOCKS_TOKEN")
    socks_host, socks_port = args.socks.rsplit(":", 1)
    mux_host, mux_port = args.mux.rsplit(":", 1)
    udp_host, udp_port = args.udp_bind.rsplit(":", 1)
    frpc_host, frpc_port = args.udp_frpc.rsplit(":", 1)
    if udp_host != "127.0.0.1" or frpc_host != "127.0.0.1":
        parser.error("UDP endpoints must be 127.0.0.1")
    node = await Node(token, socks_host, int(socks_port),
                      mux_host, int(mux_port), int(udp_port),
                      int(frpc_port), protocol=args.protocol).start()
    LOG.info("%s SOCKS5 %s:%d; XTCP TCP %s:%d; DATAGRAM UDP 127.0.0.1:%d -> %d",
             args.protocol.upper(),
             socks_host, node.socks_port, mux_host, node.mux_port,
             node.udp_port, node.frpc_udp_port)
    async with node.socks_server, node.mux_server:
        await asyncio.gather(node.socks_server.serve_forever(),
                             node.mux_server.serve_forever())


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
