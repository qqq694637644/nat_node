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

from . import protocol as p

LOG = logging.getLogger("reverse_socks")
MAX_SESSIONS = 1024
TCP_QUEUE = 32
UDP_QUEUE = 128


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
        self.queue = asyncio.Queue(maxsize=TCP_QUEUE)
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
        try:
            self.queue.put_nowait((kind, data))
        except asyncio.QueueFull:
            self.fail("TCP receiver too slow")


class UDPSession:
    def __init__(self, sid: int, relay):
        self.sid = sid
        self.relay = relay
        self.closed = asyncio.Event()

    def fail(self):
        self.closed.set()


class Tunnel:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.lock = asyncio.Lock()
        self.sessions: dict[int, TCPSession | UDPSession] = {}
        self.next_id = 0
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
        if len(data) > p.MAX_PAYLOAD:
            raise ValueError("frame too large")
        async with self.lock:
            self.writer.write(p.HEADER.pack(kind, sid, len(data)) + data)
            await self.writer.drain()

    async def open_tcp(self, host: str, port: int):
        session = self.register(TCPSession)
        try:
            await self.send(p.OPEN_TCP, session.sid, p.encode_address(host, port))
            await asyncio.wait_for(session.result, 12)
            return session
        except BaseException:
            await self.close_session(session, notify=True)
            raise

    async def open_udp(self, relay):
        session = self.register(UDPSession, relay)
        try:
            await self.send(p.OPEN_UDP, session.sid)
            return session
        except BaseException:
            self.sessions.pop(session.sid, None)
            session.fail()
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
                                                                 p.TCP_FIN, p.TCP_RST):
                    session.deliver(kind, data)
                    if session.closed:
                        self.sessions.pop(sid, None)
                elif isinstance(session, UDPSession):
                    if kind == p.UDP_DATA and not session.closed.is_set():
                        session.relay.forward(data)
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
        self.outgoing = asyncio.Queue(maxsize=UDP_QUEUE)

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
            self.outgoing.put_nowait(data)
        except (ValueError, asyncio.QueueFull):
            pass  # UDP drops instead of stalling the TCP mux.

    def forward(self, data: bytes):
        if not self.transport or self.peer is None:
            return
        try:
            p.parse_udp_packet(data)
        except ValueError:
            return
        self.transport.sendto(data, self.peer)

    async def send_loop(self):
        while not self.session.closed.is_set():
            data = await self.outgoing.get()
            await self.tunnel.send(p.UDP_DATA, self.session.sid, data)


class Node:
    def __init__(self, token: str, socks_host="127.0.0.1", socks_port=1080,
                 mux_host="127.0.0.1", mux_port=9312):
        if len(token) < 16:
            raise ValueError("REVERSE_SOCKS_TOKEN must contain at least 16 characters")
        self.token = token.encode()
        self.socks_addr = (socks_host, socks_port)
        self.mux_addr = (mux_host, mux_port)
        self.tunnel = None
        self.socks_server = None
        self.mux_server = None

    async def start(self):
        # The mux port is an internal frpc destination; do not expose it publicly.
        self.mux_server = await asyncio.start_server(self._accept_agent, *self.mux_addr)
        self.socks_server = await asyncio.start_server(self._socks_client, *self.socks_addr)
        return self

    async def stop(self):
        for server in (self.socks_server, self.mux_server):
            if server:
                server.close()
                await server.wait_closed()
        if self.tunnel:
            self.tunnel.writer.close()
            try:
                await self.tunnel.writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    @property
    def socks_port(self):
        return self.socks_server.sockets[0].getsockname()[1]

    @property
    def mux_port(self):
        return self.mux_server.sockets[0].getsockname()[1]

    async def _accept_agent(self, reader, writer):
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
            tunnel = Tunnel(reader, writer)
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

            async def client_to_exit():
                while data := await reader.read(p.TCP_CHUNK):
                    await tunnel.send(p.TCP_DATA, session.sid, data)
                await tunnel.send(p.TCP_FIN, session.sid)

            async def exit_to_client():
                while True:
                    kind, data = await session.queue.get()
                    if kind == p.TCP_RST:
                        raise ConnectionError("remote TCP stream reset")
                    if kind == p.TCP_FIN:
                        if writer.can_write_eof():
                            writer.write_eof()
                            await writer.drain()
                        return
                    writer.write(data)
                    await writer.drain()

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
        sender = None
        try:
            session = await tunnel.open_udp(relay)
            relay.session = session
            sender = asyncio.create_task(relay.send_loop())
            await socks_reply(writer, 0, "127.0.0.1", transport.get_extra_info("sockname")[1])
            control = asyncio.create_task(reader.read(1))
            closed = asyncio.create_task(session.closed.wait())
            done, pending = await asyncio.wait((control, closed),
                                               return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            for task in done:
                task.result()
        except (ConnectionError, OSError):
            pass
        finally:
            if session:
                await tunnel.close_session(session)
            if sender:
                sender.cancel()
                await asyncio.gather(sender, return_exceptions=True)
            transport.close()


async def run():
    parser = argparse.ArgumentParser(description="RSX1 reverse SOCKS5 NAT node")
    parser.add_argument("--socks", default="127.0.0.1:1080", help="local SOCKS5 bind")
    parser.add_argument("--mux", default="127.0.0.1:9312", help="frpc XTCP proxy target")
    args = parser.parse_args()
    token = os.environ.get("REVERSE_SOCKS_TOKEN", "")
    if not token:
        parser.error("set REVERSE_SOCKS_TOKEN")
    socks_host, socks_port = args.socks.rsplit(":", 1)
    mux_host, mux_port = args.mux.rsplit(":", 1)
    node = await Node(token, socks_host, int(socks_port),
                      mux_host, int(mux_port)).start()
    LOG.info("SOCKS5 at %s:%d; XTCP mux target at %s:%d",
             socks_host, node.socks_port, mux_host, node.mux_port)
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
