"""RSX3: authenticated per-TCP XTCP/QUIC streams, UDP on control + DATAGRAM.

No direct outbound dialing occurs on the NAT node. A new Go-side Visitor
connection creates a distinct XTCP QUIC stream for every TCP CONNECT.
This code accepts connections only on the loopback-only Python mux port.
"""
import asyncio
import hashlib
import hmac
import logging
import secrets
import struct
import time

from . import protocol as p
from .scheduler import FairFrameWriter
from . import diagnostics as diag

LOG = logging.getLogger("reverse_socks")
CONTROL_PREFACE = b"RSX3"
DATA_PREFACE = b"R3D1"
CONTROL_DOMAIN = b"RSX3-control-v1"
DATA_DOMAIN = b"RSX3-data-v1"
CONTROL_ID_BYTES = 16
HANDSHAKE_SECONDS = 5
SLOW_SECONDS = 0.100


class TCPSessionV3:
    def __init__(self, sid: int):
        self.sid = sid
        self.result = asyncio.get_running_loop().create_future()
        self.reader = None
        self.writer = None
        self.closed = asyncio.Event()
        self.claimed = False
        self.metric = None
        self.metrics = None

    def fail(self, reason="RSX3 connection closed"):
        if not self.result.done():
            self.result.set_exception(ConnectionError(reason))
        self.closed.set()
        if self.writer:
            self.writer.close()


class TunnelV3:
    def __init__(self, reader, writer, node):
        self.reader = reader
        self.writer = writer
        self.node = node
        self.epoch = secrets.token_bytes(CONTROL_ID_BYTES)
        self.sender = FairFrameWriter(writer)
        self.sessions = {}
        self.next_id = secrets.randbelow(0xFFFFFFFF - 1)
        self.alive = True
        self.diagnostics_peer = None

    def register(self, kind, *args):
        # Imports here avoid a circular import with the RSX2 UDP implementation.
        from .node import MAX_SESSIONS
        if not self.alive or len(self.sessions) >= MAX_SESSIONS:
            raise ConnectionError("RSX3 tunnel closed or session limit reached")
        self.next_id = (self.next_id % 0xFFFFFFFF) + 1
        while self.next_id in self.sessions:
            self.next_id = (self.next_id % 0xFFFFFFFF) + 1
        session = kind(self.next_id, *args)
        self.sessions[session.sid] = session
        return session

    async def send(self, kind, sid, data=b""):
        if not self.alive:
            raise ConnectionError("RSX3 control channel closed")
        await self.sender.send(kind, sid, data)

    async def open_tcp(self, host, port):
        session = self.register(TCPSessionV3)
        session.metrics = self.node.metrics
        if session.metrics:
            session.metric = session.metrics.begin(self.epoch.hex(), session.sid, f"{host}:{port}")
        began = time.monotonic()
        try:
            await self.send(p.OPEN_TCP, session.sid, p.encode_address(host, port))
            await asyncio.wait_for(session.result, 12)
            if session.metrics: session.metrics.ready(session.metric)
            LOG.info("RSX3 metric open_tcp sid=%d confirm_ms=%.1f",
                     session.sid, (time.monotonic() - began) * 1000)
            return session
        except BaseException as exc:
            if session.metrics:
                session.metrics.fail(session.metric, exc, "open_tcp")
                session.metrics.finish(session.metric)
            await self.close_session(session)
            raise

    async def open_udp(self, relay):
        from .node import UDPSession
        session = self.register(UDPSession, relay)
        try:
            await self.send(p.OPEN_UDP, session.sid)
            await asyncio.wait_for(session.result, 12)
            session.diag_counted = True
            if self.node.metrics: self.node.metrics.counters["udp_active"] += 1
            return session
        except BaseException:
            await self.close_session(session)
            raise

    async def close_session(self, session, notify=True):
        if self.sessions.pop(session.sid, None) is not session:
            return
        session.fail()
        if not isinstance(session, TCPSessionV3) and self.node.metrics and getattr(session, "diag_counted", False):
            self.node.metrics.counters["udp_active"] = max(0, self.node.metrics.counters["udp_active"] - 1)
            session.diag_counted = False
        if notify and self.alive:
            try:
                await self.send(
                    p.TCP_RST if isinstance(session, TCPSessionV3) else p.UDP_CLOSE,
                    session.sid)
            except (ConnectionError, OSError):
                pass

    async def read_loop(self):
        from .node import UDPSession
        try:
            while self.alive:
                header = await self.reader.readexactly(p.HEADER.size)
                kind, sid, length = p.HEADER.unpack(header)
                if length > p.MAX_PAYLOAD:
                    raise ValueError("RSX3 control frame too large")
                data = await self.reader.readexactly(length)
                if kind == p.PING:
                    response = data
                    if self.node.metrics and data.startswith(diag.CAP_REQUEST) and len(data) == len(diag.CAP_REQUEST) + 32:
                        response = diag.CAP_REPLY + data[len(diag.CAP_REQUEST):]
                    await self.send(p.PONG, sid, response)
                    continue
                session = self.sessions.get(sid)
                if isinstance(session, TCPSessionV3):
                    if kind == p.TCP_RESULT:
                        if data != b"\x00":
                            session.fail("WARP CONNECT or RSX3 data stream failed")
                    elif kind == p.TCP_RST:
                        session.fail("peer reset RSX3 TCP")
                    else:
                        raise ValueError("RSX3 control must never carry TCP payload")
                elif isinstance(session, UDPSession):
                    if kind == p.UDP_RESULT:
                        session.ready(data)
                    elif kind == p.UDP_CLOSE:
                        session.fail()
                        self.sessions.pop(sid, None)
                        if self.node.metrics and getattr(session, "diag_counted", False):
                            self.node.metrics.counters["udp_active"] = max(0, self.node.metrics.counters["udp_active"] - 1)
                            session.diag_counted = False
                elif kind not in (p.PONG, p.TCP_RST):
                    LOG.debug("RSX3 unknown stale sid=%d kind=%d", sid, kind)
        except (asyncio.IncompleteReadError, ConnectionError, OSError, ValueError) as exc:
            LOG.info("RSX3 agent disconnected: %s", exc)
        finally:
            self.alive = False
            if self.node.metrics: self.node.metrics.counters["udp_active"] = 0
            if self.diagnostics_peer is not None:
                writer = getattr(self.diagnostics_peer, "writer", None)
                if writer: writer.close()
            for session in list(self.sessions.values()):
                session.fail()
            self.sessions.clear()
            await self.sender.close()
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except (ConnectionError, OSError):
                pass


async def authenticate_control(reader, writer, token: bytes):
    nonce = secrets.token_bytes(32)
    writer.write(nonce)
    await writer.drain()
    supplied = await asyncio.wait_for(reader.readexactly(32), HANDSHAKE_SECONDS)
    expected = hmac.digest(token, CONTROL_DOMAIN + nonce, hashlib.sha256)
    if not hmac.compare_digest(supplied, expected):
        raise PermissionError("RSX3 control HMAC authentication failed")


async def accept_control(node, reader, writer):
    await authenticate_control(reader, writer, node.token)
    if node.tunnel is not None and node.tunnel.alive:
        raise ConnectionError("RSX3 agent already connected")
    tunnel = TunnelV3(reader, writer, node)
    node.tunnel = tunnel
    if node.metrics: node.metrics.epoch = tunnel.epoch.hex()
    writer.write(b"\x00" + tunnel.epoch)
    await writer.drain()
    LOG.info("RSX3 control connected epoch=%s", tunnel.epoch.hex()[:8])
    try:
        await tunnel.read_loop()
    finally:
        if node.tunnel is tunnel:
            node.tunnel = None


async def accept_data(node, reader, writer):
    from .node import MAX_SESSIONS
    header = await asyncio.wait_for(reader.readexactly(CONTROL_ID_BYTES + 4),
                                    HANDSHAKE_SECONDS)
    epoch, sid_data = header[:CONTROL_ID_BYTES], header[CONTROL_ID_BYTES:]
    sid = struct.unpack("!I", sid_data)[0]
    tunnel = node.tunnel
    if not isinstance(tunnel, TunnelV3) or not tunnel.alive or epoch != tunnel.epoch:
        raise PermissionError("RSX3 data stream has no active control session")
    session = tunnel.sessions.get(sid)
    if not isinstance(session, TCPSessionV3) or session.closed.is_set() or session.claimed:
        raise PermissionError("RSX3 data stream has no pending authorized session")
    session.claimed = True
    nonce = secrets.token_bytes(32)
    writer.write(nonce)
    await writer.drain()
    supplied = await asyncio.wait_for(reader.readexactly(32), HANDSHAKE_SECONDS)
    expected = hmac.digest(node.token, DATA_DOMAIN + epoch + sid_data + nonce,
                           hashlib.sha256)
    if not hmac.compare_digest(supplied, expected) or not tunnel.alive:
        session.fail("RSX3 data authentication rejected")
        raise PermissionError("RSX3 data stream HMAC failed")
    writer.write(b"\x00")
    await writer.drain()
    session.reader, session.writer = reader, writer
    if session.metric is not None:
        local, remote = writer.get_extra_info("sockname"), writer.get_extra_info("peername")
        session.metric["local"] = f"{local[0]}:{local[1]}"
        session.metric["remote"] = f"{remote[0]}:{remote[1]}"
        session.metric["tuple_at"] = diag.utc()
    if not session.result.done():
        session.result.set_result(None)
    # The actual SOCKS handler owns this pair of sockets. Do not close it
    # until both stream-copy directions have completed (or the session failed).
    await session.closed.wait()


async def bridge_tcp(session, browser_reader, browser_writer):
    counters = [0, 0]
    max_drain = [0.0, 0.0]
    started = time.monotonic()

    async def pump(src, dst, direction):
        operation = "read"
        try:
            while True:
                operation = "read"
                read_start = time.monotonic()
                data = await src.read(p.TCP_CHUNK * 4)
                read_wait = time.monotonic() - read_start
                if not data: break
                if session.metric is not None: session.metric["raw_read_bytes"] += len(data)
                counters[direction] += len(data)
                operation = "write"
                dst.write(data)
                start = time.monotonic()
                await dst.drain()
                latency = time.monotonic() - start
                max_drain[direction] = max(max_drain[direction], latency)
                if session.metrics: session.metrics.progress(session.metric, direction, len(data), read_wait, latency)
                if latency > SLOW_SECONDS:
                    LOG.warning("RSX3 metric slow_drain sid=%d direction=%s drain_ms=%.1f",
                                session.sid, ("upload", "download")[direction],
                                latency * 1000)
            if dst.can_write_eof():
                dst.write_eof()
                await dst.drain()
        except (asyncio.IncompleteReadError, ConnectionError, OSError) as exc:
            if session.metrics: session.metrics.fail(session.metric, exc, f"{direction}:{operation}")
            LOG.info("RSX3 stream sid=%d direction=%d terminated: %s",
                     session.sid, direction, type(exc).__name__)
            # Make sure the other direction doesn't wait forever after a
            # failed socket write.
            dst.close()

    try:
        await asyncio.gather(
            pump(browser_reader, session.writer, 0),
            pump(session.reader, browser_writer, 1),
        )
    finally:
        if session.metrics: session.metrics.finish(session.metric)
        LOG.info("RSX3 metric tcp_summary sid=%d upload_bytes=%d download_bytes=%d "
                 "duration_ms=%.1f upload_drain_max_ms=%.1f download_drain_max_ms=%.1f",
                 session.sid, *counters, (time.monotonic() - started) * 1000,
                 max_drain[0] * 1000, max_drain[1] * 1000)
