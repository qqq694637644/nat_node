"""Optional direct IPv6 QUIC transport for RSX3 (legacy FRP stays unchanged).

Requires aioquic. Authenticated RSX3 streams still use the original protocol.
"""
import asyncio
import logging
import socket
import struct

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import DatagramFrameReceived

from . import protocol as p
from . import diagnostics as diag
from .node import Node, UDPSession
from .rsx3 import TunnelV3, accept_data, authenticate_control

LOG = logging.getLogger("reverse_socks")


class DirectProtocol(QuicConnectionProtocol):
    def __init__(self, *args, node, **kwargs):
        self.node = node
        self.tasks = set()
        kwargs["stream_handler"] = self.stream_handler
        super().__init__(*args, **kwargs)

    def stream_handler(self, reader, writer):
        task = asyncio.create_task(self._run_stream(reader, writer))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    def connection_lost(self, exc):
        super().connection_lost(exc)
        self.node.protocols.discard(self)

    async def _run_stream(self, reader, writer):
        try:
            preface = await asyncio.wait_for(reader.readexactly(4), 5)
            if preface == b"RSX3":
                await self._control(reader, writer)
            elif preface == b"R3D1":
                if self.node.direct_owner is not self:
                    raise PermissionError("data stream on unauthenticated QUIC connection")
                await accept_data(self.node, reader, writer)
            else:
                raise PermissionError("unexpected RSX3 direct stream")
        except (asyncio.IncompleteReadError, PermissionError, ConnectionError,
                OSError, asyncio.TimeoutError, ValueError) as exc:
            LOG.info("direct QUIC stream terminated: %s", exc)
        finally:
            # aioquic's StreamWriter.wait_closed() can wait indefinitely for
            # peer stream completion after QUIC connection teardown (Windows
            # Proactor especially). Closing the stream is sufficient.
            writer.close()

    async def _control(self, reader, writer):
        await authenticate_control(reader, writer, self.node.token)
        if self.node.tunnel is not None and self.node.tunnel.alive:
            raise PermissionError("one RSX3 control connection at a time")
        tunnel = TunnelV3(reader, writer, self.node)
        self.node.tunnel = tunnel
        self.node.direct_owner = self
        writer.write(b"\x00" + tunnel.epoch)
        await writer.drain()
        try:
            await tunnel.read_loop()
        finally:
            if self.node.tunnel is tunnel:
                self.node.tunnel = None
                self.node.direct_owner = None

    def quic_event_received(self, event):
        super().quic_event_received(event)
        if not isinstance(event, DatagramFrameReceived) or self.node.direct_owner is not self:
            return
        try:
            sid, packet = p.decode_link_datagram(event.data)
        except ValueError:
            return
        tunnel = self.node.tunnel
        if tunnel and tunnel.alive:
            session = tunnel.sessions.get(sid)
            if isinstance(session, UDPSession) and not session.closed.is_set():
                session.relay.forward(packet)

    def send_rs_datagram(self, sid, packet):
        data = p.encode_link_datagram(sid, packet)
        self._quic.send_datagram_frame(data)
        self.transmit()


class DirectNode(Node):
    """A separate runtime instance; the original Node and XTCP remain intact."""

    def __init__(self, token, *, socks_host="127.0.0.1", socks_port=1080,
                 listen_host="::", listen_port=8080, cert_path, key_path):
        super().__init__(token, socks_host=socks_host, socks_port=socks_port)
        # Zero is supported for loopback integration tests (ephemeral port).
        if not 0 <= listen_port <= 65535:
            raise ValueError("invalid QUIC port")
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.cert_path = cert_path
        self.key_path = key_path
        self.quic_server = None
        self.direct_owner = None
        self.protocols = set()

    def _protocol(self, *args, **kwargs):
        p = DirectProtocol(*args, node=self, **kwargs)
        self.protocols.add(p)
        return p

    async def start(self):
        configuration = QuicConfiguration(is_client=False, alpn_protocols=["rsx3-direct-v1"],
                                          max_datagram_frame_size=1200)
        configuration.load_cert_chain(self.cert_path, self.key_path)
        self.socks_server = await asyncio.start_server(self._socks_client, *self.socks_addr)
        try:
            self.quic_server = await serve(
                self.listen_host, self.listen_port,
                configuration=configuration,
                create_protocol=self._protocol)
        except BaseException:
            self.socks_server.close()
            await self.socks_server.wait_closed()
            raise
        return self

    async def stop(self):
        if self.tunnel:
            self.tunnel.alive = False
            for session in list(self.tunnel.sessions.values()):
                session.fail()
            self.tunnel.writer.close()
        for protocol in tuple(self.protocols):
            protocol.close()
        if self.quic_server:
            self.quic_server.close()
        tasks = [task for protocol in self.protocols for task in protocol.tasks]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 4)
        if self.socks_server:
            self.socks_server.close()
            await self.socks_server.wait_closed()

    def send_udp(self, sid, packet):
        if not self.direct_owner or not self.tunnel or not self.tunnel.alive:
            raise ConnectionError("direct QUIC is disconnected")
        self.direct_owner.send_rs_datagram(sid, packet)
