import asyncio
import hashlib
import hmac
import io
import json
import logging
import secrets
import struct
from types import SimpleNamespace
import unittest
import zipfile

from reverse_socks import diagnostics as d
from reverse_socks.node import Node, UDPSession
from reverse_socks.rsx3 import TunnelV3, TCPSessionV3
from tests.test_real_frps_rsx3 import free_udp_port

TOKEN = "diagnostics-unit-test-secret-32-characters"


class DiagnosticsMetricsTests(unittest.TestCase):
    def test_metrics_counters_errors_and_bounds(self):
        m = d.Metrics()
        s = m.begin("epoch", 1, "original.example:443")
        self.assertEqual(m.snapshot()["metrics"]["active"], 1)
        self.assertIsNone(m.snapshot()["metrics"]["latency"]["p95"])
        m.ready(s)
        m.ready(s)
        m.progress(s, 1, 1234, .05, .2)
        m.fail(s, ConnectionResetError("original 203.0.113.1 reset"), "1:write")
        m.fail(s, BrokenPipeError("secondary"), "0:read")
        m.finish(s); m.finish(s)
        v = m.snapshot()
        self.assertEqual(v["metrics"]["success"], 1)
        self.assertEqual(v["metrics"]["closed"], 1)
        self.assertEqual(v["metrics"]["active"], 0)
        self.assertEqual(v["metrics"]["download_bytes"], 1234)
        self.assertEqual(v["sessions"][0]["close_code"], "reset")
        self.assertEqual(v["sessions"][0]["error"], "original 203.0.113.1 reset")
        for i in range(300):
            span = m.begin("epoch", i+2, "target:443")
            m.finish(span)
            m.event("test", "raw", "epoch")
        self.assertLessEqual(len(m.recent), 256)
        self.assertLessEqual(len(m.events), 256)

    def test_raw_logs_archive_and_local_scope(self):
        m = d.Metrics()
        record = logging.LogRecord("test", logging.WARNING, "source", 1,
                                   "203.0.113.44 real.example:443", (), None)
        m.emit(record)
        text = "\x1e" + json.dumps({"name": "transport:packet_sent", "address": "203.0.113.44"})
        archive = d.Peer._archive({"status": {"complete": True}, "qlogs": {"proxy:id": text}},
                                  m.snapshot(), list(m.logs))
        with zipfile.ZipFile(io.BytesIO(archive)) as z:
            self.assertIn(b"203.0.113.44 real.example:443", z.read("python.log"))
            self.assertEqual(z.read("proxyid.sqlog").decode(), text)
        for address in ("0.0.0.0:9320", "localhost:9320", "192.0.2.1:9320", "127.0.0.1:0"):
            with self.assertRaises(ValueError):
                d.LocalFRPC(address, d.local_token(TOKEN))
        expected = hmac.digest(TOKEN.encode(), b"rsx3-diagnostics-local-v1", "sha256").hex()
        self.assertEqual(d.local_token(TOKEN), expected)
        self.assertNotEqual(d.local_token(TOKEN), hashlib.sha256(TOKEN.encode()).hexdigest())


class DiagnosticsWireTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.node = await Node(TOKEN, socks_port=0, mux_port=0, udp_port=0,
                               frpc_udp_port=free_udp_port(), diagnostics=True,
                               frpc_diagnostics_addr="127.0.0.1:1").start()
        self.epoch = secrets.token_bytes(16)
        self.control = SimpleNamespace(alive=True, epoch=self.epoch, diagnostics_peer=None,
                                       diagnostics_ready=asyncio.Event())
        self.node.tunnel = self.control
        self.opened = []

    async def asyncTearDown(self):
        self.control.alive = False
        for writer in self.opened:
            writer.close()
        await asyncio.sleep(.02)
        self.node.tunnel = None
        await self.node.stop()

    async def connect(self, secret=TOKEN, epoch=None):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.node.mux_port)
        self.opened.append(writer)
        actual_epoch = self.epoch if epoch is None else epoch
        writer.write(d.PREFACE + actual_epoch)
        await writer.drain()
        nonce = await asyncio.wait_for(reader.readexactly(32), 1)
        writer.write(hmac.digest(secret.encode(), d.DOMAIN + actual_epoch + nonce, "sha256"))
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(1), 1), b"\0")
        return reader, writer

    async def rpc(self, reader, writer, method, params=None):
        ident = secrets.token_hex(16)
        request = json.dumps({"id": ident, "method": method, "params": params or {}}).encode()
        writer.write(struct.pack("!I", len(request)) + request)
        await writer.drain()
        response = await asyncio.wait_for(d.read_frame(reader), 3)
        self.assertEqual(response["id"], ident)
        return response

    async def test_authenticated_rpc_snapshot_and_unknown_methods(self):
        reader, writer = await self.connect()
        response = await self.rpc(reader, writer, "ping")
        self.assertEqual(response["result"]["schema"], d.SCHEMA)
        response = await self.rpc(reader, writer, "snapshot")
        self.assertEqual(response["result"]["frpc"]["state"], "unavailable")
        response = await self.rpc(reader, writer, "read_arbitrary_file", {"path": "/secret"})
        self.assertIn("unsupported", response["error"])
        self.assertIs(self.node.tunnel, self.control)

    async def test_bad_auth_stale_epoch_do_not_kill_business_control(self):
        with self.assertRaises((asyncio.IncompleteReadError, ConnectionError)):
            await self.connect(secret="wrong-authentication-token")
        with self.assertRaises((asyncio.IncompleteReadError, ConnectionError)):
            await self.connect(epoch=b"z"*16)
        reader, writer = await self.connect()
        self.assertIn("result", await self.rpc(reader, writer, "ping"))
        self.assertIs(self.node.tunnel, self.control)

    async def test_frame_size_and_second_peer_rejected(self):
        reader, writer = await self.connect()
        with self.assertRaises((asyncio.IncompleteReadError, ConnectionError)):
            await self.connect()
        writer.write(struct.pack("!I", 1 << 30))
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"")
        self.assertTrue(self.control.alive)

    async def test_cancelled_rpc_is_bounded(self):
        reader, writer = await self.connect()
        response = await self.rpc(reader, writer, "raw_benchmark", {"bytes": 1000000, "direction": "download"})
        self.assertIn("error", response)
        self.assertTrue(self.control.alive)

    async def test_peer_disconnect_revokes_readiness_without_killing_existing_sessions(self):
        # This is the real authenticated diagnostic stream, not a mock of
        # its .clear() call. The business control stays alive on disconnect.
        reader, writer = await self.connect()
        self.assertTrue(self.control.diagnostics_ready.is_set())
        self.control.node = self.node
        self.control.sessions = {}
        self.control.next_id = 0
        session_factory = lambda sid: SimpleNamespace(sid=sid)
        existing = TunnelV3.register(self.control, session_factory)
        writer.close()
        await writer.wait_closed()
        for _ in range(100):
            if self.control.diagnostics_peer is None and not self.control.diagnostics_ready.is_set():
                break
            await asyncio.sleep(.01)
        self.assertFalse(self.control.diagnostics_ready.is_set())
        self.assertIsNone(self.control.diagnostics_peer)
        self.assertTrue(self.control.alive)
        self.assertIn(existing.sid, self.control.sessions)
        with self.assertRaisesRegex(ConnectionError, "Diagnostics disconnected"):
            TunnelV3.register(self.control, TCPSessionV3)
        with self.assertRaisesRegex(ConnectionError, "Diagnostics disconnected"):
            TunnelV3.register(self.control, UDPSession, object())
        # A reauthenticated diagnostic stream alone re-enables new sessions.
        _, replacement = await self.connect()
        self.assertTrue(self.control.diagnostics_ready.is_set())
        self.assertNotEqual(TunnelV3.register(self.control, session_factory).sid, existing.sid)
        replacement.close()
        await replacement.wait_closed()


if __name__ == "__main__":
    unittest.main()
