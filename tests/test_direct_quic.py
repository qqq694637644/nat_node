"""Direct QUIC smoke test, separate from the stdlib-only legacy tests.

Run with: python -m pip install -r requirements-direct-quic.txt
          python -m unittest -v tests.test_direct_quic
"""
import asyncio
import datetime
import hashlib
import hmac
import secrets
import ssl
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

try:
    from aioquic.asyncio import connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import DatagramFrameReceived
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    connect = None

from reverse_socks.protocol import encode_link_datagram, udp_packet
from reverse_socks.rsx3 import TCPSessionV3
from reverse_socks.node import UDPSession
from reverse_socks.brutal import (
    BrutalCongestionControl, BrutalPacer, validate_rates, MAX_CWND, MIN_CWND
)

TOKEN = "direct-quic-test-secret-long-enough"


class TestProtocol(QuicConnectionProtocol):
    __test__ = False
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datagrams = asyncio.Queue()

    def quic_event_received(self, event):
        super().quic_event_received(event)
        if isinstance(event, DatagramFrameReceived):
            self.datagrams.put_nowait(event.data)


def make_cert(path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rsx3.example.test")])
    cert = (x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("rsx3.example.test")]), critical=False)
        .sign(key, hashes.SHA256()))
    (path / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (path / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                     serialization.PrivateFormat.PKCS8,
                                                     serialization.NoEncryption()))


@unittest.skipUnless(connect is not None, "aioquic optional dependency not installed")
class DirectQuicTest(unittest.IsolatedAsyncioTestCase):
    def test_brutal_bounds_and_actual_pacer(self):
        with self.assertRaises(ValueError):
            validate_rates(0, 24)
        with self.assertRaises(ValueError):
            validate_rates(25, 24)
        cc = BrutalCongestionControl(max_datagram_size=1200,
                                     target_mbps=16, max_mbps=24)
        self.assertEqual(cc.congestion_window, MIN_CWND)
        self.assertEqual(cc.rate, 16 * 125_000)
        cc.on_rtt_measurement(now=1, rtt=3)
        self.assertLessEqual(cc.congestion_window, MAX_CWND)
        pkt = SimpleNamespace(sent_bytes=1200)
        for _ in range(50):
            cc.on_packet_sent(packet=pkt)
        for _ in range(25):
            cc.on_packet_acked(now=2, packet=pkt)
        cc.on_packets_lost(now=2, packets=[pkt] * 25)
        self.assertEqual(cc.rate, 20 * 125_000)  # 50% ACK clamped at 80%
        pacer = BrutalPacer(max_datagram_size=1200, sender=cc)
        self.assertAlmostEqual(pacer.packet_time, 1200 / cc.rate, places=8)
        self.assertLessEqual(cc.rate, cc.max_bytes_per_second)

    async def test_authenticated_streams_and_datagram(self):
        from reverse_socks.direct_quic import DirectNode
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            make_cert(path)
            node = await DirectNode(TOKEN, socks_port=0, listen_host="::1",
                                    listen_port=0, cert_path=str(path / "cert.pem"),
                                    key_path=str(path / "key.pem")).start()
            try:
                port = node.quic_server._transport.get_extra_info("sockname")[1]
                cfg = QuicConfiguration(is_client=True,
                                        alpn_protocols=["rsx3-direct-v1"],
                                        max_datagram_frame_size=1200)
                cfg.verify_mode = ssl.CERT_NONE
                async with connect("::1", port, configuration=cfg,
                                   create_protocol=TestProtocol) as client:
                    direct = next(iter(node.protocols))
                    self.assertIsInstance(direct.brutal_sender, BrutalCongestionControl)
                    self.assertIsInstance(direct._quic._loss._pacer, BrutalPacer)
                    reader, writer = await client.create_stream()
                    writer.write(b"RSX3")
                    await writer.drain()
                    challenge = await asyncio.wait_for(reader.readexactly(32), 5)
                    writer.write(hmac.digest(TOKEN.encode(), b"RSX3-control-v1" + challenge,
                                              hashlib.sha256))
                    await writer.drain()
                    response = await asyncio.wait_for(reader.readexactly(17), 5)
                    self.assertEqual(response[0], 0)
                    epoch = response[1:]
                    tunnel = node.tunnel
                    self.assertTrue(tunnel.alive)

                    session = tunnel.register(TCPSessionV3)
                    data_reader, data_writer = await client.create_stream()
                    sid = struct.pack("!I", session.sid)
                    data_writer.write(b"R3D1" + epoch + sid)
                    await data_writer.drain()
                    nonce = await asyncio.wait_for(data_reader.readexactly(32), 5)
                    data_writer.write(hmac.digest(TOKEN.encode(), b"RSX3-data-v1" + epoch + sid + nonce,
                                                   hashlib.sha256))
                    await data_writer.drain()
                    self.assertEqual(await data_reader.readexactly(1), b"\x00")
                    await asyncio.wait_for(session.result, 5)
                    await tunnel.close_session(session)
                    data_writer.close()

                    class FakeRelay:
                        def __init__(self): self.data = []
                        def forward(self, data): self.data.append(data)
                    relay = FakeRelay()
                    udp = tunnel.register(UDPSession, relay)
                    udp.ready(b"\x00")
                    await udp.result
                    packet = udp_packet("1.1.1.1", 53, b"test")
                    client._quic.send_datagram_frame(encode_link_datagram(udp.sid, packet))
                    client.transmit()
                    await asyncio.sleep(0.15)
                    self.assertEqual(relay.data, [packet])

                    node.send_udp(udp.sid, packet)
                    received = await asyncio.wait_for(client.datagrams.get(), 5)
                    self.assertEqual(received, encode_link_datagram(udp.sid, packet))
                    await tunnel.close_session(udp)
                    writer.close()
            finally:
                await node.stop()


if __name__ == "__main__":
    unittest.main()
