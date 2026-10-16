import unittest

from reverse_socks import protocol as p


class ProtocolTest(unittest.TestCase):
    def test_address_round_trip(self):
        for host, port in (("127.0.0.1", 53), ("2001:db8::1", 443),
                           ("example.com", 65535), ("xn--bcher-kva.de", 80)):
            with self.subTest(host=host):
                raw = p.encode_address(host, port)
                self.assertEqual(p.decode_address(raw), (host, port, len(raw)))

    def test_udp_round_trip(self):
        for host in ("127.0.0.1", "::1", "dns.example.com"):
            raw = p.udp_packet(host, 53, b"\x00\x01test")
            self.assertEqual(p.parse_udp_packet(raw), (host, 53, b"\x00\x01test"))

    def test_fragmented_udp_is_rejected(self):
        packet = bytearray(p.udp_packet("127.0.0.1", 53, b"x"))
        packet[2] = 1
        with self.assertRaises(ValueError):
            p.parse_udp_packet(packet)

    def test_invalid_frame_and_address(self):
        with self.assertRaises(ValueError):
            p.encode_address("example.com", -1)
        with self.assertRaises(ValueError):
            p.decode_address(b"\x02")
        with self.assertRaises(ValueError):
            p.udp_packet("127.0.0.1", 53, b"x" * p.MAX_PAYLOAD)
