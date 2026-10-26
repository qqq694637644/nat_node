"""Bounded Brutal QUIC sender for aioquic's existing congestion interface.

Mirrors the proven frp xtcpbrutal policy: a five-second ACK/loss sample,
conservative 80% ACK-ratio floor, hard maxMbps pacing, and an 8 MiB cwnd cap.
The original RSX3 framing, stream scheduler and SOCKS5 logic are untouched.

aioquic does not expose a public pacer registration API; restrict direct mode
to the pinned aioquic 1.7.0 and fail if its expected pacer API changes.
"""
from aioquic.quic.congestion.base import (
    QuicCongestionControl, register_congestion_control,
)
from aioquic.quic.recovery import QuicPacketPacer

MAX_SAFE_MBPS = 73786
MIN_CWND = 16 * 1024
MAX_CWND = 8 * 1024 * 1024
MIN_ACK_RATIO = 0.8
MIN_SAMPLES = 50
SAMPLE_SECONDS = 5


def validate_rates(target_mbps: int, max_mbps: int) -> None:
    if not (1 <= target_mbps <= max_mbps <= MAX_SAFE_MBPS):
        raise ValueError(
            f"Brutal requires 1 <= targetMbps <= maxMbps <= {MAX_SAFE_MBPS}"
        )


class BrutalCongestionControl(QuicCongestionControl):
    def __init__(self, *, max_datagram_size, target_mbps, max_mbps):
        validate_rates(target_mbps, max_mbps)
        super().__init__(max_datagram_size=max_datagram_size)
        self.target_bytes_per_second = target_mbps * 125_000
        self.max_bytes_per_second = max_mbps * 125_000
        self._rtt = 0.1
        # Same five one-second slots used by the existing frpc Brutal sender.
        # Fixed-size storage avoids one Python object allocation per packet.
        self._samples = [(-1, 0, 0)] * SAMPLE_SECONDS
        self._ack_count = 0
        self._loss_count = 0
        self._update_window()

    @property
    def rate(self):
        count = self._ack_count + self._loss_count
        ratio = (max(MIN_ACK_RATIO, self._ack_count / count)
                 if count >= MIN_SAMPLES else 1.0)
        return min(self.max_bytes_per_second,
                   int(self.target_bytes_per_second / ratio))

    def _sample(self, now, *, acked=0, lost=0):
        second = int(now)
        slot = second % SAMPLE_SECONDS
        at, a, l = self._samples[slot]
        if at != second:
            a, l = 0, 0
        self._samples[slot] = second, a + acked, l + lost
        self._ack_count = self._loss_count = 0
        for at, a, l in self._samples:
            if 0 <= second - at < SAMPLE_SECONDS:
                self._ack_count += a
                self._loss_count += l
        self._update_window()

    def _update_window(self):
        self.congestion_window = max(
            MIN_CWND,
            min(MAX_CWND, int(self.rate * max(self._rtt, 0.001) * 2))
        )

    def on_packet_sent(self, *, packet):
        self.bytes_in_flight += packet.sent_bytes

    def on_packet_acked(self, *, now, packet):
        self.bytes_in_flight = max(0, self.bytes_in_flight - packet.sent_bytes)
        self._sample(now, acked=1)

    def on_packets_lost(self, *, now, packets):
        lost = list(packets)
        self.bytes_in_flight = max(
            0, self.bytes_in_flight - sum(p.sent_bytes for p in lost)
        )
        self._sample(now, lost=len(lost))

    def on_packets_expired(self, *, packets):
        self.bytes_in_flight = max(
            0, self.bytes_in_flight - sum(p.sent_bytes for p in packets)
        )

    def on_persistent_congestion(self):
        # Bounded Brutal uses pacing rather than Reno/Cubic loss reduction.
        pass

    def on_rtt_measurement(self, *, now, rtt):
        if rtt > 0:
            self._rtt = rtt
            self._update_window()


class BrutalPacer(QuicPacketPacer):
    """The actual wire pacer: QUIC packets/retransmits share one rate cap."""
    def __init__(self, *, max_datagram_size, sender):
        super().__init__(max_datagram_size=max_datagram_size)
        self._sender = sender
        self.update_rate(congestion_window=0, smoothed_rtt=0)

    def update_rate(self, congestion_window, smoothed_rtt):
        # aioquic's default pacer derives rate from cwnd / RTT, which is
        # incorrect for Brutal: use its explicit bounded packet rate instead.
        rate = self._sender.rate
        self.packet_time = self._max_datagram_size / rate
        self.bucket_max = max(10 * self._max_datagram_size / rate, 0.004)
        self.bucket_time = min(self.bucket_time, self.bucket_max)


def install_brutal(quic_connection, target_mbps, max_mbps):
    """Configure both congestion control and pacing; never silently use CUBIC."""
    recovery = getattr(quic_connection, "_loss", None)
    if recovery is None or not hasattr(recovery, "_cc") or not hasattr(recovery, "_pacer"):
        raise RuntimeError("Unsupported aioquic internals: refusing CUBIC fallback")
    sender = recovery._cc
    if not isinstance(sender, BrutalCongestionControl):
        raise RuntimeError("Brutal control not installed: refusing CUBIC fallback")
    if sender.target_bytes_per_second != target_mbps * 125_000 or (
            sender.max_bytes_per_second != max_mbps * 125_000):
        raise RuntimeError("Brutal parameters do not match connection")
    recovery._pacer = BrutalPacer(max_datagram_size=quic_connection._configuration.max_datagram_size,
                                  sender=sender)
    return sender


def register_brutal(target_mbps, max_mbps):
    validate_rates(target_mbps, max_mbps)
    name = f"rsx3-brutal-{target_mbps}-{max_mbps}"
    register_congestion_control(
        name,
        lambda *, max_datagram_size: BrutalCongestionControl(
            max_datagram_size=max_datagram_size,
            target_mbps=target_mbps,
            max_mbps=max_mbps,
        ),
    )
    return name
