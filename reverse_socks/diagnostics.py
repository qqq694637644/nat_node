"""Opt-in RSX diagnostics over a separately authenticated XTCP stream.

No new public listener, target resolver, or out-of-tunnel network request is
introduced here. Local frpc HTTP ignores environment proxy settings. Reports
retain original addresses/logs; no secret files or payloads are harvested.
"""
import asyncio
import base64
from collections import Counter, deque
from datetime import datetime, timezone
import hashlib
import hmac
import http.client
import io
import json
import logging
import math
import os
from pathlib import Path
import secrets
import socket
import struct
import sys
import threading
import time
import zipfile

from . import protocol as p

SCHEMA = "rsx-diagnostics/1"
PREFACE = b"R3G1"
DOMAIN = b"RSX3-diag-v1"
CAP_REQUEST = b"RD-CAP/2 "
CAP_REPLY = b"RD-OK/2 "
MAX_FRAME = 65535
MAX_HISTORY = 256
MAX_BENCH = 50_000_000


def utc():
    return datetime.now(timezone.utc).isoformat()


def local_token(token):
    if isinstance(token, str):
        token = token.encode()
    return hmac.digest(token, b"rsx3-diagnostics-local-v1", "sha256").hex()


def error_code(exc):
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return "timeout"
    if isinstance(exc, ConnectionResetError):
        return "reset"
    if isinstance(exc, BrokenPipeError):
        return "broken_pipe"
    if isinstance(exc, asyncio.CancelledError):
        return "cancelled"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    return "io_error"


class Metrics(logging.Handler):
    def __init__(self):
        super().__init__()
        self.process_id = secrets.token_hex(16)
        self.started = utc()
        self.start_mono = time.monotonic()
        self.epoch = None
        self.active = {}
        self.recent = deque(maxlen=MAX_HISTORY)
        self.events = deque(maxlen=MAX_HISTORY)
        self.logs = deque(maxlen=MAX_HISTORY)
        self.counters = Counter()
        self.errors = Counter()
        self.udp_drops = Counter()
        self.latencies = deque(maxlen=2048)
        self.log_lock = threading.Lock()
        self.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))

    def emit(self, record):
        # No redaction; cap each record and record truncation explicitly.
        text = self.format(record)
        if len(text) > 4096:
            text = text[:4096] + " [diagnostic record size limit]"
        with self.log_lock:
            self.logs.append(text)

    def begin(self, epoch, sid, target):
        key = f"{epoch}/{sid}"
        span = {"key": key, "epoch": epoch, "sid": sid, "target": target,
                "opened": utc(), "_started": time.monotonic(), "state": "opening",
                "upload_bytes": 0, "download_bytes": 0, "raw_read_bytes": 0,
                "max_write_ms": 0.0, "read_wait_ms": 0.0, "write_wait_ms": 0.0}
        self.counters["attempts"] += 1
        if len(self.active) >= 1024:
            self.errors["telemetry_capacity"] += 1
            return None
        self.active[key] = span
        return span

    def ready(self, span):
        if span is None or span["state"] != "opening":
            return
        span["state"] = "active"
        span["confirm_ms"] = (time.monotonic() - span["_started"]) * 1000
        self.latencies.append((time.monotonic(), span["confirm_ms"]))
        self.counters["success"] += 1

    def event(self, code, detail, key=""):
        self.events.append({"time": utc(), "component": "python", "code": code,
                            "detail": str(detail), "session": key})

    def fail(self, span, exc, operation):
        if span is None:
            return
        if "close_code" not in span:
            span["close_code"] = error_code(exc)
            span["error"] = str(exc) or type(exc).__name__
            span["operation"] = operation
            self.event(span["close_code"], span["error"], span["key"])

    def finish(self, span):
        if span is None or span["key"] not in self.active:
            return
        if span["state"] == "opening":
            self.counters["failures"] += 1
        self.active.pop(span["key"], None)
        span["state"] = "closed"
        span["closed"] = utc()
        span["duration_ms"] = (time.monotonic() - span["_started"]) * 1000
        span.setdefault("close_code", "eof")
        if span["close_code"] != "eof":
            self.errors[span["close_code"]] += 1
        self.counters["closed"] += 1
        self.recent.append(span.copy())

    def progress(self, span, direction, n, read_seconds, write_seconds):
        if span is None:
            return
        key = "upload_bytes" if direction == 0 else "download_bytes"
        span[key] += n
        self.counters[key] += n
        span["read_wait_ms"] += read_seconds * 1000
        span["write_wait_ms"] += write_seconds * 1000
        span["max_write_ms"] = max(span["max_write_ms"], write_seconds * 1000)
        if write_seconds > .100:
            self.counters["slow_write"] += 1

    def snapshot(self, limit=32):
        now = time.monotonic()
        values = sorted(ms for at, ms in self.latencies if now - at < 60)
        latency = {"samples": len(values)}
        for name, quantile in (("p50", .5), ("p95", .95), ("p99", .99)):
            latency[name] = values[int((len(values)-1)*quantile)] if values else None
        counters = dict(self.counters)
        counters.update(active=len(self.active), errors=dict(self.errors),
                        udp_drops=dict(self.udp_drops), latency=latency)
        sessions = list(self.active.values()) + list(self.recent)
        sessions.sort(key=lambda s: s["_started"], reverse=True)
        return {"schema": SCHEMA, "process_id": self.process_id,
                "component": "python", "time": utc(), "started": self.started,
                "epoch": self.epoch, "uptime_seconds": now-self.start_mono,
                "metrics": counters, "sessions": [{k: v for k, v in s.items()
                    if not k.startswith("_")} for s in sessions[:limit]],
                "events": list(self.events)[-16:], "truncated": len(sessions) > limit,
                "runtime": {"python": sys.version, "pid": os.getpid(),
                            "source_sha256": source_hash()}, "heap_bytes": None}


def source_hash():
    if not hasattr(source_hash, "value"):
        digest = hashlib.sha256()
        for name in ("diagnostics.py", "node.py", "rsx3.py", "protocol.py"):
            digest.update(name.encode())
            digest.update(Path(__file__).with_name(name).read_bytes())
        source_hash.value = digest.hexdigest()
    return source_hash.value


class LocalFRPC:
    def __init__(self, address, token):
        host, raw_port = address.rsplit(":", 1)
        port = int(raw_port)
        if host != "127.0.0.1" or not 1 <= port <= 65535:
            raise ValueError("frpc diagnostics must be 127.0.0.1:port")
        self.host, self.port, self.token = host, port, token

    def request(self, method, path, payload=None, timeout=3):
        if not path.startswith("/v1/"):
            raise ValueError("invalid local diagnostic route")
        conn = http.client.HTTPConnection(self.host, self.port, timeout=timeout)
        try:
            data = json.dumps(payload).encode() if payload is not None else None
            conn.request(method, path, data, {"Authorization": "Bearer " + self.token,
                                             "Content-Type": "application/json"})
            response = conn.getresponse()
            raw = response.read(48 * 1024 * 1024 + 1)
            if len(raw) > 48 * 1024 * 1024:
                raise ValueError("frpc diagnostic response size limit")
            if response.status != 200:
                raise ConnectionError(f"frpc diagnostics HTTP {response.status}: {raw[:256]!r}")
            return json.loads(raw)
        finally:
            conn.close()

    async def call(self, method, path, payload=None, timeout=3):
        return await asyncio.to_thread(self.request, method, path, payload, timeout)


async def read_frame(reader):
    n = struct.unpack("!I", await reader.readexactly(4))[0]
    if not 1 <= n <= MAX_FRAME:
        raise ValueError("diagnostic frame size limit")
    return json.loads(await reader.readexactly(n))


async def write_frame(writer, lock, obj):
    raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode()
    if len(raw) > MAX_FRAME:
        raw = json.dumps({"id": obj.get("id", ""), "error": "diagnostic response exceeds 65535 bytes; sample unavailable", "truncated": True}).encode()
    async with lock:
        writer.write(struct.pack("!I", len(raw)) + raw)
        await asyncio.wait_for(writer.drain(), 3)


def compact_frpc(snapshot):
    # The local full snapshot/report retains all identities; low-priority
    # periodic telemetry is deliberately bounded.
    snapshot["links"] = []
    snapshot["events"] = snapshot.get("events", [])[-12:]
    connections = snapshot.get("connections", [])
    snapshot["connections_truncated"] = len(connections) > 4
    snapshot["connections"] = sorted(connections, key=lambda c: c.get("opened", ""))[-4:]
    return snapshot


async def socks_connect(node, host, port, command=1):
    reader, writer = await asyncio.open_connection(node.socks_addr[0], node.socks_port)
    try:
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        if await reader.readexactly(2) != b"\x05\x00":
            raise ConnectionError("local SOCKS5 auth failed")
        writer.write(bytes((5, command, 0)) + p.encode_address(host, port))
        await writer.drain()
        reply = await reader.readexactly(4)
        if reply[:3] != b"\x05\x00\x00":
            raise ConnectionError(f"local SOCKS5 command {command} rejected ({reply[1]})")
        from .node import read_socks_address
        bound = await read_socks_address(reader, reply[3])
        return reader, writer, bound
    except BaseException:
        writer.close()
        raise


async def socks_benchmark(node, params):
    host = params["host"]
    if not host.endswith(".rsxdiag.invalid") or len(host.split(".")[0]) != 32:
        raise ValueError("diagnostic benchmark requires a one-time authorized target")
    size = int(params["bytes"])
    if size not in (1_000_000, 10_000_000, 50_000_000):
        raise ValueError("size must be 1, 10, or 50 MB")
    direction = params["direction"]
    if direction not in ("upload", "download"):
        raise ValueError("invalid benchmark direction")
    reader, writer, _ = await socks_connect(node, host, 1)
    try:
        writer.write(bytes((0 if direction == "download" else 1,)) + struct.pack("!Q", size))
        await writer.drain()
        started = time.monotonic()
        digest = hashlib.sha256()
        remaining = size
        if direction == "download":
            while remaining:
                chunk = await reader.read(min(65536, remaining))
                if not chunk:
                    raise ConnectionError("benchmark truncated")
                digest.update(chunk)
                remaining -= len(chunk)
        else:
            data = bytes(i % 251 for i in range(32768))
            while remaining:
                chunk = data[:min(len(data), remaining)]
                writer.write(chunk)
                await writer.drain()
                digest.update(chunk)
                remaining -= len(chunk)
        expected = await reader.readexactly(32)
        elapsed = time.monotonic()-started
        verified = hmac.compare_digest(expected, digest.digest())
        return {"state": "ok" if verified else "failed", "kind": "rsx3_socks_benchmark",
                "direction": direction, "bytes": size-remaining, "verified": verified,
                "duration_ms": elapsed*1000, "bytes_per_second": size/elapsed,
                "includes_target_xray": False}
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 3)
        except (OSError, asyncio.TimeoutError):
            pass


async def udp_end_to_end(node):
    # Actual SOCKS5 UDP -> RSX DATAGRAM -> target Xray/WARP -> DNS reply.
    _, control, bound = await socks_connect(node, "0.0.0.0", 0, 3)
    if bound[0] not in ("127.0.0.1", "0.0.0.0"):
        control.close()
        raise ValueError("local SOCKS5 returned non-loopback UDP relay")
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0)); udp.setblocking(False)
    loop = asyncio.get_running_loop()
    tx = secrets.token_bytes(2)
    query = tx + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    start = time.monotonic()
    try:
        packet = p.udp_packet("1.1.1.1", 53, query)
        await loop.sock_sendto(udp, packet, ("127.0.0.1", bound[1]))
        reply, source = await asyncio.wait_for(loop.sock_recvfrom(udp, 65535), 5)
        _, _, payload = p.parse_udp_packet(reply)
        if source[0] != "127.0.0.1" or len(payload) < 12 or payload[:2] != tx or not payload[2] & 128:
            raise ValueError("invalid end-to-end DNS response")
        return {"state": "ok", "verified": True, "kind": "rsx3_socks_udp_dns",
                "duration_ms": (time.monotonic()-start)*1000, "rcode": payload[3] & 15}
    finally:
        udp.close(); control.close()


class Peer:
    def __init__(self, node):
        self.node = node
        self.frpc = LocalFRPC(node.frpc_diagnostics_addr, local_token(node.token))
        self.archive = None
        self.archive_id = None
        self.busy = asyncio.Lock()

    async def execute(self, method, params):
        if method == "ping":
            return {"schema": SCHEMA, "time": utc(), "epoch": self.node.tunnel.epoch.hex()}
        if method == "snapshot":
            result = self.node.metrics.snapshot(16)
            try:
                result["frpc"] = compact_frpc(await self.frpc.call("GET", "/v1/snapshot"))
            except (OSError, ValueError, ConnectionError) as exc:
                result["frpc"] = {"state": "unavailable", "error": str(exc), "time": utc()}
            return result
        if method == "sessions":
            all_sessions = self.node.metrics.snapshot(128)["sessions"]
            offset = max(0, min(int(params.get("offset", 0)), 1024))
            return {"sessions": all_sessions[offset:offset+16], "next": offset+16 if offset+16 < len(all_sessions) else None}
        if method == "logs":
            with self.node.metrics.log_lock:
                return {"lines": list(self.node.metrics.logs)[-16:]}
        if method == "lookup":
            from urllib.parse import urlencode
            local, remote = params.get("local", ""), params.get("remote", "")
            if len(local)+len(remote) > 256:
                raise ValueError("invalid tuple")
            return await self.frpc.call("GET", "/v1/lookup?" + urlencode({"local": local, "remote": remote, "at": params.get("at", "")}))
        if method in ("raw_benchmark", "quic_udp", "socks_benchmark", "socks_udp"):
            if self.busy.locked():
                raise RuntimeError("another node diagnostic test is active")
            async with self.busy:
                if method == "raw_benchmark":
                    try:
                        return await self.frpc.call("POST", "/v1/benchmark", params, 120)
                    except asyncio.CancelledError:
                        # Cancelling asyncio.to_thread alone cannot stop its
                        # blocking HTTP socket; explicitly stop the private
                        # frpc test before releasing the single-test lock.
                        try:
                            await asyncio.shield(self.frpc.call("POST", "/v1/cancel-test", {}, 3))
                        except (OSError, ValueError):
                            pass
                        raise
                if method == "quic_udp":
                    return await self.frpc.call("POST", "/v1/udp-probe", {}, 8)
                if method == "socks_udp":
                    return await udp_end_to_end(self.node)
                return await socks_benchmark(self.node, params)
        if method == "capture_start":
            self.archive = None; self.archive_id = None
            return await self.frpc.call("POST", "/v1/capture", {"seconds": params.get("seconds")})
        if method == "capture_stop":
            return await self.frpc.call("DELETE", "/v1/capture")
        if method == "capture_status":
            return await self.frpc.call("GET", "/v1/capture")
        if method == "capture_manifest":
            await self.frpc.call("DELETE", "/v1/capture")
            contents = await self.frpc.call("GET", "/v1/capture/data", timeout=15)
            data = self.node.metrics.snapshot(128)
            with self.node.metrics.log_lock:
                lines = list(self.node.metrics.logs)
            self.archive = await asyncio.to_thread(self._archive, contents, data, lines)
            self.archive_id = secrets.token_hex(16)
            return {"id": self.archive_id, "bytes": len(self.archive),
                    "sha256": hashlib.sha256(self.archive).hexdigest(), "redacted": False}
        if method == "capture_chunk":
            offset = int(params.get("offset", -1))
            if self.archive is None or params.get("id") != self.archive_id or not 0 <= offset <= len(self.archive):
                raise ValueError("invalid capture download")
            chunk = self.archive[offset:offset+32768]
            return {"offset": offset, "data": base64.b64encode(chunk).decode(),
                    "next": offset+len(chunk) if offset+len(chunk) < len(self.archive) else None}
        raise ValueError("unsupported diagnostics method")

    @staticmethod
    def _archive(contents, data, lines):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("python.json", json.dumps(data, ensure_ascii=False))
            archive.writestr("python.log", "\n".join(lines))
            archive.writestr("capture.json", json.dumps(contents.get("status")))
            for name, text in (contents.get("qlogs") or {}).items():
                safe = "".join(c for c in name if c.isalnum() or c in "_-")
                archive.writestr(safe + ".sqlog", text)
        if buf.tell() > 24 * 1024 * 1024:
            raise ValueError("compressed capture exceeds 24 MiB budget")
        return buf.getvalue()


async def accept_diagnostics(node, reader, writer):
    if node.metrics is None or node.tunnel is None or not node.tunnel.alive:
        raise PermissionError("diagnostics disabled or no RSX3 control")
    epoch = await asyncio.wait_for(reader.readexactly(16), 5)
    tunnel = node.tunnel
    if epoch != tunnel.epoch or getattr(tunnel, "diagnostics_peer", None) is not None:
        raise PermissionError("invalid or duplicate diagnostic peer")
    nonce = secrets.token_bytes(32)
    writer.write(nonce); await writer.drain()
    supplied = await asyncio.wait_for(reader.readexactly(32), 5)
    expected = hmac.digest(node.token, DOMAIN + epoch + nonce, "sha256")
    if not hmac.compare_digest(expected, supplied) or not tunnel.alive:
        raise PermissionError("diagnostic HMAC failed")
    peer = Peer(node); peer.writer = writer; tunnel.diagnostics_peer = peer
    lock = asyncio.Lock(); tasks = {}

    async def request(msg):
        ident = msg["id"]
        try:
            timeout = min(125, max(1, float(msg.get("timeout", 8))))
            result = await asyncio.wait_for(peer.execute(msg["method"], msg.get("params") or {}), timeout)
            response = {"id": ident, "result": result}
        except asyncio.CancelledError:
            response = {"id": ident, "error": "cancelled"}
        except Exception as exc:
            response = {"id": ident, "error": f"{type(exc).__name__}: {exc}"}
        try:
            await write_frame(writer, lock, response)
        except (OSError, asyncio.TimeoutError, ValueError):
            writer.close()
        finally:
            tasks.pop(ident, None)

    try:
        # The acknowledgement itself can fail. Keep it inside the cleanup
        # boundary so a half-connected peer never pins diagnostics_ready or
        # blocks a later replacement stream.
        writer.write(b"\x00"); await writer.drain()
        tunnel.diagnostics_ready.set()
        while tunnel.alive:
            msg = await read_frame(reader)
            ident = msg.get("id", "")
            if not isinstance(ident, str) or len(ident) != 32:
                raise ValueError("invalid diagnostic request id")
            if msg.get("method") == "cancel":
                if ident in tasks:
                    tasks[ident].cancel()
                continue
            if ident in tasks or len(tasks) >= 4:
                await write_frame(writer, lock, {"id": ident, "error": "diagnostic request capacity"})
                continue
            tasks[ident] = asyncio.create_task(request(msg))
    finally:
        # Drop readiness before any potentially slow RPC task cancellation
        # or stream shutdown. A disconnected peer must never authorize new
        # business TCP/UDP sessions, even while the RSX3 control stays alive.
        if getattr(tunnel, "diagnostics_peer", None) is peer:
            tunnel.diagnostics_ready.clear()
        for task in list(tasks.values()):
            task.cancel()
        await asyncio.gather(*list(tasks.values()), return_exceptions=True)
        if getattr(tunnel, "diagnostics_peer", None) is peer:
            tunnel.diagnostics_peer = None
        peer.archive = None
        writer.close()
