"""Bounded RSX3 control-only frame writer.

TCP data uses independent QUIC streams; only control messages use this
serialized bounded queue. No application payload enters the control writer.
"""
import asyncio
from collections import deque
from dataclasses import dataclass
import logging
import time

from . import protocol as p

LOG = logging.getLogger("reverse_socks")

CONTROL_LIMIT = 128
SLOW_SECONDS = 0.100


@dataclass
class _Pending:
    kind: int
    sid: int
    data: bytes
    accepted: float
    result: asyncio.Future


class FairFrameWriter:
    def __init__(self, writer: asyncio.StreamWriter):
        self.writer = writer
        self.condition = asyncio.Condition()
        self.control = deque()
        self.closed = False
        self.total_bytes = 0
        self.queue_wait_max = 0.0
        self.drain_max = 0.0
        self.task = asyncio.create_task(self._run(), name="rsx-frame-writer")

    async def send(self, kind: int, sid: int, payload: bytes = b""):
        if len(payload) > p.MAX_PAYLOAD:
            raise ValueError("RSX frame too large")
        start = time.monotonic()
        result = asyncio.get_running_loop().create_future()
        async with self.condition:
            while not self.closed and len(self.control) >= CONTROL_LIMIT:
                await self.condition.wait()
            if self.closed:
                raise ConnectionError("RSX writer closed")
            req = _Pending(kind, sid, payload, time.monotonic(), result)
            self.control.append(req)
            self.condition.notify_all()
        elapsed = time.monotonic() - start
        if elapsed > SLOW_SECONDS:
            LOG.warning("RSX metric queue_backpressure kind=%d sid=%d wait_ms=%.1f",
                        kind, sid, elapsed * 1000)
        return await result

    async def _next(self):
        async with self.condition:
            while not self.closed and not self.control:
                await self.condition.wait()
            if self.closed:
                return None
            req = self.control.popleft()
            self.condition.notify_all()
            return req

    async def _run(self):
        error = ConnectionError("RSX frame writer stopped")
        in_flight = None
        try:
            while (req := await self._next()) is not None:
                in_flight = req
                if req.result.cancelled():
                    in_flight = None
                    continue
                elapsed = time.monotonic() - req.accepted
                self.queue_wait_max = max(self.queue_wait_max, elapsed)
                start = time.monotonic()
                self.writer.write(p.HEADER.pack(req.kind, req.sid, len(req.data)) + req.data)
                await self.writer.drain()
                drain_time = time.monotonic() - start
                self.drain_max = max(self.drain_max, drain_time)
                self.total_bytes += len(req.data)
                if elapsed > SLOW_SECONDS or drain_time > SLOW_SECONDS:
                    LOG.warning("RSX metric frame_write kind=%d sid=%d queued_ms=%.1f drain_ms=%.1f",
                                req.kind, req.sid, elapsed * 1000, drain_time * 1000)
                if not req.result.done():
                    req.result.set_result(None)
                in_flight = None
        except (OSError, ConnectionError, asyncio.CancelledError) as exc:
            error = ConnectionError(f"RSX frame writer failure: {type(exc).__name__}")
            if not isinstance(exc, asyncio.CancelledError):
                LOG.warning("RSX writer failed: %s", exc)
        finally:
            # The in-flight frame has already left its bounded queue.
            # Failing queued frames alone would leave its sender hanging
            # forever when shutdown cancels a blocked writer.drain().
            if in_flight is not None and not in_flight.result.done():
                in_flight.result.set_exception(error)
            async with self.condition:
                self.closed = True
                leftovers = list(self.control)
                self.control.clear()
                self.condition.notify_all()
            for req in leftovers:
                if not req.result.done():
                    req.result.set_exception(error)
            LOG.info("RSX metric writer_summary bytes=%d queue_max_ms=%.1f drain_max_ms=%.1f",
                     self.total_bytes, self.queue_wait_max * 1000, self.drain_max * 1000)

    async def close(self):
        async with self.condition:
            self.closed = True
            self.condition.notify_all()
        # Interrupt any network drain. The surrounding tunnel owns the
        # StreamWriter and closes its transport after this call.
        self.task.cancel()
        await asyncio.gather(self.task, return_exceptions=True)
