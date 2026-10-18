"""Deterministic RSX2/RSX3 bounded writer scheduling and cancellation tests."""
import asyncio
import unittest

from reverse_socks import protocol as p
from reverse_socks.scheduler import FairFrameWriter, DATA_LIMIT, PER_SESSION_LIMIT


class ControlledStreamWriter:
    def __init__(self):
        self.raw = []
        self.wrote_first = asyncio.Event()
        self.first_drain_gate = asyncio.Event()
        self.block = True

    def write(self, data):
        self.raw.append(data)
        if len(self.raw) == 1:
            self.wrote_first.set()

    async def drain(self):
        if self.block and len(self.raw) == 1:
            await self.first_drain_gate.wait()

    def kinds(self):
        return [p.HEADER.unpack(frame[:p.HEADER.size])[0] for frame in self.raw]


class RSXFairSchedulerTests(unittest.IsolatedAsyncioTestCase):
    async def test_control_priority_session_fairness_and_fin_order(self):
        stream = ControlledStreamWriter()
        scheduler = FairFrameWriter(stream)
        first = asyncio.create_task(scheduler.send(p.TCP_DATA, 1, b"first"))
        await asyncio.wait_for(stream.wrote_first.wait(), 1)
        tasks = []
        for kind, sid, value in [
            (p.TCP_DATA, 1, b"second"),
            (p.TCP_DATA, 1, b"third"),
            (p.TCP_FIN, 1, b""),
            (p.TCP_DATA, 2, b"other"),
            (p.TCP_WINDOW, 3, b"\x00\x01"),
            (p.TCP_RESULT, 4, b"\x00"),
        ]:
            tasks.append(asyncio.create_task(scheduler.send(kind, sid, value)))
            await asyncio.sleep(0)
        self.assertEqual(scheduler.data_count, 4)
        self.assertEqual(len(scheduler.control), 2)
        stream.first_drain_gate.set()
        await asyncio.wait_for(asyncio.gather(first, *tasks), 3)
        self.assertEqual(stream.kinds(), [
            p.TCP_DATA, p.TCP_WINDOW, p.TCP_RESULT, p.TCP_DATA,
            p.TCP_DATA, p.TCP_DATA, p.TCP_FIN,
        ])
        await scheduler.close()

    async def test_per_session_backpressure_and_cancel(self):
        stream = ControlledStreamWriter()
        scheduler = FairFrameWriter(stream)
        tasks = [asyncio.create_task(scheduler.send(p.TCP_DATA, 7, b"x"))]
        await asyncio.wait_for(stream.wrote_first.wait(), 1)
        for _ in range(PER_SESSION_LIMIT + 3):
            tasks.append(asyncio.create_task(scheduler.send(p.TCP_DATA, 7, b"x")))
            await asyncio.sleep(0)
        self.assertEqual(scheduler.data_count, PER_SESSION_LIMIT)
        self.assertFalse(tasks[-1].done())
        await asyncio.wait_for(scheduler.close(), 2)
        results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 2)
        self.assertTrue(all(isinstance(r, ConnectionError) for r in results))

    async def test_control_capacity_and_bounded_global_data(self):
        stream = ControlledStreamWriter()
        scheduler = FairFrameWriter(stream)
        first = asyncio.create_task(scheduler.send(p.TCP_DATA, 1, b"x"))
        await stream.wrote_first.wait()
        tasks = []
        for sid in range(2, 2 + DATA_LIMIT + 3):
            tasks.append(asyncio.create_task(scheduler.send(p.TCP_DATA, sid, b"x")))
            await asyncio.sleep(0)
        self.assertEqual(scheduler.data_count, DATA_LIMIT)
        self.assertFalse(tasks[-1].done())
        await scheduler.close()
        results = await asyncio.wait_for(asyncio.gather(first, *tasks,
                                                        return_exceptions=True), 3)
        self.assertTrue(all(isinstance(r, ConnectionError) for r in results))


if __name__ == "__main__":
    unittest.main()
