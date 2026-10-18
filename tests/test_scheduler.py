"""RSX3-only bounded, serialized control writer tests."""
import asyncio
import unittest
from reverse_socks import protocol as p
from reverse_socks.scheduler import FairFrameWriter, CONTROL_LIMIT

class ControlledStreamWriter:
    def __init__(self):
        self.raw=[]
        self.wrote_first=asyncio.Event()
        self.first_drain_gate=asyncio.Event()
    def write(self,data):
        self.raw.append(data)
        if len(self.raw)==1:
            self.wrote_first.set()
    async def drain(self):
        if len(self.raw)==1:
            await self.first_drain_gate.wait()
    def kinds(self):
        return [p.HEADER.unpack(b[:p.HEADER.size])[0] for b in self.raw]

class RSX3ControlSchedulerTests(unittest.IsolatedAsyncioTestCase):
    async def test_fifo_for_rsx3_control_only(self):
        stream=ControlledStreamWriter()
        scheduler=FairFrameWriter(stream)
        first=asyncio.create_task(scheduler.send(p.OPEN_TCP,1,b"target"))
        await asyncio.wait_for(stream.wrote_first.wait(),1)
        tasks=[]
        for kind,sid in [(p.OPEN_UDP,2),(p.PING,0),(p.TCP_RST,1),(p.UDP_CLOSE,2)]:
            tasks.append(asyncio.create_task(scheduler.send(kind,sid)))
            await asyncio.sleep(0)
        self.assertEqual(len(scheduler.control),4)
        stream.first_drain_gate.set()
        await asyncio.wait_for(asyncio.gather(first,*tasks),3)
        self.assertEqual(stream.kinds(),[p.OPEN_TCP,p.OPEN_UDP,p.PING,p.TCP_RST,p.UDP_CLOSE])
        await scheduler.close()
    async def test_bounded_control_queue_cancel(self):
        stream=ControlledStreamWriter()
        scheduler=FairFrameWriter(stream)
        first=asyncio.create_task(scheduler.send(p.OPEN_TCP,1,b"first"))
        await asyncio.wait_for(stream.wrote_first.wait(),1)
        tasks=[first]
        for sid in range(2,CONTROL_LIMIT+5):
            tasks.append(asyncio.create_task(scheduler.send(p.OPEN_UDP,sid)))
            await asyncio.sleep(0)
        self.assertEqual(len(scheduler.control),CONTROL_LIMIT)
        self.assertFalse(tasks[-1].done())
        await asyncio.wait_for(scheduler.close(),3)
        results=await asyncio.wait_for(asyncio.gather(*tasks,return_exceptions=True),3)
        self.assertTrue(all(isinstance(item,ConnectionError) for item in results))
