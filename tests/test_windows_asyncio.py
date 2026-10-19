"""Windows Python 3.13 Proactor TCP reset: close/detach without traceback.

Uses real Windows error 10054 and a live IOCP TCP client/server. This module
is skipped on Linux: it must run on the Windows CI runner as well as locally.
"""
import asyncio
import os
from pathlib import Path
import struct
import socket
import subprocess
import sys
import time
import unittest

@unittest.skipUnless(sys.platform == "win32", "requires Windows Proactor")
class WindowsProactorResetTests(unittest.TestCase):

    @staticmethod
    def make_transport(shutdown_error=None, protocol_error=None):
        import ctypes
        from reverse_socks.windows_asyncio import _ResetTolerantSocketTransport

        class DummySocket:
            closed = 0
            shutdowns = 0

            def fileno(self):
                return 88

            def shutdown(self, how):
                assert how == socket.SHUT_RDWR
                self.shutdowns += 1
                if shutdown_error:
                    raise shutdown_error

            def close(self):
                self.closed += 1

        class DummyProtocol:
            notified = 0

            def connection_lost(self, exc):
                self.notified += 1
                if protocol_error:
                    raise protocol_error

        class DummyServer:
            detached = 0

            def _detach(self, transport):
                self.detached += 1

        sock, protocol, server = DummySocket(), DummyProtocol(), DummyServer()
        transport = object.__new__(_ResetTolerantSocketTransport)
        transport._sock = sock
        transport._protocol = protocol
        transport._server = server
        transport._called_connection_lost = False
        return transport, sock, protocol, server

    def test_winerror_10054_shutdown_does_not_interrupt_cleanup(self):
        import ctypes
        transport, sock, protocol, server = self.make_transport(ctypes.WinError(10054))
        transport._call_connection_lost(ConnectionResetError("peer reset"))
        self.assertEqual(sock.shutdowns, 1)
        self.assertEqual(sock.closed, 1)
        self.assertEqual(protocol.notified, 1)
        self.assertEqual(server.detached, 1)
        self.assertIsNone(transport._sock)
        self.assertIsNone(transport._server)
        self.assertTrue(transport._called_connection_lost)
        transport._call_connection_lost(None)
        self.assertEqual(sock.closed, 1)
        self.assertEqual(protocol.notified, 1)

    def test_unrelated_shutdown_error_still_propagates_after_cleanup(self):
        transport, sock, protocol, server = self.make_transport(
            ConnectionResetError("unrecognized network reset")
        )
        with self.assertRaisesRegex(ConnectionResetError, "unrecognized network reset"):
            transport._call_connection_lost(None)
        self.assertEqual(sock.closed, 1)
        self.assertEqual(server.detached, 1)
        self.assertTrue(transport._called_connection_lost)

    def test_protocol_callback_errors_still_propagate_after_cleanup(self):
        transport, sock, protocol, server = self.make_transport(
            protocol_error=RuntimeError("unexpected protocol failure")
        )
        with self.assertRaisesRegex(RuntimeError, "unexpected protocol failure"):
            transport._call_connection_lost(None)
        self.assertEqual(sock.closed, 1)
        self.assertEqual(server.detached, 1)
        self.assertTrue(transport._called_connection_lost)

    def test_regular_close_matches_proactor_transport(self):
        transport, sock, protocol, server = self.make_transport()
        transport._call_connection_lost(None)
        self.assertEqual(sock.shutdowns, 1)
        self.assertEqual(sock.closed, 1)
        self.assertEqual(server.detached, 1)

    def test_live_tcp_reset_preserves_windows_proactor_and_no_callback_errors(self):
        from reverse_socks.windows_asyncio import (
            RSX3WindowsProactorEventLoop, _ResetTolerantSocketTransport
        )
        seen = []

        async def scenario():
            loop = asyncio.get_running_loop()
            self.assertIsInstance(loop, RSX3WindowsProactorEventLoop)
            # An unexpected callback error is a real failure, not a log to hide.
            loop.set_exception_handler(lambda _, context: seen.append(context))

            async def reset_connection(reader, writer):
                # SO_LINGER(1,0) sends a TCP RST instead of orderly FIN.
                sock = writer.get_extra_info("socket")
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                struct.pack("hh", 1, 0))
                writer.transport.abort()

            server = await asyncio.start_server(
                reset_connection, "127.0.0.1", 0
            )
            try:
                port = server.sockets[0].getsockname()[1]
                for _ in range(8):
                    reader, writer = await asyncio.open_connection(
                        "127.0.0.1", port
                    )
                    self.assertIsInstance(
                        writer.transport, _ResetTolerantSocketTransport
                    )
                    try:
                        await asyncio.wait_for(reader.read(1), 3)
                    except (ConnectionResetError, BrokenPipeError):
                        pass
                    writer.close()
                    try:
                        await asyncio.wait_for(writer.wait_closed(), 3)
                    except (ConnectionResetError, BrokenPipeError):
                        pass
                await asyncio.sleep(0.15)
            finally:
                server.close()
                await server.wait_closed()

        with asyncio.Runner(loop_factory=RSX3WindowsProactorEventLoop) as runner:
            runner.run(scenario())
        self.assertEqual(
            seen, [],
            "unexpected Windows Proactor callback exception: " +
            repr([(e.get("message"), e.get("exception")) for e in seen])
        )

    def test_actual_cli_socks_reset_does_not_print_callback_traceback(self):
        """The deployed python -m reverse_socks path uses the patched loop."""
        def available_port(kind):
            with socket.socket(socket.AF_INET, kind) as sock:
                sock.bind(("127.0.0.1", 0))
                return sock.getsockname()[1]

        socks_port = available_port(socket.SOCK_STREAM)
        mux_port = available_port(socket.SOCK_STREAM)
        udp_port = available_port(socket.SOCK_DGRAM)
        peer_port = available_port(socket.SOCK_DGRAM)
        env = dict(os.environ, REVERSE_SOCKS_TOKEN="windows-reset-test-token-32-characters")
        proc = subprocess.Popen(
            [sys.executable, "-S", "-m", "reverse_socks",
             "--socks", f"127.0.0.1:{socks_port}",
             "--mux", f"127.0.0.1:{mux_port}",
             "--udp-bind", f"127.0.0.1:{udp_port}",
             "--udp-frpc", f"127.0.0.1:{peer_port}",
             "--log-level", "warning"],
            cwd=Path(__file__).resolve().parents[1],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        try:
            for _ in range(70):
                if proc.poll() is not None:
                    break
                try:
                    conn = socket.create_connection(("127.0.0.1", socks_port), 0.1)
                except OSError:
                    time.sleep(0.05)
                else:
                    conn.sendall(b"\x05\x01\x00")
                    conn.settimeout(1)
                    self.assertEqual(conn.recv(2), b"\x05\x00")
                    conn.close()
                    break
            else:
                self.fail("real Python node did not open SOCKS listener")
            self.assertIsNone(proc.poll(), "real Python node exited before test")
            for _ in range(14):
                with socket.create_connection(("127.0.0.1", socks_port), 1) as client:
                    # Complete accept()/SOCKS negotiation before forcing RST.
                    # Aborting during accept produces a distinct WinError 64
                    # that this narrowly targeted TCP teardown fix must not
                    # silently swallow.
                    client.sendall(b"\x05\x01\x00")
                    client.settimeout(1)
                    self.assertEqual(client.recv(2), b"\x05\x00")
                    client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                      struct.pack("hh", 1, 0))
            time.sleep(0.35)
        finally:
            if proc.poll() is None:
                proc.terminate()
            try:
                _, stderr = proc.communicate(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
                _, stderr = proc.communicate(timeout=8)
        self.assertNotIn("Exception in callback", stderr)
        self.assertNotIn("WinError 10054", stderr)
        self.assertNotIn("Traceback", stderr)


if __name__ == "__main__":
    unittest.main()
