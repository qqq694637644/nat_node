"""Windows Python 3.13 Proactor TCP teardown for peer-reset connections.

CPython 3.13's _ProactorBasePipeTransport._call_connection_lost() calls
socket.shutdown(SHUT_RDWR) after connection_lost(). A TCP peer that already
sent RST makes shutdown raise WinError 10054. The stock callback then
skips socket.close(), _server._detach(), and _called_connection_lost, and
asyncio reports an unhandled callback exception.

Use a per-event-loop socket transport on Windows (not a process-wide
monkeypatch or a SelectorEventLoop with Windows select() socket limits).
Suppress only WinError 10054 from shutdown *during final teardown*, and
always close/detach the socket. Any other exception remains visible.
"""
import socket

from asyncio import proactor_events, windows_events


class _ResetTolerantSocketTransport(proactor_events._ProactorSocketTransport):
    """Only alter final cleanup; keep stock Proactor reads, writes and IOCP."""

    def _call_connection_lost(self, exc):
        if self._called_connection_lost:
            return
        try:
            self._protocol.connection_lost(exc)
        finally:
            sock = self._sock
            try:
                if sock is not None and hasattr(sock, "shutdown") and sock.fileno() != -1:
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except ConnectionResetError as reset:
                        if getattr(reset, "winerror", None) != 10054:
                            raise
            finally:
                try:
                    if sock is not None:
                        sock.close()
                finally:
                    self._sock = None
                    server = self._server
                    self._server = None
                    self._called_connection_lost = True
                    if server is not None:
                        server._detach(self)


class RSX3WindowsProactorEventLoop(windows_events.ProactorEventLoop):
    """Windows-only loop factory; preserves Proactor capacity and semantics."""

    def _make_socket_transport(self, sock, protocol, waiter=None,
                               extra=None, server=None):
        return _ResetTolerantSocketTransport(
            self, sock, protocol, waiter, extra, server
        )
