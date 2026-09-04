"""Transparent TCP relay.

Connections redirected by the Windows redirector arrive here. For each one we
look up the ORIGINAL destination (camera ip, port) in the NAT table keyed by the
client's source port, open a connection to it, and pump bytes both ways without
modification. A copy of every byte goes to a StreamDecoder.

The outbound socket to the camera is bound to a source port inside
`src_port_range` so the redirector's WinDivert filter can exclude our own
traffic (otherwise we would redirect ourselves in a loop).

On Linux / in tests there is no redirector; `default_target` makes every
incoming connection go to a fixed (ip, port) so the relay can be exercised by
simply connecting to it.
"""
from __future__ import annotations

import asyncio
import threading
from typing import Callable, Optional, Tuple

from .decoders import StreamDecoder
from .model import LogStore
from .redirector_linux import original_dst

Target = Tuple[str, int]


class NatTable:
    """client source port → original (dst_ip, dst_port). Shared between the
    redirector thread (writer) and the relay (reader)."""

    def __init__(self) -> None:
        self._m: dict[int, Target] = {}
        self._lock = threading.Lock()

    def set(self, client_port: int, target: Target) -> None:
        with self._lock:
            self._m[client_port] = target

    def get(self, client_port: int) -> Optional[Target]:
        with self._lock:
            return self._m.get(client_port)

    def pop(self, client_port: int) -> None:
        with self._lock:
            self._m.pop(client_port, None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._m)


class Relay:
    def __init__(self, store: LogStore, nat: NatTable, *, listen_host: str = "0.0.0.0",
                 listen_port: int = 0, default_target: Optional[Target] = None,
                 src_port_range: Tuple[int, int] = (40000, 41000),
                 decoder_factory: Callable[..., StreamDecoder] = StreamDecoder,
                 on_error: Optional[Callable[[str], None]] = None):
        self.store = store
        self.nat = nat
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.default_target = default_target
        self.src_port_range = src_port_range
        self.decoder_factory = decoder_factory
        self.on_error = on_error or (lambda msg: None)
        self._server: Optional[asyncio.base_events.Server] = None
        self._next_src = src_port_range[0]
        self.active = 0

    @property
    def port(self) -> int:
        assert self._server is not None
        return self._server.sockets[0].getsockname()[1]

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.listen_host, self.listen_port)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    def _pick_src_port(self) -> int:
        lo, hi = self.src_port_range
        p = self._next_src
        self._next_src = lo if p + 1 >= hi else p + 1
        return p

    async def _connect(self, target: Target) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        last: Optional[Exception] = None
        for _ in range(64):
            sp = self._pick_src_port()
            try:
                return await asyncio.wait_for(
                    asyncio.open_connection(target[0], target[1], local_addr=("0.0.0.0", sp)),
                    timeout=10)
            except OSError as e:  # port in use → try next
                last = e
                if e.errno not in (98, 48, 10048, 10013):  # EADDRINUSE variants / WSAEACCES
                    raise
        raise OSError(f"no free source port in {self.src_port_range}: {last}")

    async def _handle(self, creader: asyncio.StreamReader, cwriter: asyncio.StreamWriter) -> None:
        peer = cwriter.get_extra_info("peername")
        client_port = peer[1] if peer else 0
        target = self.nat.get(client_port)
        if target is None:
            sock = cwriter.get_extra_info("socket")
            od = original_dst(sock) if sock is not None else None
            # REDIRECTed connections report the camera; direct ones report ourselves
            if od and od[1] != self.port:
                target = od
        if target is None:
            target = self.default_target
        if target is None:
            self.on_error(f"no NAT entry for client port {client_port}; dropping")
            cwriter.close()
            return
        stream = self.store.new_stream()
        dec = self.decoder_factory(self.store, stream, target[0], target[1], client_port)
        try:
            sreader, swriter = await self._connect(target)
        except Exception as e:
            self.on_error(f"connect to {target[0]}:{target[1]} failed: {e}")
            dec.close()
            cwriter.close()
            self.nat.pop(client_port)
            return
        self.active += 1
        try:
            await asyncio.gather(
                self._pump(creader, swriter, dec.feed_c2s, self.on_error),
                self._pump(sreader, cwriter, dec.feed_s2c, self.on_error),
            )
        finally:
            self.active -= 1
            dec.close()
            self.nat.pop(client_port)
            for w in (cwriter, swriter):
                try:
                    w.close()
                except Exception:
                    pass

    @staticmethod
    async def _pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                    tee: Callable[[bytes], None], on_error: Callable[[str], None]) -> None:
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                try:
                    tee(data)
                except Exception as e:  # decoder bugs must never break the relay
                    on_error(f"decoder error: {e!r}")
                writer.write(data)
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError, OSError):
            pass
        finally:
            try:
                writer.write_eof()
            except Exception:
                pass


class RelayThread:
    """Runs a Relay on its own asyncio loop in a daemon thread (UI friendly)."""

    def __init__(self, relay: Relay):
        self.relay = relay
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, name="camcap-relay", daemon=True)
        self._ready = threading.Event()
        self._err: Optional[BaseException] = None

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self.relay.start())
        except BaseException as e:  # noqa: BLE001
            self._err = e
            self._ready.set()
            return
        self._ready.set()
        self._loop.run_forever()
        self._loop.run_until_complete(self.relay.stop())
        self._loop.close()

    def start(self) -> "RelayThread":
        self._thread.start()
        self._ready.wait(5)
        if self._err:
            raise self._err
        return self

    @property
    def port(self) -> int:
        return self.relay.port

    def stop(self) -> None:
        if self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(5)
