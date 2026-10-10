#
# test_fanout.py -- end-to-end tests for vnc_fanout dispatch
#
"""
Runs a VNCProxy against a fake upstream RFB server that answers every
update request with a full-screen RAW frame, and connects scripted
downstream clients (fast, slow, stalled; RAW and Tight).

Most tests run twice: with send_queues off (direct dispatch) and on.

$ pytest tests/
"""
import asyncio
import logging
import struct
import time
import zlib

import pytest

from vnc_fanout.main import run_proxy
from vnc_fanout.proxy import VNCProxy, vnc_encrypt

W, H = 640, 480
PW = "pw"
PATTERN = bytes(range(256)) * ((W * H * 4) // 256 + 2)

modes = pytest.mark.parametrize("send_queues", [False, True],
                                ids=["direct", "queued"])


def frame_bytes(n):
    """Pixel data of upstream frame ``n``: non-solid, differs per frame."""
    off = n % 256
    return PATTERN[off:off + W * H * 4]


# ------------------------------------------------------------
# FAKE UPSTREAM SERVER
# ------------------------------------------------------------

async def fake_upstream(reader, writer):
    writer.write(b"RFB 003.008\n")
    await reader.readexactly(12)
    writer.write(b"\x01\x02")
    await reader.readexactly(1)
    writer.write(b"\x00" * 16)
    await reader.readexactly(16)
    writer.write(struct.pack(">I", 0))
    await reader.readexactly(1)
    # 32bpp, depth 24, little-endian, truecolor, RGB shifts 16/8/0
    pf = struct.pack(">BBBBHHHBBBxxx", 32, 24, 0, 1,
                     255, 255, 255, 16, 8, 0)
    writer.write(struct.pack(">HH", W, H) + pf + struct.pack(">I", 4)
                 + b"fake")
    frame = 0
    try:
        while True:
            msg_type = ord(await reader.readexactly(1))
            if msg_type == 2:  # SetEncodings
                await reader.readexactly(1)
                n = struct.unpack(">H", await reader.readexactly(2))[0]
                await reader.readexactly(4 * n)
            elif msg_type == 3:  # FramebufferUpdateRequest
                await reader.readexactly(9)
                frame += 1
                writer.write(struct.pack(">BxH", 0, 1)
                             + struct.pack(">HHHHi", 0, 0, W, H, 0)
                             + frame_bytes(frame))
                await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError):
        pass


# ------------------------------------------------------------
# DOWNSTREAM TEST CLIENT
# ------------------------------------------------------------

class Client:
    """Scripted downstream VNC client.

    Counts received updates (``times``) and, if ``check`` is set,
    reconstructs the framebuffer and verifies it against the upstream
    frame pattern after every update.
    """

    def __init__(self, port, tight=False, delay=0.0, check=False):
        self.port = port
        self.tight = tight
        self.delay = delay
        self.check = check
        self.times = []
        self.errors = []
        self.disconnected = False
        self.fb = bytearray(W * H * 4)
        self.dz = zlib.decompressobj()

    async def connect(self):
        r, w = await asyncio.open_connection("127.0.0.1", self.port)
        await r.readexactly(12)
        w.write(b"RFB 003.008\n")
        await r.readexactly(2)
        w.write(b"\x02")
        challenge = await r.readexactly(16)
        w.write(vnc_encrypt(challenge, PW))
        assert struct.unpack(">I", await r.readexactly(4))[0] == 0
        w.write(b"\x01")
        hdr = await r.readexactly(24)
        await r.readexactly(struct.unpack(">I", hdr[20:24])[0])
        encodings = [7, 0] if self.tight else [0]
        w.write(struct.pack(">BxH", 2, len(encodings))
                + b"".join(struct.pack(">i", e) for e in encodings))
        w.write(struct.pack(">BBHHHH", 3, 0, 0, 0, W, H))
        await w.drain()
        self.reader, self.writer = r, w

    async def run(self):
        """Read updates forever, requesting the next after each one."""
        try:
            while True:
                await self._read_update()
                self.times.append(time.monotonic())
                if self.check:
                    self._check_fb()
                self.writer.write(struct.pack(">BBHHHH", 3, 1, 0, 0, W, H))
                await self.writer.drain()
                if self.delay:
                    await asyncio.sleep(self.delay)
        except (asyncio.IncompleteReadError, ConnectionError):
            self.disconnected = True

    def stall(self):
        """Stop reading: request one update, then never read again."""
        self.writer.write(struct.pack(">BBHHHH", 3, 1, 0, 0, W, H))
        self.writer.transport.pause_reading()

    def close(self):
        self.writer.transport.abort()

    def rate(self, start, end):
        """Updates per second received in [start, end)."""
        n = sum(1 for t in self.times if start <= t < end)
        return n / (end - start)

    async def _read_compact(self):
        r = self.reader
        b = (await r.readexactly(1))[0]
        n = b & 0x7f
        if b & 0x80:
            b = (await r.readexactly(1))[0]
            n |= (b & 0x7f) << 7
            if b & 0x80:
                n |= (await r.readexactly(1))[0] << 14
        return n

    async def _read_update(self):
        r = self.reader
        await r.readexactly(2)
        nrect = struct.unpack(">H", await r.readexactly(2))[0]
        for _ in range(nrect):
            x, y, w, h, enc = struct.unpack(">HHHHi",
                                            await r.readexactly(12))
            if enc == 0:
                data = await r.readexactly(w * h * 4)
            elif enc == 7:
                data = await self._read_tight(w, h)
            else:
                raise AssertionError(f"unexpected encoding {enc}")
            stride = W * 4
            for row in range(h):
                dst = (y + row) * stride + x * 4
                self.fb[dst:dst + w * 4] = data[row * w * 4:
                                                (row + 1) * w * 4]

    async def _read_tight(self, w, h):
        r = self.reader
        ctl = (await r.readexactly(1))[0]
        if ctl == 0x80:  # FillCompression
            tpixels = await r.readexactly(3) * (w * h)
        else:
            assert ctl >> 4 == 0, f"unexpected Tight control {ctl:#x}"
            size = w * h * 3
            if size < 12:
                tpixels = await r.readexactly(size)
            else:
                comp = await r.readexactly(await self._read_compact())
                tpixels = self.dz.decompress(comp)
                assert len(tpixels) == size
        # TPIXEL (R,G,B) -> upstream 32bpp little-endian (B,G,R,x)
        data = bytearray(w * h * 4)
        data[2::4] = tpixels[0::3]
        data[1::4] = tpixels[1::3]
        data[0::4] = tpixels[2::3]
        return data

    def _check_fb(self):
        # whole frame should be one upstream frame; byte 0 identifies it.
        # The pad byte (offset 3) isn't carried by Tight's TPIXEL.
        expected = frame_bytes(self.fb[0])
        for ch in range(4 if not self.tight else 3):
            if self.fb[ch::4] != expected[ch::4]:
                self.errors.append(f"framebuffer mismatch, channel {ch}")
                return


# ------------------------------------------------------------
# HARNESS
# ------------------------------------------------------------

class LogCapture(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)

    def messages(self, level=logging.DEBUG):
        return [r.getMessage() for r in self.records if r.levelno >= level]


class Harness:
    """Fake upstream + VNCProxy + helpers for spawning clients."""

    def __init__(self, send_queues, client_write_timeout=2.0,
                 viewonly_password=PW, control_password=None):
        self.send_queues = send_queues
        self.viewonly_password = viewonly_password
        self.control_password = control_password
        self.client_write_timeout = client_write_timeout
        self.log = LogCapture()
        self.tasks = []
        self.clients = []

    async def __aenter__(self):
        logger = logging.Logger("vnc_fanout_test")
        logger.addHandler(self.log)
        self.upstream = await asyncio.start_server(fake_upstream,
                                                   "127.0.0.1", 0)
        up_port = self.upstream.sockets[0].getsockname()[1]
        self.proxy = VNCProxy(logger, "127.0.0.1", up_port, "x",
                              "127.0.0.1", 0, self.viewonly_password,
                              downstream_control_password=self.control_password,
                              reconnect_delay=1,
                              client_write_timeout=self.client_write_timeout,
                              send_queues=self.send_queues)
        self.proxy_task = asyncio.create_task(self.proxy.start())
        while getattr(self.proxy, "_server", None) is None:
            await asyncio.sleep(0.01)
        self.port = self.proxy._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc):
        # close client sockets first: the proxy's server shutdown waits
        # for all connections to close
        for c in self.clients:
            c.close()
        for t in self.tasks + [self.proxy_task]:
            t.cancel()
        await asyncio.gather(*self.tasks, self.proxy_task,
                             return_exceptions=True)
        self.upstream.close()

    async def client(self, run=True, **kw):
        c = Client(self.port, **kw)
        await c.connect()
        self.clients.append(c)
        if run:
            self.tasks.append(asyncio.create_task(c.run()))
        return c


def run(coro):
    asyncio.run(coro)


async def try_auth(port, password):
    """Authenticate to the proxy; return the SecurityResult (0 = OK)."""
    r, w = await asyncio.open_connection("127.0.0.1", port)
    try:
        await r.readexactly(12)
        w.write(b"RFB 003.008\n")
        await r.readexactly(2)
        w.write(b"\x02")
        challenge = await r.readexactly(16)
        w.write(vnc_encrypt(challenge, password))
        return struct.unpack(">I", await r.readexactly(4))[0]
    finally:
        w.close()


# ------------------------------------------------------------
# TESTS
# ------------------------------------------------------------

@modes
def test_raw_and_tight_pixels(send_queues):
    """RAW and Tight clients receive updates with correct pixel data."""
    async def go():
        async with Harness(send_queues) as h:
            raw = await h.client(check=True)
            tgt = await h.client(tight=True, check=True)
            t0 = time.monotonic()
            await asyncio.sleep(2)
            for c in (raw, tgt):
                assert c.rate(t0, t0 + 2) >= 5
                assert c.errors == []
    run(go())


@modes
def test_stalled_client_is_disconnected(send_queues):
    """A client that stops reading is dropped after client_write_timeout
    and the remaining clients keep receiving updates."""
    async def go():
        async with Harness(send_queues, client_write_timeout=2.0) as h:
            good = await h.client()
            await asyncio.sleep(0.5)
            stalled = await h.client(run=False)
            stalled.stall()
            await asyncio.sleep(4)
            assert any("not reading updates" in m
                       for m in h.log.messages(logging.ERROR))
            assert stalled not in h.proxy.clients.values()
            assert len(h.proxy.clients) == 1
            t = time.monotonic()
            await asyncio.sleep(1)
            assert good.rate(t, t + 1) >= 5
    run(go())


@modes
def test_client_churn_during_stall(send_queues):
    """Regression: clients connecting/disconnecting while dispatch is
    blocked on a stalled client used to raise "dictionary changed size
    during iteration", reported as an upstream disconnect."""
    async def go():
        async with Harness(send_queues, client_write_timeout=10.0) as h:
            await h.client()
            await asyncio.sleep(0.5)
            stalled = await h.client(run=False)
            stalled.stall()
            await asyncio.sleep(0.5)
            churn = await h.client()
            await asyncio.sleep(0.5)
            churn.close()
            await asyncio.sleep(0.5)
            stalled.close()  # unblocks a pending drain() in direct mode
            await asyncio.sleep(1)
            msgs = h.log.messages(logging.WARNING)
            assert not any("upstream disconnected" in m for m in msgs), msgs
    run(go())


def test_queued_stalled_client_does_not_block_others():
    """With send queues, other clients are unaffected by a stalled one
    even before it times out."""
    async def go():
        async with Harness(True, client_write_timeout=10.0) as h:
            raw = await h.client()
            tgt = await h.client(tight=True, check=True)
            await asyncio.sleep(0.5)
            stalled = await h.client(run=False)
            stalled.stall()
            t0 = time.monotonic()
            await asyncio.sleep(3)
            for c in (raw, tgt):
                assert c.rate(t0, t0 + 3) >= 10
            assert tgt.errors == []
    run(go())


def test_queued_slow_client_does_not_throttle_others():
    """With send queues, a slow-but-alive client gets fewer updates
    (skipping to full frames) without slowing other clients or being
    disconnected."""
    async def go():
        async with Harness(True, client_write_timeout=10.0) as h:
            fast = await h.client()
            slow = await h.client(delay=0.5, check=True)
            await asyncio.sleep(0.5)
            t0 = time.monotonic()
            await asyncio.sleep(3)
            assert fast.rate(t0, t0 + 3) >= 10
            assert 1 <= slow.rate(t0, t0 + 3) <= 3
            assert not slow.disconnected
            assert slow.errors == []
            assert any("fell behind" in m for m in h.log.messages())
    run(go())


def test_direct_slow_client_throttles_others():
    """Documents the known limitation of direct dispatch: a slow client
    that keeps reading sets the pace for everyone."""
    async def go():
        async with Harness(False, client_write_timeout=10.0) as h:
            fast = await h.client()
            await h.client(delay=0.5)
            await asyncio.sleep(1.5)
            t0 = time.monotonic()
            await asyncio.sleep(3)
            assert fast.rate(t0, t0 + 3) <= 3
    run(go())


def test_auth_viewonly_and_control():
    """Both passwords accepted; anything else rejected."""
    async def go():
        async with Harness(False, viewonly_password="view",
                           control_password="ctrl") as h:
            assert await try_auth(h.port, "view") == 0
            assert await try_auth(h.port, "ctrl") == 0
            assert await try_auth(h.port, "wrong") == 1
    run(go())


def test_auth_control_only():
    """With only a control password configured, it is accepted and
    other passwords are rejected (not an exception)."""
    async def go():
        async with Harness(False, viewonly_password=None,
                           control_password="ctrl") as h:
            assert await try_auth(h.port, "ctrl") == 0
            assert await try_auth(h.port, "wrong") == 1
            assert h.log.messages(logging.ERROR) == []
    run(go())


def test_no_downstream_password_does_not_start():
    """A screen with neither downstream password refuses to start."""
    cfg = {'name': 'screenT',
           'upstream': {'vnc_host': '127.0.0.1', 'vnc_port': 1},
           'downstream': {'proxy_host': '127.0.0.1', 'proxy_port': 0}}
    t0 = time.monotonic()
    assert run_proxy(cfg) == 'screenT'
    assert time.monotonic() - t0 < 1
