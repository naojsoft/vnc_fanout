#
# proxy.py -- proxy class for vnc_fanout
#
# stdlib imports
import asyncio
import collections
import ssl
import struct

# 3rd party
from Crypto.Cipher import DES

# local
from vnc_fanout import tight

RFB_VERSION = b"RFB 003.008\n"

# Keysyms for control grab sequence (Ctrl + grab key)
XK_Control_L = 0xffe3
XK_Control_R = 0xffe4

# Named keysyms for the configurable grab key
GRAB_KEYSYMS = {
    "f1": 0xffbe, "f2": 0xffbf, "f3": 0xffc0, "f4": 0xffc1,
    "f5": 0xffc2, "f6": 0xffc3, "f7": 0xffc4, "f8": 0xffc5,
    "f9": 0xffc6, "f10": 0xffc7, "f11": 0xffc8, "f12": 0xffc9,
    "escape": 0xff1b, "tab": 0xff09, "space": 0x0020,
    "pause": 0xff13, "scroll_lock": 0xff14, "insert": 0xff63,
    "delete": 0xffff, "home": 0xff50, "end": 0xff57,
}

DEFAULT_GRAB_KEY = "f1"

# Ctrl + this key releases the control token
RELEASE_KEYSYM = 0xff1b  # Escape

# Default seconds to wait for a downstream client to accept an update
# before disconnecting it.  Dispatch runs in the upstream read path, so a
# client that stops reading would otherwise freeze the fanout for everyone.
DEFAULT_CLIENT_WRITE_TIMEOUT = 10.0

# Max pending update data per client, in multiples of the framebuffer
# size.  A client whose backlog exceeds this gets a single full frame
# instead, which bounds memory use for clients that fall behind.
MAX_QUEUED_FRAMES = 2

# VeNCrypt sub-types
VENCRYPT_TLSVNC = 258    # TLS + VNC authentication
VENCRYPT_X509VNC = 261   # X.509 cert + VNC authentication

__all__ = ["VNCProxy"]


# ------------------------------------------------------------
# VNC AUTH
# ------------------------------------------------------------

def reverse_bits(byte):
    return int('{:08b}'.format(byte)[::-1], 2)


def vnc_key(password):
    pw = password.encode("latin-1")[:8].ljust(8, b"\x00")
    return bytes(reverse_bits(b) for b in pw)


def vnc_encrypt(challenge, password):
    return DES.new(vnc_key(password), DES.MODE_ECB).encrypt(challenge)


# ------------------------------------------------------------
# CLIENT STATE
# ------------------------------------------------------------

class ClientState:
    def __init__(self, client_id, reader, writer, pixel_format,
                 can_control=False):
        self.id = client_id
        self.reader = reader
        self.writer = writer
        self.wants_update = False
        # send a full frame (built from the current framebuffer) next
        self.needs_full = False
        # pending _Update objects, drained by VNCProxy._client_writer()
        self.queue = collections.deque()
        self.queued_bytes = 0
        self.has_data = asyncio.Event()
        self.writer_task = None
        self.fell_behind = 0  # times backlog was replaced by a full frame
        self.supported_encodings = []
        self.zlib_streams = [None, None, None, None]
        self.pixel_format = pixel_format
        self.can_control = can_control
        self.ctrl_pressed = False  # for Ctrl+F1 grab detection

    @property
    def wants_tight(self):
        return 7 in self.supported_encodings


class _Update:
    """One upstream FramebufferUpdate, shared by all client queues.

    The RAW message and the Tight tiling are built on first use and
    cached, so that work is done at most once regardless of how many
    clients receive the update.  Rectangle data is immutable (bytes
    read from upstream), so it is safe to hold while clients catch up.
    """

    def __init__(self, proxy, rects):
        self.proxy = proxy
        self.rects = rects
        self.size = sum(len(r[4]) for r in rects)
        self._raw_msg = None
        self._tiles = None

    def msg_for(self, client):
        if client.wants_tight:
            return self._tight_msg(client)
        return self._raw()

    def _raw(self):
        if self._raw_msg is None:
            msg = bytearray(b"\x00\x00")
            msg += struct.pack(">H", len(self.rects))
            for x, y, w, h, data in self.rects:
                msg += struct.pack(">HHHHi", x, y, w, h, 0)
                msg += data
            self._raw_msg = bytes(msg)
        return self._raw_msg

    def _tight_msg(self, client):
        proxy = self.proxy
        if self._tiles is None:
            self._tiles = []
            for x, y, w, h, data in self.rects:
                self._tiles.extend(proxy._tile_rect(x, y, w, h, data))
        msg = bytearray(b"\x00\x00")
        msg += struct.pack(">H", len(self._tiles))
        for x, y, w, h, data in self._tiles:
            msg += struct.pack(">HHHHi", x, y, w, h, 7)
            msg += tight.encode_rect(data, w, h, proxy.pixel_format,
                                     proxy.bpp, client)
        return msg


# ------------------------------------------------------------
# PROXY
# ------------------------------------------------------------

class VNCProxy:

    def __init__(self, logger,
                 upstream_host, upstream_port, upstream_password,
                 downstream_host, downstream_port, downstream_viewonly_password,
                 downstream_control_password=None,
                 reconnect_delay=5,
                 grab_key=DEFAULT_GRAB_KEY,
                 downstream_tls_cert=None, downstream_tls_key=None,
                 downstream_tls_required=False,
                 upstream_tls=False, upstream_tls_ca=None,
                 client_write_timeout=DEFAULT_CLIENT_WRITE_TIMEOUT,
                 send_queues=False):
        self.logger = logger
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.upstream_password = upstream_password
        self.downstream_host = downstream_host
        self.downstream_port = downstream_port
        self.downstream_viewonly_password = downstream_viewonly_password
        self.downstream_control_password = downstream_control_password
        self.reconnect_delay = reconnect_delay
        self.client_write_timeout = client_write_timeout
        # per-client send queues (see _dispatch_queued) vs. writing to
        # each client in turn (see _dispatch_direct)
        self.send_queues = send_queues
        if self.send_queues:
            self.logger.info("per-client send queues enabled")

        key = grab_key.lower()
        if key not in GRAB_KEYSYMS:
            raise ValueError(
                f"unknown grab key {grab_key!r}; "
                f"valid keys: {', '.join(sorted(GRAB_KEYSYMS))}")
        self.grab_keysym = GRAB_KEYSYMS[key]
        self.grab_key_name = grab_key

        # TLS for upstream VeNCrypt
        self.upstream_tls = upstream_tls
        self.upstream_tls_ca = upstream_tls_ca
        if self.upstream_tls:
            self.logger.info("TLS enabled for upstream (VeNCrypt)")

        # TLS for downstream VeNCrypt
        self.downstream_tls_cert = downstream_tls_cert
        self.downstream_tls_key = downstream_tls_key
        self._tls_enabled = downstream_tls_cert is not None
        self._tls_required = downstream_tls_required and self._tls_enabled
        if self._tls_enabled:
            mode = "required" if self._tls_required else "optional"
            self.logger.info(
                f"TLS enabled for downstream (VeNCrypt, {mode})")

        self.clients = {}       # client_id -> ClientState
        self._next_client_id = 1
        self.controller = None  # ClientState that holds the control token

        self.up_reader = None
        self.up_writer = None

        self.framebuffer = None
        self.fb_width = None
        self.fb_height = None
        self.bpp = 4  # assuming 32-bit truecolor RAW

    # --------------------------------------------------------
    # UPSTREAM
    # --------------------------------------------------------

    async def connect_upstream(self):
        """Perform the VNC handshake with the upstream server.

        Sets up self.up_reader, self.up_writer, self.framebuffer,
        self.server_init, etc.  Does NOT start the read/update tasks;
        the caller (_run_upstream) manages those.
        """
        self.logger.info(
            f"connecting to upstream {self.upstream_host}:{self.upstream_port}")

        self.up_reader, self.up_writer = \
            await asyncio.open_connection(self.upstream_host,
                                          self.upstream_port)

        await self.up_reader.readexactly(12)
        self.up_writer.write(RFB_VERSION)
        await self.up_writer.drain()

        nsec = ord(await self.up_reader.readexactly(1))
        sec_types = await self.up_reader.readexactly(nsec)

        if self.upstream_tls and 19 in sec_types:
            # Choose VeNCrypt (security type 19)
            self.up_writer.write(b"\x13")
            await self.up_writer.drain()
            await self._upstream_vencrypt_handshake()
        elif 2 in sec_types:
            # Plain VNC auth (security type 2)
            self.up_writer.write(b"\x02")
            await self.up_writer.drain()
        else:
            raise RuntimeError(
                f"No supported upstream security type "
                f"(offered: {list(sec_types)})")

        # VNC auth challenge-response (runs over TLS if VeNCrypt)
        challenge = await self.up_reader.readexactly(16)
        self.up_writer.write(vnc_encrypt(challenge, self.upstream_password))
        await self.up_writer.drain()

        result = struct.unpack(">I",
                               await self.up_reader.readexactly(4))[0]
        if result != 0:
            raise RuntimeError("Upstream auth failed")

        self.up_writer.write(b"\x01")
        await self.up_writer.drain()

        header = await self.up_reader.readexactly(24)
        self.fb_width, self.fb_height = struct.unpack(">HH", header[:4])
        self.pixel_format = header[4:20]
        name_len = struct.unpack(">I", header[20:24])[0]
        name = await self.up_reader.readexactly(name_len)

        self.server_init = header + name

        self.framebuffer = bytearray(
            self.fb_width * self.fb_height * self.bpp
        )

        # RAW only
        msg = struct.pack(">BxH", 2, 1)
        msg += struct.pack(">i", 0)
        self.up_writer.write(msg)
        await self.up_writer.drain()

        self.logger.info("upstream connected")

    async def _upstream_vencrypt_handshake(self):
        """Perform VeNCrypt sub-negotiation as a client and upgrade to TLS."""
        reader, writer = self.up_reader, self.up_writer

        # Version exchange -- server sends its version, we reply 0.2
        srv_major, srv_minor = struct.unpack(
            ">BB", await reader.readexactly(2))
        writer.write(struct.pack(">BB", 0, 2))
        await writer.drain()

        # Server ack
        ack = ord(await reader.readexactly(1))
        if ack != 0:
            raise RuntimeError("Upstream VeNCrypt version rejected")

        # Read offered sub-types
        n_sub = ord(await reader.readexactly(1))
        sub_data = await reader.readexactly(4 * n_sub)
        sub_types = [struct.unpack(">I", sub_data[i*4:(i+1)*4])[0]
                     for i in range(n_sub)]
        self.logger.debug(f"upstream VeNCrypt sub-types: {sub_types}")

        # Prefer X509Vnc if we have a CA, otherwise TLSVnc
        chosen = None
        preferred = [VENCRYPT_X509VNC, VENCRYPT_TLSVNC]
        for st in preferred:
            if st in sub_types:
                chosen = st
                break
        if chosen is None:
            raise RuntimeError(
                f"No supported upstream VeNCrypt sub-type "
                f"(offered: {sub_types})")

        writer.write(struct.pack(">I", chosen))
        await writer.drain()

        # Server confirms
        ok = ord(await reader.readexactly(1))
        if ok != 1:
            raise RuntimeError("Upstream rejected VeNCrypt sub-type")

        # Build client-side SSL context
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if chosen == VENCRYPT_TLSVNC:
            # Anonymous TLS -- no server certificate verification
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            ssl_ctx.set_ciphers("aNULL:@SECLEVEL=0")
            self.logger.debug("upstream VeNCrypt: TLSVnc (anonymous DH)")
        else:
            # X509Vnc -- verify server certificate if CA provided
            if self.upstream_tls_ca:
                ssl_ctx.load_verify_locations(self.upstream_tls_ca)
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_REQUIRED
            else:
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
            self.logger.debug("upstream VeNCrypt: X509Vnc")

        # Upgrade to TLS
        transport = writer.transport
        protocol = transport.get_protocol()
        loop = asyncio.get_running_loop()
        new_transport = await loop.start_tls(
            transport, protocol, ssl_ctx, server_side=False)

        self.up_writer = asyncio.StreamWriter(
            new_transport, protocol, reader, loop)
        # reader is updated by protocol.connection_made()
        self.logger.info("upstream TLS handshake complete")

    def _close_upstream(self):
        """Close the upstream connection if open."""
        if self.up_writer is not None:
            try:
                self.up_writer.close()
            except Exception:
                pass
            self.up_writer = None
            self.up_reader = None

    async def _run_upstream(self):
        """Run upstream read/update tasks; reconnect on failure.

        On disconnect, cancels both tasks, closes the upstream socket,
        marks all clients for a full refresh, and retries the connection
        every ``reconnect_delay`` seconds.  If reconnect_delay is 0,
        the proxy shuts down instead of reconnecting.
        """
        while True:
            update_task = asyncio.create_task(self.upstream_update_loop())
            read_task = asyncio.create_task(self.read_upstream())

            try:
                done, pending = await asyncio.wait(
                    [update_task, read_task],
                    return_when=asyncio.FIRST_COMPLETED
                )
                for task in pending:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
                # Re-raise the exception from the completed task
                for task in done:
                    task.result()
            except Exception as e:
                self.logger.warning(f"upstream disconnected: {e}")

            self._close_upstream()

            if self.reconnect_delay == 0:
                self.logger.info(
                    "reconnect disabled, shutting down")
                # Close all downstream clients
                for client in list(self.clients.values()):
                    try:
                        client.writer.close()
                    except Exception:
                        pass
                self.clients.clear()
                # Stop the downstream server so serve_forever() returns
                self._server.close()
                await self._server.wait_closed()
                return

            # Clients are refreshed by the full upstream frame requested
            # on reconnect (upstream_update_loop).  Do NOT clear
            # wants_update -- clients have already sent their
            # FramebufferUpdateRequest and are waiting for a response.
            # Clearing it would deadlock (proxy waits for request, client
            # waits for response).

            # Retry loop
            while True:
                self.logger.info(
                    f"attempting reconnection in {self.reconnect_delay}s...")
                await asyncio.sleep(self.reconnect_delay)
                try:
                    await self.connect_upstream()
                    break
                except Exception as e:
                    self.logger.warning(
                        f"upstream reconnect failed: {e}")

    async def upstream_update_loop(self):
        # initial full frame
        msg = struct.pack(">BBHHHH",
                          3, 0, 0, 0,
                          self.fb_width,
                          self.fb_height
                          )
        self.up_writer.write(msg)
        await self.up_writer.drain()

        await asyncio.sleep(0.2)

        # Performance: pre-build the incremental request message once
        # instead of calling struct.pack every 50 ms.
        inc_msg = struct.pack(">BBHHHH",
                              3, 1, 0, 0,
                              self.fb_width,
                              self.fb_height
                              )

        # incremental loop
        while True:
            self.up_writer.write(inc_msg)
            await self.up_writer.drain()
            await asyncio.sleep(0.05)

    async def read_upstream(self):
        while True:
            msg_type = ord(await self.up_reader.readexactly(1))
            if msg_type != 0:
                continue

            await self.up_reader.readexactly(1)  # padding
            nrect = struct.unpack(">H",
                                  await self.up_reader.readexactly(2))[0]

            rectangles = []

            for _ in range(nrect):
                rect_hdr = await self.up_reader.readexactly(12)
                x, y, w, h, enc = struct.unpack(">HHHHi", rect_hdr)

                if enc != 0:
                    raise RuntimeError("Only RAW supported")

                size = w * h * self.bpp
                data = await self.up_reader.readexactly(size)

                self.apply_rect(x, y, w, h, data)

                rectangles.append((x, y, w, h, data))

            if self.send_queues:
                self._dispatch_queued(rectangles)
                # readexactly() does not yield while data is buffered, so
                # give the client writer tasks a chance to run.
                await asyncio.sleep(0)
            else:
                await self._dispatch_direct(rectangles)

    def apply_rect(self, x, y, w, h, data):
        stride = self.fb_width * self.bpp
        rowbytes = w * self.bpp

        # Performance: full-width rects (common for initial frames and
        # large updates) use a single slice assignment instead of
        # row-by-row copying.
        if w == self.fb_width:
            dst = y * stride
            self.framebuffer[dst:dst + h * stride] = data[:h * stride]
        else:
            for row in range(h):
                src = row * rowbytes
                dst = ((y + row) * stride) + (x * self.bpp)
                self.framebuffer[dst:dst+rowbytes] = data[src:src+rowbytes]

    # --------------------------------------------------------
    # DOWNSTREAM DISPATCH
    # --------------------------------------------------------

    def _tile_rect(self, x, y, w, h, data):
        """Split a rectangle into tiles no wider than TIGHT_MAX_WIDTH
        and no taller than TIGHT_MAX_HEIGHT.  Returns a list of
        (x, y, w, h, data) tuples with pixel data extracted from the
        source rectangle.

        Performance: uses memoryview to avoid copying pixel data.
        Full-width tiles (the common case when width <= TIGHT_MAX_WIDTH)
        get a zero-copy contiguous slice.  Non-full-width tiles still
        require row-by-row extraction but use memoryview slices on the
        source to avoid intermediate copies.
        """
        max_w = tight.TIGHT_MAX_WIDTH
        max_h = tight.TIGHT_MAX_HEIGHT

        if w <= max_w and h <= max_h:
            return [(x, y, w, h, data)]

        tiles = []
        mv = memoryview(data) if not isinstance(data, memoryview) \
            else data
        src_stride = w * self.bpp
        ty = 0
        while ty < h:
            th = min(max_h, h - ty)
            tx = 0
            while tx < w:
                tw = min(max_w, w - tx)
                # Full-width tile: single contiguous slice, no row copy
                if tw == w:
                    start = ty * src_stride
                    end = (ty + th) * src_stride
                    tiles.append((x + tx, y + ty, tw, th,
                                  mv[start:end]))
                else:
                    tile_data = bytearray(tw * th * self.bpp)
                    dst_stride = tw * self.bpp
                    for row in range(th):
                        src = (ty + row) * src_stride + tx * self.bpp
                        dst = row * dst_stride
                        tile_data[dst:dst + dst_stride] = \
                            mv[src:src + dst_stride]
                    tiles.append((x + tx, y + ty, tw, th,
                                  bytes(tile_data)))
                tx += tw
            ty += th
        return tiles

    async def _dispatch_direct(self, rects):
        """Fan out a FramebufferUpdate by writing to each client in turn.

        Used when send_queues is False.  A client that is slow to read
        delays updates to all clients (and upstream reads) until it
        catches up or client_write_timeout expires.

        Performance: expensive work is done at most once regardless of
        client count.  The RAW message is built once and shared across
        all RAW clients.  Tight tiling (_tile_rect) is computed once
        and reused for all Tight clients (per-client zlib encoding is
        still required since each client has its own zlib stream state).

        Note: encoding is intentionally synchronous (not offloaded to a
        thread executor) to naturally throttle upstream update requests.
        If encoding were async, the upstream_update_loop would keep
        sending requests while responses pile up unread, causing the
        upstream server to drop the connection.
        """
        dead = []

        # Pre-build the RAW message once for all RAW clients
        raw_msg = None
        # Pre-tile once for all Tight clients
        tight_rects = None

        # Iterate over a snapshot: drain() yields to the event loop, during
        # which clients may connect or disconnect and modify self.clients.
        for client in list(self.clients.values()):
            if not client.wants_update:
                continue

            try:
                if client.wants_tight:
                    if tight_rects is None:
                        tight_rects = []
                        for x, y, w, h, data in rects:
                            tight_rects.extend(
                                self._tile_rect(x, y, w, h, data))

                    msg = bytearray(b"\x00\x00")
                    msg += struct.pack(">H", len(tight_rects))
                    for x, y, w, h, data in tight_rects:
                        msg += struct.pack(">HHHHi", x, y, w, h, 7)
                        msg += tight.encode_rect(data, w, h,
                                                 self.pixel_format,
                                                 self.bpp, client)
                else:
                    if raw_msg is None:
                        raw_msg = bytearray(b"\x00\x00")
                        raw_msg += struct.pack(">H", len(rects))
                        for x, y, w, h, data in rects:
                            raw_msg += struct.pack(">HHHHi",
                                                   x, y, w, h, 0)
                            raw_msg += data
                    msg = raw_msg

                client.writer.write(msg)
                await asyncio.wait_for(client.writer.drain(),
                                       self.client_write_timeout)
            except asyncio.TimeoutError:
                dead.append(client)
                self.logger.error(
                    f"client {client.id} not reading updates for "
                    f"{self.client_write_timeout}s; closing...")
            except Exception as e:
                dead.append(client)
                self.logger.error(
                    f"exception writing to client {client.id}: "
                    f"{e}; closing...")

        for c in dead:
            self.clients.pop(c.id, None)
            # Closing the transport also ends the client's handle_client()
            # task, which releases the control token if held.
            try:
                c.writer.transport.abort()
            except Exception:
                pass

    async def _send_full_frame_direct(self, client):
        client.writer.write(self._full_frame_msg(client))
        await client.writer.drain()

    def _dispatch_queued(self, rects):
        """Fan out a FramebufferUpdate via per-client send queues.

        Used when send_queues is True.  Does not write to any socket:
        the update is appended to each client's send queue and that
        client's writer task (see
        _client_writer) encodes and sends it.  A slow or stalled client
        therefore only delays itself, never the upstream read path or
        other clients.

        Performance: expensive work is done at most once regardless of
        client count.  The shared _Update object lazily builds the RAW
        message and the Tight tiling once and caches them for all
        clients (per-client zlib encoding is still required since each
        client has its own zlib stream state).
        """
        update = _Update(self, rects)
        max_queued = MAX_QUEUED_FRAMES * len(self.framebuffer)

        for client in self.clients.values():
            if not client.wants_update or client.writer_task is None:
                continue
            if client.needs_full:
                # A full frame is pending; it is built from the
                # framebuffer when sent, so it will include this update.
                continue
            if client.queued_bytes + update.size > max_queued:
                # Client has fallen too far behind: drop its backlog and
                # catch it up with a single full frame instead.
                client.fell_behind += 1
                log = self.logger.info if client.fell_behind == 1 \
                    else self.logger.debug
                log(f"client {client.id} fell behind "
                    f"({client.fell_behind}x); "
                    f"sending full frame instead of backlog")
                client.queue.clear()
                client.queued_bytes = 0
                client.needs_full = True
            else:
                client.queue.append(update)
                client.queued_bytes += update.size
            client.has_data.set()

    async def _client_writer(self, client):
        """Per-client task: encode and send queued updates to ``client``.

        If the client does not accept an update within
        client_write_timeout seconds, its connection is aborted, which
        also ends its handle_client() task.
        """
        try:
            while True:
                await client.has_data.wait()
                if client.needs_full:
                    client.needs_full = False
                    client.queue.clear()
                    client.queued_bytes = 0
                    msg = self._full_frame_msg(client)
                elif client.queue:
                    update = client.queue.popleft()
                    client.queued_bytes -= update.size
                    msg = update.msg_for(client)
                else:
                    client.has_data.clear()
                    continue

                client.writer.write(msg)
                await asyncio.wait_for(client.writer.drain(),
                                       self.client_write_timeout)

        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            self.logger.error(
                f"client {client.id} not reading updates for "
                f"{self.client_write_timeout}s; closing...")
        except Exception as e:
            self.logger.error(
                f"exception writing to client {client.id}: "
                f"{e}; closing...")
        # handle_client() sees the closed connection and cleans up,
        # including releasing the control token if held.
        try:
            client.writer.transport.abort()
        except Exception:
            pass

    def _full_frame_msg(self, client):
        """Build a FramebufferUpdate covering the whole framebuffer."""
        if client.wants_tight:
            strips = self._tile_rect(0, 0,
                                     self.fb_width, self.fb_height,
                                     self.framebuffer)
            msg = bytearray(b"\x00\x00")
            msg += struct.pack(">H", len(strips))
            for x, y, w, h, data in strips:
                msg += struct.pack(">HHHHi", x, y, w, h, 7)
                msg += tight.encode_rect(data, w, h,
                                         self.pixel_format,
                                         self.bpp, client)
        else:
            msg = bytearray(b"\x00\x00")
            msg += struct.pack(">H", 1)
            msg += struct.pack(">HHHHi",
                               0, 0,
                               self.fb_width,
                               self.fb_height,
                               0)
            msg += self.framebuffer
        return msg

    # --------------------------------------------------------
    # VENCRYPT
    # --------------------------------------------------------

    async def _vencrypt_handshake(self, reader, writer):
        """Perform VeNCrypt sub-negotiation and upgrade to TLS.

        Returns a new (reader, writer) pair wrapping the TLS connection,
        or (None, None) on failure.  The VNC auth challenge-response
        happens after this, over the encrypted channel.
        """
        # VeNCrypt version exchange (we support 0.2)
        writer.write(struct.pack(">BB", 0, 2))
        await writer.drain()

        client_major, client_minor = struct.unpack(
            ">BB", await reader.readexactly(2))

        if (client_major, client_minor) < (0, 2):
            writer.write(b"\xff")  # version not OK
            await writer.drain()
            return None, None

        writer.write(b"\x00")  # version OK
        await writer.drain()

        # Offer both TLSVnc (258) and X509Vnc (261) sub-types
        sub_types = [VENCRYPT_TLSVNC, VENCRYPT_X509VNC]
        writer.write(struct.pack(">B", len(sub_types)))
        for st in sub_types:
            writer.write(struct.pack(">I", st))
        await writer.drain()

        chosen = struct.unpack(">I", await reader.readexactly(4))[0]
        if chosen not in sub_types:
            writer.write(b"\x00")  # sub-type not accepted
            await writer.drain()
            return None, None

        writer.write(b"\x01")  # sub-type OK, proceed to TLS
        await writer.drain()

        # Build an SSL context appropriate for the chosen sub-type.
        # TLSVnc (258) uses anonymous DH -- no certificate, aNULL ciphers.
        # X509Vnc (261) uses certificate-based TLS -- standard ciphers.
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        if chosen == VENCRYPT_TLSVNC:
            ssl_ctx.set_ciphers("aNULL:@SECLEVEL=0")
            self.logger.debug("VeNCrypt: using TLSVnc (anonymous DH)")
        else:
            ssl_ctx.load_cert_chain(self.downstream_tls_cert,
                                    self.downstream_tls_key)
            ssl_ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
            self.logger.debug("VeNCrypt: using X509Vnc (certificate)")

        # Upgrade the transport to TLS.
        # start_tls() auto-calls protocol.connection_made() with the
        # new transport, which updates the reader's transport ref.
        transport = writer.transport
        protocol = transport.get_protocol()
        loop = asyncio.get_running_loop()
        new_transport = await loop.start_tls(
            transport, protocol, ssl_ctx, server_side=True)

        # The existing reader is updated by protocol.connection_made(),
        # but we need a new writer pointing to the TLS transport.
        new_writer = asyncio.StreamWriter(
            new_transport, protocol, reader, loop)

        return reader, new_writer

    # --------------------------------------------------------
    # CLIENT HANDLER
    # --------------------------------------------------------

    async def handle_client(self, reader, writer):
        peername = writer.get_extra_info("peername")
        addr = f"{peername[0]}:{peername[1]}" if peername else "unknown"

        client_id = self._next_client_id
        self._next_client_id += 1
        self.logger.info(f"client {client_id} connected: {addr}")

        can_control = False
        state = ClientState(client_id, reader, writer, self.pixel_format)
        self.clients[client_id] = state

        try:
            # Version
            writer.write(RFB_VERSION)
            await writer.drain()
            await reader.readexactly(12)

            # Security type negotiation
            if self._tls_enabled:
                if self._tls_required:
                    # Only offer VeNCrypt (19) -- no unencrypted fallback
                    writer.write(b"\x01\x13")  # 1 type: 19
                else:
                    # Offer VeNCrypt (19) and plain VNC auth (2)
                    writer.write(b"\x02\x13\x02")  # 2 types: 19, 2
                await writer.drain()
                sec_type = ord(await reader.readexactly(1))

                if sec_type == 19:  # VeNCrypt
                    new_reader, new_writer = \
                        await self._vencrypt_handshake(reader, writer)
                    if new_reader is None:
                        return
                    reader = new_reader
                    writer = new_writer
                    state.reader = reader
                    state.writer = writer
                    self.logger.info(
                        f"client {client_id} upgraded to TLS")
                elif sec_type == 2 and not self._tls_required:
                    pass  # plain VNC auth, allowed
                else:
                    return
            else:
                # No TLS -- offer plain VNC auth only
                writer.write(b"\x01\x02")
                await writer.drain()
                await reader.readexactly(1)

            # VNC auth challenge-response
            challenge = b"ProxyAuthChallenge!"[:16]
            writer.write(challenge)
            await writer.drain()

            resp = await reader.readexactly(16)

            # Check control password first (if configured)
            if self.downstream_control_password is not None and \
                    resp == vnc_encrypt(challenge,
                                        self.downstream_control_password):
                can_control = True
            elif self.downstream_viewonly_password is None or \
                    resp != vnc_encrypt(challenge,
                                        self.downstream_viewonly_password):
                # no view-only password configured, or it doesn't match
                writer.write(struct.pack(">I", 1))
                await writer.drain()
                return

            state.can_control = can_control
            if can_control:
                self.logger.info(
                    f"client {client_id} ({addr}) authenticated with "
                    f"control (Ctrl+{self.grab_key_name} to grab)")
            else:
                self.logger.info(
                    f"client {client_id} ({addr}) authenticated view-only")

            writer.write(struct.pack(">I", 0))
            await writer.drain()

            await reader.readexactly(1)  # ClientInit

            writer.write(self.server_init)
            await writer.drain()

            if self.send_queues:
                # From here on all FramebufferUpdates go through this task
                state.writer_task = asyncio.create_task(
                    self._client_writer(state))

            # ---- MAIN CLIENT LOOP ----
            while True:
                msg_type = ord(await reader.readexactly(1))
                # for debugging
                # self.logger.debug("Downstream msg type:", msg_type)
                if msg_type == 0:  # SetPixelFormat
                    await reader.readexactly(3)
                    state.pixel_format = await reader.readexactly(16)

                elif msg_type == 2:  # SetEncodings
                    await reader.readexactly(1)
                    n = struct.unpack(">H", await reader.readexactly(2))[0]
                    enc_data = await reader.readexactly(4 * n)
                    state.supported_encodings = [
                        struct.unpack(">i", enc_data[i*4:(i+1)*4])[0]
                        for i in range(n)
                    ]

                elif msg_type == 3:  # FramebufferUpdateRequest
                    rest = await reader.readexactly(9)
                    incremental, x, y, w, h = struct.unpack(">BHHHH", rest)

                    if incremental == 0:
                        if self.send_queues:
                            state.needs_full = True
                            state.has_data.set()
                        else:
                            await self._send_full_frame_direct(state)
                    state.wants_update = True

                elif msg_type == 4:  # KeyEvent
                    payload = await reader.readexactly(7)
                    down = payload[0]
                    keysym = struct.unpack(">I", payload[3:7])[0]

                    self.logger.debug(
                        f"KeyEvent from client {client_id}: "
                        f"keysym=0x{keysym:04x} down={down} "
                        f"ctrl={state.ctrl_pressed} "
                        f"can_control={state.can_control}")

                    # Track Ctrl state for grab sequence
                    if keysym in (XK_Control_L, XK_Control_R):
                        state.ctrl_pressed = bool(down)

                    # Ctrl + grab key: claim control token
                    if keysym == self.grab_keysym and down and \
                            state.ctrl_pressed and state.can_control:
                        if self.controller is not state:
                            self.controller = state
                            self.logger.info(
                                f"client {client_id} grabbed control")
                        # Consume the grab key -- don't forward
                        continue

                    # Ctrl + release key: release control token
                    if keysym == RELEASE_KEYSYM and down and \
                            state.ctrl_pressed and \
                            self.controller is state:
                        self.controller = None
                        self.logger.info(
                            f"client {client_id} released control")
                        continue

                    # Forward to upstream if this client has control
                    if state is self.controller and \
                            self.up_writer is not None:
                        self.up_writer.write(b"\x04" + payload)
                        await self.up_writer.drain()

                elif msg_type == 5:  # PointerEvent
                    payload = await reader.readexactly(5)

                    # Forward to upstream if this client has control
                    if state is self.controller and \
                            self.up_writer is not None:
                        self.up_writer.write(b"\x05" + payload)
                        await self.up_writer.drain()

                elif msg_type == 6:  # ClientCutText
                    await reader.readexactly(3)
                    length = struct.unpack(">I",
                                           await reader.readexactly(4))[0]
                    await reader.readexactly(length)

                else:
                    self.logger.warning(f"Unknown downstream message: {msg_type}")  # noqa
                    break

        except (asyncio.IncompleteReadError, ConnectionResetError):
            self.logger.info(f"client {client_id} disconnected: {addr}")

        except Exception as e:
            self.logger.error(f"exception handling client {client_id}: {e}",
                              exc_info=True)

        finally:
            if self.controller is state:
                self.controller = None
                self.logger.info(
                    f"client {client_id} released control (disconnected)")
            self.clients.pop(client_id, None)
            if state.writer_task is not None:
                state.writer_task.cancel()
            writer.close()

    # --------------------------------------------------------
    async def start(self):
        # Must connect upstream first to get server_init for clients
        while True:
            try:
                await self.connect_upstream()
                break
            except Exception as e:
                if self.reconnect_delay == 0:
                    raise
                self.logger.warning(f"upstream connection failed: {e}")
                self.logger.info(
                    f"retrying in {self.reconnect_delay}s...")
                await asyncio.sleep(self.reconnect_delay)

        self._server = await asyncio.start_server(
            self.handle_client,
            self.downstream_host,
            self.downstream_port
        )

        # Run upstream read/update tasks with reconnect in background
        asyncio.create_task(self._run_upstream())

        async with self._server:
            try:
                await self._server.serve_forever()
            except asyncio.CancelledError:
                pass
