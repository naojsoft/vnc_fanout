#
# proxy.py -- proxy class for vnc_fanout
#
# stdlib imports
import asyncio
import struct

# 3rd party
from Crypto.Cipher import DES

# local
from vnc_fanout import tight

RFB_VERSION = b"RFB 003.008\n"


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
    def __init__(self, reader, writer, pixel_format):
        self.reader = reader
        self.writer = writer
        self.wants_update = False
        self.needs_full = True
        self.supported_encodings = []
        self.zlib_streams = [None, None, None, None]
        self.pixel_format = pixel_format

    @property
    def wants_tight(self):
        return 7 in self.supported_encodings


# ------------------------------------------------------------
# PROXY
# ------------------------------------------------------------

class VNCProxy:

    def __init__(self, logger,
                 upstream_host, upstream_port, upstream_password,
                 downstream_host, downstream_port, downstream_password):
        self.logger = logger
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.upstream_password = upstream_password
        self.downstream_host = downstream_host
        self.downstream_port = downstream_port
        self.downstream_password = downstream_password

        self.clients = set([])

        self.framebuffer = None
        self.fb_width = None
        self.fb_height = None
        self.bpp = 4  # assuming 32-bit truecolor RAW

        self.initial_frame_event = asyncio.Event()

    # --------------------------------------------------------
    # UPSTREAM
    # --------------------------------------------------------

    async def connect_upstream(self):
        self.up_reader, self.up_writer = \
            await asyncio.open_connection(self.upstream_host,
                                          self.upstream_port)

        await self.up_reader.readexactly(12)
        self.up_writer.write(RFB_VERSION)
        await self.up_writer.drain()

        nsec = ord(await self.up_reader.readexactly(1))
        sec_types = await self.up_reader.readexactly(nsec)  # noqa

        self.up_writer.write(b"\x02")
        await self.up_writer.drain()

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

        asyncio.create_task(self.upstream_update_loop())
        asyncio.create_task(self.read_upstream())

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

            await self.dispatch_rectangles(rectangles)

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

    async def dispatch_rectangles(self, rects):
        """Fan out a FramebufferUpdate to all active clients.

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

        for client in self.clients:
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
                await client.writer.drain()
            except Exception as e:
                dead.append(client)
                self.logger.error(
                    f"exception writing to client: {e}; closing...")

        for c in dead:
            self.clients.discard(c)

    async def send_full_frame(self, client):
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

        client.writer.write(msg)
        await client.writer.drain()

    # --------------------------------------------------------
    # CLIENT HANDLER
    # --------------------------------------------------------

    async def handle_client(self, reader, writer):
        state = ClientState(reader, writer, self.pixel_format)
        self.clients.add(state)

        try:
            # Version
            writer.write(RFB_VERSION)
            await writer.drain()
            await reader.readexactly(12)

            # Auth
            writer.write(b"\x01\x02")
            await writer.drain()
            await reader.readexactly(1)

            challenge = b"ProxyAuthChallenge!"[:16]
            writer.write(challenge)
            await writer.drain()

            resp = await reader.readexactly(16)
            if resp != vnc_encrypt(challenge, self.downstream_password):
                writer.write(struct.pack(">I", 1))
                await writer.drain()
                return

            writer.write(struct.pack(">I", 0))
            await writer.drain()

            await reader.readexactly(1)  # ClientInit

            writer.write(self.server_init)
            await writer.drain()

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
                        await self.send_full_frame(state)
                        state.needs_full = False
                        state.wants_update = True
                    else:
                        state.wants_update = True

                elif msg_type == 4:  # KeyEvent
                    await reader.readexactly(7)

                elif msg_type == 5:  # PointerEvent
                    await reader.readexactly(5)

                elif msg_type == 6:  # ClientCutText
                    await reader.readexactly(3)
                    length = struct.unpack(">I",
                                           await reader.readexactly(4))[0]
                    await reader.readexactly(length)

                else:
                    self.logger.warning(f"Unknown downstream message: {msg_type}")  # noqa
                    break

        except (asyncio.IncompleteReadError, ConnectionResetError):
            self.logger.info("client disconnected")

        except Exception as e:
            self.logger.error(f"exception handling client: {e}", exc_info=True)

        finally:
            self.clients.discard(state)
            writer.close()

    # --------------------------------------------------------
    async def start(self):
        await self.connect_upstream()

        server = await asyncio.start_server(
            self.handle_client,
            self.downstream_host,
            self.downstream_port
        )

        async with server:
            await server.serve_forever()
