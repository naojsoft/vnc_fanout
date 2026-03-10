#
# tight.py -- Tight encoding for downstream VNC clients
#
import struct
import zlib


__all__ = ["encode_rect", "TIGHT_MAX_WIDTH"]

TIGHT_MAX_WIDTH = 2040
TIGHT_MAX_HEIGHT = 64


def compact_length(length):
    """Encode length in Tight's 1-3 byte compact format."""
    buf = bytearray()
    buf.append(length & 0x7F)
    if length > 0x7F:
        buf[0] |= 0x80
        buf.append((length >> 7) & 0x7F)
        if length > 0x3FFF:
            buf[1] |= 0x80
            buf.append((length >> 14) & 0xFF)
    return bytes(buf)


def use_tpixel(pixel_format):
    """Check if TPIXEL (3-byte) format should be used instead of 4-byte."""
    bpp = pixel_format[0]
    depth = pixel_format[1]
    true_color = pixel_format[3]
    if bpp != 32 or depth != 24 or not true_color:
        return False
    r_max, g_max, b_max = struct.unpack(">HHH", pixel_format[4:10])
    return r_max == 255 and g_max == 255 and b_max == 255


def pixels_to_tpixel(data, pixel_format):
    """Convert 32bpp pixel data to 3-byte TPIXEL (R, G, B) format.

    Uses byte-array slicing for speed — TPIXEL requires byte-aligned
    shifts so we can compute the byte offset for each channel directly.
    """
    big_endian = pixel_format[2]
    r_shift = pixel_format[10]
    g_shift = pixel_format[11]
    b_shift = pixel_format[12]

    if big_endian:
        r_off = (24 - r_shift) // 8
        g_off = (24 - g_shift) // 8
        b_off = (24 - b_shift) // 8
    else:
        r_off = r_shift // 8
        g_off = g_shift // 8
        b_off = b_shift // 8

    n = len(data) // 4
    result = bytearray(n * 3)
    result[0::3] = data[r_off::4]
    result[1::3] = data[g_off::4]
    result[2::3] = data[b_off::4]
    return bytes(result)


def is_solid_rect(data, bpp):
    """Check if all pixels in the rectangle are the same color."""
    pixel = data[:bpp]
    return data == pixel * (len(data) // bpp)


def encode_fill(pixel_bytes):
    """FillCompression: control byte 0x80 + single pixel."""
    return b'\x80' + pixel_bytes


def encode_basic_copy(data, client_state, stream_id=0):
    """BasicCompression with CopyFilter using persistent zlib stream."""
    control = (stream_id & 0x03) << 4

    if len(data) < 12:
        return bytes([control]) + data

    if client_state.zlib_streams[stream_id] is None:
        client_state.zlib_streams[stream_id] = zlib.compressobj(
            level=6, method=zlib.DEFLATED, wbits=zlib.MAX_WBITS
        )

    compressor = client_state.zlib_streams[stream_id]
    compressed = compressor.compress(data) + compressor.flush(zlib.Z_SYNC_FLUSH)

    return bytes([control]) + compact_length(len(compressed)) + compressed


def encode_rect(data, w, h, server_pixel_format, bpp, client_state):
    """Encode a rectangle using Tight encoding.

    Uses the client's pixel format for TPIXEL determination (must match
    what the client's Tight decoder expects) and the server's pixel format
    for extracting RGB values from the raw pixel data.
    """
    tpixel = use_tpixel(client_state.pixel_format)

    if is_solid_rect(data, bpp):
        pixel = data[:bpp]
        if tpixel:
            pixel = pixels_to_tpixel(pixel, server_pixel_format)
        return encode_fill(pixel)

    pixel_data = pixels_to_tpixel(data, server_pixel_format) if tpixel else data
    return encode_basic_copy(pixel_data, client_state, stream_id=0)
