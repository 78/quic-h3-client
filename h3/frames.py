"""
HTTP/3 Frame Building and Parsing (RFC 9114)
"""

from quic.varint import encode_varint, decode_varint
from .constants import (
    H3_FRAME_TYPE_NAMES, H3_SETTINGS_NAMES,
    QPACK_STATIC_TABLE, QPACK_STATIC_TABLE_BY_NAME
)

# HPACK/QPACK Huffman Decoding Table (RFC 7541 Appendix B)
# This is the Huffman code table used for HPACK and QPACK
HUFFMAN_DECODE_TABLE = {
    # Format: huffman_code (as int) -> (symbol, bit_length)
    # Build from RFC 7541 Appendix B
}

# Pre-built huffman decoder (simplified - using lookup approach)
def _build_huffman_decoder():
    """Build Huffman decoding lookup table."""
    # Huffman codes from RFC 7541 Appendix B
    huffman_codes = [
        (0x1ff8, 13, 0), (0x7fffd8, 23, 1), (0xfffffe2, 28, 2), (0xfffffe3, 28, 3),
        (0xfffffe4, 28, 4), (0xfffffe5, 28, 5), (0xfffffe6, 28, 6), (0xfffffe7, 28, 7),
        (0xfffffe8, 28, 8), (0xffffea, 24, 9), (0x3ffffffc, 30, 10), (0xfffffe9, 28, 11),
        (0xfffffea, 28, 12), (0x3ffffffd, 30, 13), (0xfffffeb, 28, 14), (0xfffffec, 28, 15),
        (0xfffffed, 28, 16), (0xfffffee, 28, 17), (0xfffffef, 28, 18), (0xffffff0, 28, 19),
        (0xffffff1, 28, 20), (0xffffff2, 28, 21), (0x3ffffffe, 30, 22), (0xffffff3, 28, 23),
        (0xffffff4, 28, 24), (0xffffff5, 28, 25), (0xffffff6, 28, 26), (0xffffff7, 28, 27),
        (0xffffff8, 28, 28), (0xffffff9, 28, 29), (0xffffffa, 28, 30), (0xffffffb, 28, 31),
        (0x14, 6, 32),  # ' '
        (0x3f8, 10, 33), (0x3f9, 10, 34), (0xffa, 12, 35), (0x1ff9, 13, 36),
        (0x15, 6, 37), (0xf8, 8, 38), (0x7fa, 11, 39), (0x3fa, 10, 40), (0x3fb, 10, 41),
        (0xf9, 8, 42), (0x7fb, 11, 43), (0xfa, 8, 44), (0x16, 6, 45), (0x17, 6, 46),
        (0x18, 6, 47), (0x0, 5, 48), (0x1, 5, 49), (0x2, 5, 50), (0x19, 6, 51),
        (0x1a, 6, 52), (0x1b, 6, 53), (0x1c, 6, 54), (0x1d, 6, 55), (0x1e, 6, 56),
        (0x1f, 6, 57), (0x5c, 7, 58), (0xfb, 8, 59), (0x7ffc, 15, 60), (0x20, 6, 61),
        (0xffb, 12, 62), (0x3fc, 10, 63), (0x1ffa, 13, 64), (0x21, 6, 65), (0x5d, 7, 66),
        (0x5e, 7, 67), (0x5f, 7, 68), (0x60, 7, 69), (0x61, 7, 70), (0x62, 7, 71),
        (0x63, 7, 72), (0x64, 7, 73), (0x65, 7, 74), (0x66, 7, 75), (0x67, 7, 76),
        (0x68, 7, 77), (0x69, 7, 78), (0x6a, 7, 79), (0x6b, 7, 80), (0x6c, 7, 81),
        (0x6d, 7, 82), (0x6e, 7, 83), (0x6f, 7, 84), (0x70, 7, 85), (0x71, 7, 86),
        (0x72, 7, 87), (0xfc, 8, 88), (0x73, 7, 89), (0xfd, 8, 90), (0x1ffb, 13, 91),
        (0x7fff0, 19, 92), (0x1ffc, 13, 93), (0x3ffc, 14, 94), (0x22, 6, 95), (0x7ffd, 15, 96),
        (0x3, 5, 97), (0x23, 6, 98), (0x4, 5, 99), (0x24, 6, 100), (0x5, 5, 101),
        (0x25, 6, 102), (0x26, 6, 103), (0x27, 6, 104), (0x6, 5, 105), (0x74, 7, 106),
        (0x75, 7, 107), (0x28, 6, 108), (0x29, 6, 109), (0x2a, 6, 110), (0x7, 5, 111),
        (0x2b, 6, 112), (0x76, 7, 113), (0x2c, 6, 114), (0x8, 5, 115), (0x9, 5, 116),
        (0x2d, 6, 117), (0x77, 7, 118), (0x78, 7, 119), (0x79, 7, 120), (0x7a, 7, 121),
        (0x7b, 7, 122), (0x7ffe, 15, 123), (0x7fc, 11, 124), (0x3ffd, 14, 125), (0x1ffd, 13, 126),
        (0xffffffc, 28, 127), (0xfffe6, 20, 128), (0x3fffd2, 22, 129), (0xfffe7, 20, 130),
        (0xfffe8, 20, 131), (0x3fffd3, 22, 132), (0x3fffd4, 22, 133), (0x3fffd5, 22, 134),
        (0x7fffd9, 23, 135), (0x3fffd6, 22, 136), (0x7fffda, 23, 137), (0x7fffdb, 23, 138),
        (0x7fffdc, 23, 139), (0x7fffdd, 23, 140), (0x7fffde, 23, 141), (0xffffeb, 24, 142),
        (0x7fffdf, 23, 143), (0xffffec, 24, 144), (0xffffed, 24, 145), (0x3fffd7, 22, 146),
        (0x7fffe0, 23, 147), (0xffffee, 24, 148), (0x7fffe1, 23, 149), (0x7fffe2, 23, 150),
        (0x7fffe3, 23, 151), (0x7fffe4, 23, 152), (0x1fffdc, 21, 153), (0x3fffd8, 22, 154),
        (0x7fffe5, 23, 155), (0x3fffd9, 22, 156), (0x7fffe6, 23, 157), (0x7fffe7, 23, 158),
        (0xffffef, 24, 159), (0x3fffda, 22, 160), (0x1fffdd, 21, 161), (0xfffe9, 20, 162),
        (0x3fffdb, 22, 163), (0x3fffdc, 22, 164), (0x7fffe8, 23, 165), (0x7fffe9, 23, 166),
        (0x1fffde, 21, 167), (0x7fffea, 23, 168), (0x3fffdd, 22, 169), (0x3fffde, 22, 170),
        (0xfffff0, 24, 171), (0x1fffdf, 21, 172), (0x3fffdf, 22, 173), (0x7fffeb, 23, 174),
        (0x7fffec, 23, 175), (0x1fffe0, 21, 176), (0x1fffe1, 21, 177), (0x3fffe0, 22, 178),
        (0x1fffe2, 21, 179), (0x7fffed, 23, 180), (0x3fffe1, 22, 181), (0x7fffee, 23, 182),
        (0x7fffef, 23, 183), (0xfffea, 20, 184), (0x3fffe2, 22, 185), (0x3fffe3, 22, 186),
        (0x3fffe4, 22, 187), (0x7ffff0, 23, 188), (0x3fffe5, 22, 189), (0x3fffe6, 22, 190),
        (0x7ffff1, 23, 191), (0x3ffffe0, 26, 192), (0x3ffffe1, 26, 193), (0xfffeb, 20, 194),
        (0x7fff1, 19, 195), (0x3fffe7, 22, 196), (0x7ffff2, 23, 197), (0x3fffe8, 22, 198),
        (0x1ffffec, 25, 199), (0x3ffffe2, 26, 200), (0x3ffffe3, 26, 201), (0x3ffffe4, 26, 202),
        (0x7ffffde, 27, 203), (0x7ffffdf, 27, 204), (0x3ffffe5, 26, 205), (0xfffff1, 24, 206),
        (0x1ffffed, 25, 207), (0x7fff2, 19, 208), (0x1fffe3, 21, 209), (0x3ffffe6, 26, 210),
        (0x7ffffe0, 27, 211), (0x7ffffe1, 27, 212), (0x3ffffe7, 26, 213), (0x7ffffe2, 27, 214),
        (0xfffff2, 24, 215), (0x1fffe4, 21, 216), (0x1fffe5, 21, 217), (0x3ffffe8, 26, 218),
        (0x3ffffe9, 26, 219), (0xffffffd, 28, 220), (0x7ffffe3, 27, 221), (0x7ffffe4, 27, 222),
        (0x7ffffe5, 27, 223), (0xfffec, 20, 224), (0xfffff3, 24, 225), (0xfffed, 20, 226),
        (0x1fffe6, 21, 227), (0x3fffe9, 22, 228), (0x1fffe7, 21, 229), (0x1fffe8, 21, 230),
        (0x7ffff3, 23, 231), (0x3fffea, 22, 232), (0x3fffeb, 22, 233), (0x1ffffee, 25, 234),
        (0x1ffffef, 25, 235), (0xfffff4, 24, 236), (0xfffff5, 24, 237), (0x3ffffea, 26, 238),
        (0x7ffff4, 23, 239), (0x3ffffeb, 26, 240), (0x7ffffe6, 27, 241), (0x3ffffec, 26, 242),
        (0x3ffffed, 26, 243), (0x7ffffe7, 27, 244), (0x7ffffe8, 27, 245), (0x7ffffe9, 27, 246),
        (0x7ffffea, 27, 247), (0x7ffffeb, 27, 248), (0xfffffffe, 28, 249), (0x7ffffec, 27, 250),
        (0x7ffffed, 27, 251), (0x7ffffee, 27, 252), (0x7ffffef, 27, 253), (0x7fffff0, 27, 254),
        (0x3ffffee, 26, 255), (0x3fffffff, 30, 256),  # EOS
    ]
    
    decoder = {}
    for code, bits, sym in huffman_codes:
        decoder[(code, bits)] = sym
    return decoder, huffman_codes

HUFFMAN_DECODER, HUFFMAN_CODES = _build_huffman_decoder()


def huffman_decode(data: bytes) -> str:
    """
    Decode Huffman encoded string.
    
    Args:
        data: Huffman encoded bytes
        
    Returns:
        str: Decoded string
    """
    result = []
    buffer = 0
    buffer_bits = 0
    
    for byte in data:
        buffer = (buffer << 8) | byte
        buffer_bits += 8
        
        while buffer_bits >= 5:  # Minimum code length is 5 bits
            found = False
            # Try matching from longest to shortest codes
            for max_bits in range(min(buffer_bits, 30), 4, -1):
                code = buffer >> (buffer_bits - max_bits)
                if (code, max_bits) in HUFFMAN_DECODER:
                    sym = HUFFMAN_DECODER[(code, max_bits)]
                    if sym == 256:  # EOS
                        return ''.join(result)
                    result.append(chr(sym))
                    buffer_bits -= max_bits
                    buffer &= (1 << buffer_bits) - 1
                    found = True
                    break
            
            if not found:
                # No match found, might be partial at end
                break
    
    return ''.join(result)


def build_h3_settings_frame(settings: dict) -> bytes:
    """
    Build HTTP/3 SETTINGS frame.
    
    Frame Type: 0x04
    
    Args:
        settings: Dict of {setting_id: value}
        
    Returns:
        bytes: Complete SETTINGS frame
    """
    # Build settings payload
    payload = b""
    for setting_id, value in settings.items():
        payload += encode_varint(setting_id)
        payload += encode_varint(value)
    
    # Build frame: type + length + payload
    frame = encode_varint(0x04)  # SETTINGS frame type
    frame += encode_varint(len(payload))
    frame += payload
    return frame


def build_h3_max_push_id_frame(push_id: int) -> bytes:
    """
    Build HTTP/3 MAX_PUSH_ID frame.
    
    Frame Type: 0x0d
    
    Args:
        push_id: Maximum push ID the client is willing to accept
        
    Returns:
        bytes: Complete MAX_PUSH_ID frame
    """
    payload = encode_varint(push_id)
    frame = encode_varint(0x0d)  # MAX_PUSH_ID frame type
    frame += encode_varint(len(payload))
    frame += payload
    return frame


def build_h3_control_stream_data(settings: dict, max_push_id: int = 8) -> bytes:
    """
    Build complete HTTP/3 control stream data.
    
    Control stream data format:
    1. Stream type (varint): 0x00 for control stream
    2. SETTINGS frame
    3. Optional: MAX_PUSH_ID frame
    
    Args:
        settings: HTTP/3 settings to send
        max_push_id: Maximum push ID (default 8)
        
    Returns:
        bytes: Complete control stream initialization data
    """
    data = encode_varint(0x00)  # Control stream type
    data += build_h3_settings_frame(settings)
    data += build_h3_max_push_id_frame(max_push_id)
    return data


def build_qpack_set_dynamic_table_capacity(capacity: int) -> bytes:
    """
    Build QPACK Set Dynamic Table Capacity instruction (RFC 9204 Section 4.3.1).
    
    Instruction format:
    - 001xxxxx (5-bit prefix for capacity value)
    
    Args:
        capacity: Dynamic table capacity in bytes
        
    Returns:
        bytes: Encoded Set Dynamic Table Capacity instruction
    """
    # Set Dynamic Table Capacity: 001xxxxx with 5-bit prefix
    prefix_bits = 5
    max_first = (1 << prefix_bits) - 1  # 31
    
    if capacity < max_first:
        # Fits in prefix: 001 + 5-bit value = 0x20 | capacity
        return bytes([0x20 | capacity])
    
    # Need continuation bytes
    result = bytearray([0x20 | max_first])  # 0x3f
    capacity -= max_first
    
    while capacity >= 128:
        result.append((capacity & 0x7f) | 0x80)
        capacity >>= 7
    
    result.append(capacity)
    return bytes(result)


def build_h3_qpack_encoder_stream_data(max_table_capacity: int = 0) -> bytes:
    """
    Build QPACK encoder stream data.
    
    Encoder stream data format:
    1. Stream type (varint): 0x02 for QPACK encoder
    2. Set Dynamic Table Capacity instruction (optional)
    
    According to RFC 9204 Section 2.1.2:
    - The encoder MUST NOT send a Set Dynamic Table Capacity that exceeds
      the decoder's (server's) SETTINGS_QPACK_MAX_TABLE_CAPACITY.
    - Since we send this BEFORE receiving server's SETTINGS, we should NOT
      send a Set Dynamic Table Capacity instruction.
    - For simple clients that don't use dynamic table encoding, just sending
      the stream type is sufficient.
    
    Args:
        max_table_capacity: QPACK dynamic table capacity (default 0 = don't send)
        
    Returns:
        bytes: Encoder stream initialization data
    """
    data = encode_varint(0x02)  # QPACK Encoder stream type
    
    # NOTE: Do NOT send Set Dynamic Table Capacity here!
    # We haven't received server's SETTINGS yet, so we don't know their
    # QPACK_MAX_TABLE_CAPACITY. Sending a non-zero capacity could cause
    # QPACK_ENCODER_STREAM_ERROR (0x201) if server's limit is lower.
    # For a simple client, we use static table + literals for encoding.
    
    return data


def build_h3_qpack_decoder_stream_data() -> bytes:
    """
    Build QPACK decoder stream data.
    
    Decoder stream data format:
    1. Stream type (varint): 0x03 for QPACK decoder
    
    For a basic client, we don't send any decoder instructions.
    
    Returns:
        bytes: Decoder stream initialization data
    """
    return encode_varint(0x03)  # QPACK Decoder stream type


def encode_qpack_int(value: int, prefix_bits: int) -> bytes:
    """
    Encode integer using QPACK integer encoding (RFC 9204 Section 4.1.1).
    
    Args:
        value: Integer to encode
        prefix_bits: Number of prefix bits (affects max first byte value)
        
    Returns:
        bytes: Encoded integer
    """
    max_first = (1 << prefix_bits) - 1
    
    if value < max_first:
        return bytes([value])
    
    result = bytes([max_first])
    value -= max_first
    
    while value >= 128:
        result += bytes([(value & 0x7f) | 0x80])
        value >>= 7
    
    result += bytes([value])
    return result


def encode_qpack_string(s: str, huffman: bool = False) -> bytes:
    """
    Encode string for QPACK (RFC 9204).
    
    Args:
        s: String to encode
        huffman: Use Huffman encoding (not implemented, always False)
        
    Returns:
        bytes: Encoded string
    """
    data = s.encode('utf-8')
    # For simplicity, we don't use Huffman encoding
    # Format: H (1 bit, 0 for no huffman) + length (7-bit prefix) + data
    length_encoded = encode_qpack_int(len(data), 7)
    # Ensure H bit is 0
    return length_encoded + data


def encode_literal_with_name_ref(name_idx: int, value: str, static: bool = True) -> bytes:
    """
    Encode a literal header field with name reference (RFC 9204 Section 4.5.4).
    
    Format: 01 N T Index(4+) + H Value_Length(7+) + Value
    - N = 0 (never indexed)
    - T = 1 for static table, 0 for dynamic table
    
    Args:
        name_idx: Index of the name in the table
        value: Header value
        static: True for static table reference
        
    Returns:
        bytes: Encoded header field
    """
    # Base byte: 01NT = 0x50 for static (T=1), 0x40 for dynamic (T=0)
    base = 0x50 if static else 0x40
    
    # 4-bit prefix for index
    if name_idx < 15:
        result = bytes([base | name_idx])
    else:
        result = bytes([base | 0x0f])
        # Encode remaining value with variable-length encoding
        remaining = name_idx - 15
        while remaining >= 128:
            result += bytes([(remaining & 0x7f) | 0x80])
            remaining >>= 7
        result += bytes([remaining])
    
    # Append encoded value
    result += encode_qpack_string(value)
    return result


def build_qpack_request_headers(method: str, scheme: str, authority: str, path: str, 
                                 extra_headers: dict = None) -> bytes:
    """
    Build QPACK encoded request headers.
    
    Uses static table references where possible, literal otherwise.
    
    Args:
        method: HTTP method (GET, POST, etc.)
        scheme: URL scheme (https, http)
        authority: Host:port
        path: Request path
        extra_headers: Additional headers dict
        
    Returns:
        bytes: QPACK encoded header block
    """
    encoded = b""
    
    # Required Insert Count and Delta Base (both 0 for static-only)
    encoded += b"\x00\x00"  # Required Insert Count = 0, Sign = 0, Delta Base = 0
    
    # Encode :method
    method_upper = method.upper()
    method_idx = None
    if method_upper in ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'CONNECT']:
        for idx, val in QPACK_STATIC_TABLE_BY_NAME.get(':method', []):
            if val == method_upper:
                method_idx = idx
                break
    
    if method_idx is not None:
        # Indexed header field (static table) - RFC 9204 Section 4.5.2
        # Format: 1 T Index(6+), T=1 for static table
        encoded += bytes([0xc0 | method_idx])  # method_idx is always < 63
    else:
        # Literal with name reference (static) - RFC 9204 Section 4.5.4
        name_idx = QPACK_STATIC_TABLE_BY_NAME.get(':method', [(15, '')])[0][0]
        encoded += encode_literal_with_name_ref(name_idx, method, static=True)
    
    # Encode :scheme
    scheme_lower = scheme.lower()
    scheme_idx = None
    for idx, val in QPACK_STATIC_TABLE_BY_NAME.get(':scheme', []):
        if val == scheme_lower:
            scheme_idx = idx
            break
    
    if scheme_idx is not None:
        # Indexed header field (static table)
        encoded += bytes([0xc0 | scheme_idx])  # scheme_idx is always < 63
    else:
        name_idx = QPACK_STATIC_TABLE_BY_NAME.get(':scheme', [(22, '')])[0][0]
        encoded += encode_literal_with_name_ref(name_idx, scheme, static=True)
    
    # Encode :authority (literal with name reference from static table)
    # :authority is at index 0
    encoded += encode_literal_with_name_ref(0, authority, static=True)
    
    # Encode :path
    if path == '/':
        # Index 1 is ":path" = "/" - indexed field from static table
        encoded += bytes([0xc0 | 1])
    else:
        # :path is at index 1
        encoded += encode_literal_with_name_ref(1, path, static=True)
    
    # Encode extra headers
    if extra_headers:
        for name, value in extra_headers.items():
            name_lower = name.lower()
            
            # Try to find in static table
            found = False
            if name_lower in QPACK_STATIC_TABLE_BY_NAME:
                for idx, static_val in QPACK_STATIC_TABLE_BY_NAME[name_lower]:
                    if static_val == value:
                        # Full match - indexed field from static table
                        # Use 6-bit prefix encoding for indexed field
                        if idx < 63:
                            encoded += bytes([0xc0 | idx])
                        else:
                            # Index >= 63 needs variable-length encoding
                            encoded += bytes([0xc0 | 0x3f])
                            remaining = idx - 63
                            while remaining >= 128:
                                encoded += bytes([(remaining & 0x7f) | 0x80])
                                remaining >>= 7
                            encoded += bytes([remaining])
                        found = True
                        break
                
                if not found:
                    # Name only match - literal with name reference from static table
                    name_idx = QPACK_STATIC_TABLE_BY_NAME[name_lower][0][0]
                    encoded += encode_literal_with_name_ref(name_idx, value, static=True)
                    found = True
            
            if not found:
                # Literal with literal name - RFC 9204 Section 4.5.6
                # Format: 001 N H NameLen(3+) Name H ValueLen(7+) Value
                # N=0, H=0 (no Huffman)
                name_bytes = name_lower.encode('utf-8')
                
                # First byte: 001 N=0 H=0 NameLen(3-bit prefix)
                # 0x20 = 00100000, last 3 bits for name length prefix
                if len(name_bytes) < 7:
                    # Name length fits in 3-bit prefix
                    encoded += bytes([0x20 | len(name_bytes)])
                else:
                    # Name length >= 7, needs multi-byte encoding
                    encoded += bytes([0x27])  # 0x20 | 0x07 (all prefix bits set)
                    remaining = len(name_bytes) - 7
                    while remaining >= 128:
                        encoded += bytes([(remaining & 0x7f) | 0x80])
                        remaining >>= 7
                    encoded += bytes([remaining])
                
                # Name string (raw bytes, no H bit / length prefix)
                encoded += name_bytes
                
                # Value with H=0 and 7-bit length prefix
                encoded += encode_qpack_string(value)
    
    return encoded


def build_h3_headers_frame(headers_block: bytes) -> bytes:
    """
    Build HTTP/3 HEADERS frame.
    
    Frame Type: 0x01
    
    Args:
        headers_block: QPACK encoded headers
        
    Returns:
        bytes: Complete HEADERS frame
    """
    frame = encode_varint(0x01)  # HEADERS frame type
    frame += encode_varint(len(headers_block))
    frame += headers_block
    return frame


def build_h3_data_frame(data: bytes) -> bytes:
    """
    Build HTTP/3 DATA frame.
    
    Frame Type: 0x00
    
    Args:
        data: Request/response body data
        
    Returns:
        bytes: Complete DATA frame
    """
    frame = encode_varint(0x00)  # DATA frame type
    frame += encode_varint(len(data))
    frame += data
    return frame


def parse_h3_frames(data: bytes, debug: bool = False) -> list:
    """
    Parse HTTP/3 frames from stream data.
    
    HTTP/3 Frame format:
    - Frame Type (varint)
    - Frame Length (varint)
    - Frame Payload (Length bytes)
    
    Args:
        data: Raw stream data
        debug: Enable debug output
    
    Returns:
        list: List of parsed frame dicts
    """
    frames = []
    offset = 0
    
    while offset < len(data):
        # Need at least 2 bytes for type and length
        if offset + 2 > len(data):
            break
        
        # Frame Type (varint)
        frame_type, type_consumed = decode_varint(data, offset)
        if type_consumed == 0:
            break
        offset += type_consumed
        
        # Frame Length (varint)
        if offset >= len(data):
            break
        frame_length, length_consumed = decode_varint(data, offset)
        if length_consumed == 0:
            break
        offset += length_consumed
        
        # Frame Payload
        if offset + frame_length > len(data):
            if debug:
                print(f"    ⚠️  H3 frame truncated: need {frame_length} bytes, have {len(data) - offset}")
            break
        
        payload = data[offset:offset + frame_length]
        offset += frame_length
        
        # Check if this is a GREASE frame type (0x1f * N + 0x21)
        is_grease = (frame_type >= 0x21) and ((frame_type - 0x21) % 0x1f == 0)
        
        if frame_type in H3_FRAME_TYPE_NAMES:
            frame_type_name = H3_FRAME_TYPE_NAMES[frame_type]
        elif is_grease:
            frame_type_name = f"GREASE(0x{frame_type:x})"
        else:
            frame_type_name = f"Extension(0x{frame_type:x})"
        
        frame = {
            "frame_type": frame_type_name,
            "frame_type_id": frame_type,
            "length": frame_length,
        }
        
        if debug:
            # Don't print GREASE/Extension frames to reduce noise
            if not (is_grease or frame_type_name.startswith("Extension")):
                print(f"    📦 H3 Frame: {frame_type_name} (type=0x{frame_type:x}, len={frame_length})")
        
        # Parse specific frame types
        if frame_type == 0x00:  # DATA
            frame["data"] = payload
            frame["data_preview"] = payload[:50].hex() + "..." if len(payload) > 50 else payload.hex()
            if debug:
                print(f"        Data: {frame['data_preview']}")
        
        elif frame_type == 0x01:  # HEADERS
            frame["encoded_headers"] = payload
            frame["encoded_headers_preview"] = payload[:50].hex() + "..." if len(payload) > 50 else payload.hex()
            if debug:
                print(f"        Encoded Headers (QPACK): {frame['encoded_headers_preview']}")
        
        elif frame_type == 0x04:  # SETTINGS
            settings = parse_h3_settings(payload, debug)
            frame["settings"] = settings
        
        elif frame_type == 0x07:  # GOAWAY
            if len(payload) >= 1:
                stream_id, _ = decode_varint(payload, 0)
                frame["stream_id"] = stream_id
                if debug:
                    print(f"        Stream ID: {stream_id}")
        
        elif frame_type == 0x0d:  # MAX_PUSH_ID
            if len(payload) >= 1:
                push_id, _ = decode_varint(payload, 0)
                frame["push_id"] = push_id
                if debug:
                    print(f"        Push ID: {push_id}")
        
        elif frame_type == 0x03:  # CANCEL_PUSH
            if len(payload) >= 1:
                push_id, _ = decode_varint(payload, 0)
                frame["push_id"] = push_id
                if debug:
                    print(f"        Cancelled Push ID: {push_id}")
        
        else:
            frame["raw_payload"] = payload.hex()
            if debug:
                print(f"        Raw Payload: {payload.hex()[:64]}...")
        
        frames.append(frame)
    
    return frames


def parse_h3_settings(data: bytes, debug: bool = False) -> dict:
    """
    Parse HTTP/3 SETTINGS frame payload.
    
    SETTINGS frame format:
    - Repeated: Setting ID (varint) + Setting Value (varint)
    
    Args:
        data: Raw SETTINGS payload
        debug: Enable debug output
    
    Returns:
        dict: Settings {setting_name: value}
    """
    settings = {}
    offset = 0
    
    while offset < len(data):
        # Setting ID (varint)
        setting_id, id_consumed = decode_varint(data, offset)
        if id_consumed == 0:
            break
        offset += id_consumed
        
        # Setting Value (varint)
        if offset >= len(data):
            break
        setting_value, value_consumed = decode_varint(data, offset)
        if value_consumed == 0:
            break
        offset += value_consumed
        
        setting_name = H3_SETTINGS_NAMES.get(setting_id, f"unknown(0x{setting_id:02x})")
        settings[setting_name] = setting_value
        
        if debug:
            print(f"        {setting_name} (0x{setting_id:02x}): {setting_value}")
    
    return settings


def decode_qpack_int(data: bytes, offset: int, prefix_bits: int) -> tuple:
    """
    Decode QPACK integer encoding (RFC 9204 Section 4.1.1).
    
    Args:
        data: Raw bytes
        offset: Current offset
        prefix_bits: Number of prefix bits
        
    Returns:
        tuple: (value, bytes_consumed) - returns (0, 0) if data is incomplete
    """
    if offset >= len(data):
        return 0, 0
    
    max_first = (1 << prefix_bits) - 1
    value = data[offset] & max_first
    consumed = 1
    
    if value < max_first:
        return value, consumed
    
    # Multi-byte encoding
    shift = 0
    complete = False
    while offset + consumed < len(data):
        byte = data[offset + consumed]
        value += (byte & 0x7f) << shift
        consumed += 1
        if not (byte & 0x80):
            # Last byte of multi-byte sequence (MSB is 0)
            complete = True
            break
        shift += 7
    
    # If we exited the loop without finding the last byte, data is incomplete
    if not complete:
        return 0, 0
    
    return value, consumed


def decode_qpack_string(data: bytes, offset: int) -> tuple:
    """
    Decode QPACK string (RFC 9204).
    
    Args:
        data: Raw bytes
        offset: Current offset
        
    Returns:
        tuple: (string, bytes_consumed)
    """
    if offset >= len(data):
        return "", 0
    
    # First byte: H bit (huffman) + 7-bit length prefix
    huffman = (data[offset] & 0x80) != 0
    length, len_consumed = decode_qpack_int(data, offset, 7)
    
    if offset + len_consumed + length > len(data):
        return "", 0
    
    string_bytes = data[offset + len_consumed:offset + len_consumed + length]
    
    if huffman:
        try:
            return huffman_decode(string_bytes), len_consumed + length
        except:
            return f"[huffman:{string_bytes.hex()}]", len_consumed + length
    
    try:
        return string_bytes.decode('utf-8'), len_consumed + length
    except:
        return string_bytes.hex(), len_consumed + length


def decode_qpack_headers(data: bytes, debug: bool = False, dynamic_table=None) -> tuple:
    """
    Decode QPACK encoded headers (RFC 9204).
    
    Args:
        data: QPACK encoded header block
        debug: Enable debug output
        dynamic_table: QPACKDynamicTable instance for dynamic table lookups
        
    Returns:
        tuple: (headers_list, req_insert_count)
            - headers_list: List of (name, value) tuples
            - req_insert_count: Required Insert Count from header block prefix
              (used to determine if Section Acknowledgment should be sent)
    """
    headers = []
    offset = 0
    
    if len(data) < 2:
        return headers, 0
    
    # Required Insert Count (prefix 8) - RFC 9204 Section 4.5.1
    # Encoded Required Insert Count (ERIC)
    encoded_insert_count, consumed = decode_qpack_int(data, offset, 8)
    offset += consumed
    
    # Sign bit and Delta Base (prefix 7)
    if offset >= len(data):
        return headers, 0
    sign = (data[offset] & 0x80) != 0
    delta_base, consumed = decode_qpack_int(data, offset, 7)
    offset += consumed
    
    # Calculate actual Required Insert Count and Base (RFC 9204 Section 4.5.1)
    if encoded_insert_count == 0:
        req_insert_count = 0
        base = 0
    else:
        # Decode Required Insert Count
        # Full Range = 2 * MaxEntries
        # MaxEntries = floor(QPACK_MAX_TABLE_CAPACITY / 32)
        max_entries = 4096 // 32 if dynamic_table is None else dynamic_table.max_capacity // 32
        if max_entries == 0:
            max_entries = 1  # Avoid division by zero
        full_range = 2 * max_entries
        
        if encoded_insert_count > full_range:
            # Error case per RFC, but handle gracefully
            req_insert_count = encoded_insert_count - 1
        else:
            # RFC 9204 Section 4.5.1:
            # MaxValue = TotalNumberOfInserts + MaxEntries
            # MaxWrapped = floor(MaxValue / FullRange) * FullRange
            # ReqInsertCount = MaxWrapped + EncodedInsertCount - 1
            total_inserts = dynamic_table.insert_count if dynamic_table else 0
            max_value = total_inserts + max_entries
            max_wrapped = (max_value // full_range) * full_range
            
            req_insert_count = max_wrapped + encoded_insert_count - 1
            
            # Handle wrap-around case
            if req_insert_count > max_value:
                if req_insert_count <= full_range:
                    # Decompression error per RFC
                    req_insert_count = 0
                else:
                    req_insert_count -= full_range
    
    # Calculate Base (RFC 9204 Section 4.5.1)
    if sign:
        # Base = ReqInsertCount - DeltaBase - 1
        base = req_insert_count - delta_base - 1
    else:
        # Base = ReqInsertCount + DeltaBase
        base = req_insert_count + delta_base
    
    if debug:
        print(f"        QPACK: req_insert_count={req_insert_count}, base={base}, delta_base={delta_base}, sign={sign}")
    
    # Parse header field representations
    while offset < len(data):
        byte = data[offset]
        
        if byte & 0x80:  # Indexed Header Field
            # 1Txxxxxx - T indicates static(1) or dynamic(0) table
            static_ref = (byte & 0x40) != 0
            index, consumed = decode_qpack_int(data, offset, 6)
            offset += consumed
            
            if static_ref:
                # Static table reference
                if index < len(QPACK_STATIC_TABLE):
                    name, value = QPACK_STATIC_TABLE[index]
                    headers.append((name, value))
                    if debug:
                        print(f"          [{index}] {name}: {value}")
                else:
                    if debug:
                        print(f"          [static:{index}] (invalid index)")
            else:
                # Dynamic table reference (pre-base)
                # Absolute index = Base - index - 1
                # Only valid if req_insert_count > 0
                if req_insert_count == 0:
                    if debug:
                        print(f"          ⚠️ [dynamic:{index}] (invalid: req_insert_count=0)")
                    continue
                    
                entry = None
                if dynamic_table:
                    entry = dynamic_table.get_for_header_decode(index, base, is_post_base=False)
                
                if entry:
                    name, value = entry
                    headers.append((name, value))
                    if debug:
                        print(f"          [dynamic:{index}→abs:{base - index - 1}] {name}: {value}")
                else:
                    if debug:
                        print(f"          [dynamic:{index}] (not decoded - entry not found)")
        
        elif byte & 0x40:  # Literal with Name Reference
            # 01NTxxxx - N: never index, T: static(1) or dynamic(0)
            static_ref = (byte & 0x10) != 0
            name_idx, consumed = decode_qpack_int(data, offset, 4)
            offset += consumed
            
            value, consumed = decode_qpack_string(data, offset)
            offset += consumed
            
            if static_ref:
                # Name from static table
                if name_idx < len(QPACK_STATIC_TABLE):
                    name = QPACK_STATIC_TABLE[name_idx][0]
                else:
                    name = f"[static:{name_idx}]"
            else:
                # Name from dynamic table (pre-base)
                # Only valid if req_insert_count > 0
                if req_insert_count == 0:
                    name = f"[dynamic:{name_idx}]"
                    if debug:
                        print(f"          ⚠️ {name}: {value} (invalid: req_insert_count=0)")
                    headers.append((name, value))
                    continue
                    
                entry = None
                if dynamic_table:
                    entry = dynamic_table.get_for_header_decode(name_idx, base, is_post_base=False)
                
                if entry:
                    name = entry[0]
                else:
                    name = f"[dynamic:{name_idx}]"
            
            headers.append((name, value))
            if debug:
                print(f"          {name}: {value}")
        
        elif byte & 0x20:  # Literal with Literal Name
            # 001NHxxx - N: never index, H: Huffman for name, followed by name and value strings
            # Name uses 3-bit prefix for length (bits 0-2)
            # RFC 9204 Section 4.5.6
            
            # Parse name: H bit is bit 3, length uses 3-bit prefix
            name_huffman = (byte & 0x08) != 0
            name_length, name_len_consumed = decode_qpack_int(data, offset, 3)
            offset += name_len_consumed
            
            if offset + name_length > len(data):
                break
            
            name_bytes = data[offset:offset + name_length]
            offset += name_length
            
            if name_huffman:
                try:
                    name = huffman_decode(name_bytes)
                except:
                    name = f"[huffman:{name_bytes.hex()}]"
            else:
                try:
                    name = name_bytes.decode('utf-8')
                except:
                    name = name_bytes.hex()
            
            # Value uses standard 7-bit prefix
            value, consumed = decode_qpack_string(data, offset)
            offset += consumed
            
            headers.append((name, value))
            if debug:
                print(f"          {name}: {value}")
        
        elif byte & 0x10:  # Indexed Header Field (post-base)
            # 0001xxxx - post-base indexed (references entries after Base)
            index, consumed = decode_qpack_int(data, offset, 4)
            offset += consumed
            
            # Post-base: absolute index = Base + index
            # Only valid if req_insert_count > 0
            if req_insert_count == 0:
                if debug:
                    print(f"          ⚠️ [post-base:{index}] (invalid: req_insert_count=0)")
                continue
            
            entry = None
            if dynamic_table:
                entry = dynamic_table.get_for_header_decode(index, base, is_post_base=True)
            
            if entry:
                name, value = entry
                headers.append((name, value))
                if debug:
                    print(f"          [post-base:{index}→abs:{base + index}] {name}: {value}")
            else:
                if debug:
                    print(f"          [post-base:{index}] (not decoded - entry not found)")
        
        else:
            # 0000Nxxx - Literal with Post-Base Name Reference
            # N: never index, name index uses 3-bit prefix
            # RFC 9204 Section 4.5.5
            name_idx, consumed = decode_qpack_int(data, offset, 3)
            offset += consumed
            
            # Value uses standard 7-bit prefix
            value, consumed = decode_qpack_string(data, offset)
            offset += consumed
            
            # Post-base name reference: absolute index = Base + name_idx
            # Only valid if req_insert_count > 0
            if req_insert_count == 0:
                headers.append((f"[post-base-name:{name_idx}]", value))
                if debug:
                    print(f"          ⚠️ [post-base-name:{name_idx}]: {value} (invalid: req_insert_count=0)")
                continue
            
            entry = None
            if dynamic_table:
                entry = dynamic_table.get_for_header_decode(name_idx, base, is_post_base=True)
            
            if entry:
                name = entry[0]
                headers.append((name, value))
                if debug:
                    print(f"          [post-base-name:{name_idx}] {name}: {value}")
            else:
                headers.append((f"[post-base-name:{name_idx}]", value))
            if debug:
                print(f"          [post-base-name:{name_idx}]: {value}")
    
    return headers, req_insert_count

