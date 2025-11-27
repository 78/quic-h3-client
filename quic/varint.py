"""
QUIC Variable-Length Integer Encoding/Decoding (RFC 9000 Section 16)
"""

import struct


def decode_varint(data: bytes, offset: int = 0) -> tuple:
    """
    Decode QUIC variable-length integer.
    
    Args:
        data: Bytes to decode from
        offset: Starting offset in data
        
    Returns:
        tuple: (value, bytes_consumed)
    """
    first_byte = data[offset]
    prefix = first_byte >> 6
    
    if prefix == 0:
        return first_byte & 0x3f, 1
    elif prefix == 1:
        value = struct.unpack(">H", data[offset:offset+2])[0] & 0x3fff
        return value, 2
    elif prefix == 2:
        value = struct.unpack(">I", data[offset:offset+4])[0] & 0x3fffffff
        return value, 4
    else:
        value = struct.unpack(">Q", data[offset:offset+8])[0] & 0x3fffffffffffffff
        return value, 8


def encode_varint(value: int) -> bytes:
    """
    Encode integer using QUIC variable-length encoding.
    
    Args:
        value: Integer to encode (0 to 2^62-1)
        
    Returns:
        bytes: Encoded value (1, 2, 4, or 8 bytes)
    """
    if value <= 63:
        return struct.pack("B", value)
    elif value <= 16383:
        return struct.pack(">H", value | 0x4000)
    elif value <= 1073741823:
        return struct.pack(">I", value | 0x80000000)
    else:
        return struct.pack(">Q", value | 0xC000000000000000)

