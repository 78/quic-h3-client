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
        tuple: (value, bytes_consumed) or (0, 0) if insufficient data
    """
    if offset >= len(data):
        return 0, 0
    
    first_byte = data[offset]
    prefix = first_byte >> 6
    
    if prefix == 0:
        return first_byte & 0x3f, 1
    elif prefix == 1:
        if offset + 2 > len(data):
            return 0, 0
        value = struct.unpack(">H", data[offset:offset+2])[0] & 0x3fff
        return value, 2
    elif prefix == 2:
        if offset + 4 > len(data):
            return 0, 0
        value = struct.unpack(">I", data[offset:offset+4])[0] & 0x3fffffff
        return value, 4
    else:
        if offset + 8 > len(data):
            return 0, 0
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


def decode_packet_number(largest_pn: int, truncated_pn: int, pn_nbits: int) -> int:
    """
    Reconstruct full packet number from truncated value.
    
    RFC 9000 Appendix A.3: Sample Packet Number Decoding Algorithm
    
    Args:
        largest_pn: Largest packet number received so far (-1 if none received)
        truncated_pn: Truncated packet number from wire (1-4 bytes)
        pn_nbits: Number of bits in truncated_pn (8, 16, 24, or 32)
        
    Returns:
        int: Full reconstructed packet number
    """
    # If no packets received yet, the truncated PN is the full PN
    if largest_pn < 0:
        return truncated_pn
    
    expected_pn = largest_pn + 1
    pn_win = 1 << pn_nbits
    pn_hwin = pn_win >> 1
    pn_mask = pn_win - 1
    
    # Calculate candidate packet number
    candidate_pn = (expected_pn & ~pn_mask) | truncated_pn
    
    # Adjust if candidate is outside the expected window
    if candidate_pn <= expected_pn - pn_hwin and candidate_pn < (1 << 62) - pn_win:
        return candidate_pn + pn_win
    if candidate_pn > expected_pn + pn_hwin and candidate_pn >= pn_win:
        return candidate_pn - pn_win
    return candidate_pn

