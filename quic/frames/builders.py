"""
QUIC Frame Builders (RFC 9000)
"""

import struct
from ..varint import encode_varint


def build_crypto_frame(offset: int, data: bytes) -> bytes:
    """
    Build QUIC CRYPTO frame.
    
    Frame format:
    - Type (varint): 0x06
    - Offset (varint): Byte offset in the stream
    - Length (varint): Length of data
    - Crypto Data
    
    Args:
        offset: Byte offset in the crypto stream
        data: Crypto data (TLS handshake messages)
        
    Returns:
        bytes: Complete CRYPTO frame
    """
    frame = encode_varint(0x06)  # Frame type: CRYPTO
    frame += encode_varint(offset)
    frame += encode_varint(len(data))
    frame += data
    return frame


def build_ack_frame(largest_ack: int, ack_delay: int = 0, first_ack_range: int = 0,
                    ack_ranges: list = None) -> bytes:
    """
    Build QUIC ACK frame with support for multiple ACK ranges (gaps).
    
    Frame format:
    - Type (varint): 0x02 (ACK) or 0x03 (ACK_ECN)
    - Largest Acknowledged (varint)
    - ACK Delay (varint)
    - ACK Range Count (varint)
    - First ACK Range (varint)
    - [Additional ACK Ranges: Gap, ACK Range Length pairs]
    
    Args:
        largest_ack: Largest packet number being acknowledged
        ack_delay: Encoded ACK delay
        first_ack_range: Number of contiguous packets before largest_ack (largest - smallest in first range)
        ack_ranges: Optional list of (start, end) tuples for additional ranges.
                    These should be sorted by descending packet number (highest first).
                    Format: [(range1_start, range1_end), (range2_start, range2_end), ...]
                    where range1 is the highest range (already encoded in first_ack_range),
                    and subsequent ranges represent gaps.
        
    Returns:
        bytes: Complete ACK frame
    """
    frame = encode_varint(0x02)  # Frame type: ACK (without ECN)
    frame += encode_varint(largest_ack)  # Largest Acknowledged
    frame += encode_varint(ack_delay)    # ACK Delay
    
    # Calculate additional ACK ranges (excluding the first range)
    if ack_ranges and len(ack_ranges) > 1:
        # ack_ranges[0] is the first range (already covered by first_ack_range)
        # ack_ranges[1:] are additional ranges that need gap encoding
        additional_ranges = ack_ranges[1:]
        frame += encode_varint(len(additional_ranges))  # ACK Range Count
        frame += encode_varint(first_ack_range)  # First ACK Range
        
        # Encode additional ranges
        # For each range, we encode:
        # - Gap: number of missing packets - 2 (gap = smallest_in_prev_range - largest_in_current_range - 2)
        # - ACK Range Length: number of acknowledged packets - 1 (length = largest - smallest)
        prev_smallest = largest_ack - first_ack_range
        for range_start, range_end in additional_ranges:
            # range_start is the largest in this range, range_end is the smallest
            gap = prev_smallest - range_start - 2
            ack_range_len = range_start - range_end
            frame += encode_varint(gap)
            frame += encode_varint(ack_range_len)
            prev_smallest = range_end
    else:
        frame += encode_varint(0)  # ACK Range Count (0 = no gaps)
        frame += encode_varint(first_ack_range)  # First ACK Range
    
    return frame


def build_padding_frame(length: int) -> bytes:
    """
    Build QUIC PADDING frames.
    
    PADDING frames are simply zero bytes.
    
    Args:
        length: Number of padding bytes
        
    Returns:
        bytes: Padding bytes
    """
    return b"\x00" * length


def build_stream_frame(stream_id: int, data: bytes, offset: int = 0, fin: bool = False) -> bytes:
    """
    Build QUIC STREAM frame.
    
    Frame Type: 0x08-0x0f depending on flags:
    - 0x08 = base (no offset, no length, no fin)
    - 0x01 = FIN flag
    - 0x02 = LEN flag (include length field)
    - 0x04 = OFF flag (include offset field)
    
    Args:
        stream_id: The stream ID
        data: The stream data
        offset: Byte offset in the stream (0 for first frame)
        fin: True if this is the final frame for this stream
        
    Returns:
        bytes: Complete STREAM frame
    """
    # Build frame type with flags
    frame_type = 0x08  # Base STREAM frame type
    if fin:
        frame_type |= 0x01  # FIN flag
    if len(data) > 0:
        frame_type |= 0x02  # LEN flag (always include length for clarity)
    if offset > 0:
        frame_type |= 0x04  # OFF flag
    
    frame = encode_varint(frame_type)
    frame += encode_varint(stream_id)
    
    if offset > 0:
        frame += encode_varint(offset)
    
    # Always include length (LEN flag set)
    frame += encode_varint(len(data))
    frame += data
    
    return frame


def build_new_connection_id_frame(sequence: int, retire_prior_to: int,
                                   connection_id: bytes, stateless_reset_token: bytes) -> bytes:
    """
    Build QUIC NEW_CONNECTION_ID frame.
    
    Frame Type: 0x18
    
    Args:
        sequence: Sequence number for this connection ID
        retire_prior_to: Connection IDs with sequence < this should be retired
        connection_id: The new connection ID (1-20 bytes)
        stateless_reset_token: 16-byte stateless reset token
        
    Returns:
        bytes: Complete NEW_CONNECTION_ID frame
    """
    frame = encode_varint(0x18)  # Frame type: NEW_CONNECTION_ID
    frame += encode_varint(sequence)
    frame += encode_varint(retire_prior_to)
    frame += struct.pack("B", len(connection_id))  # Connection ID length
    frame += connection_id
    frame += stateless_reset_token  # 16 bytes
    return frame


def build_connection_close_frame(error_code: int = 0, frame_type: int = None, 
                                  reason: str = "", is_application: bool = False) -> bytes:
    """
    Build QUIC CONNECTION_CLOSE frame.
    
    Frame Types:
    - 0x1c: CONNECTION_CLOSE (QUIC layer error, includes frame type field)
    - 0x1d: CONNECTION_CLOSE (Application layer error, no frame type field)
    
    Args:
        error_code: Error code (0 = NO_ERROR for graceful close)
        frame_type: The frame type that triggered the error (only for 0x1c)
        reason: Human-readable reason phrase (optional)
        is_application: If True, use application-level close (0x1d)
        
    Returns:
        bytes: Complete CONNECTION_CLOSE frame
    """
    reason_bytes = reason.encode('utf-8') if reason else b""
    
    if is_application:
        # Application-level CONNECTION_CLOSE (0x1d)
        # No frame type field
        frame = encode_varint(0x1d)
        frame += encode_varint(error_code)
        frame += encode_varint(len(reason_bytes))
        frame += reason_bytes
    else:
        # QUIC-level CONNECTION_CLOSE (0x1c)
        # Includes frame type field
        frame = encode_varint(0x1c)
        frame += encode_varint(error_code)
        frame += encode_varint(frame_type if frame_type is not None else 0)
        frame += encode_varint(len(reason_bytes))
        frame += reason_bytes
    
    return frame

