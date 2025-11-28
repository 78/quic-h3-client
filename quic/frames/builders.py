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


def build_max_data_frame(max_data: int) -> bytes:
    """
    Build QUIC MAX_DATA frame for connection-level flow control.
    
    Frame Type: 0x10
    
    This frame informs the peer of the maximum amount of data that can be 
    sent on the connection as a whole.
    
    Args:
        max_data: The new maximum data limit (cumulative)
        
    Returns:
        bytes: Complete MAX_DATA frame
    """
    frame = encode_varint(0x10)  # Frame type: MAX_DATA
    frame += encode_varint(max_data)
    return frame


def build_max_stream_data_frame(stream_id: int, max_stream_data: int) -> bytes:
    """
    Build QUIC MAX_STREAM_DATA frame for stream-level flow control.
    
    Frame Type: 0x11
    
    This frame informs the peer of the maximum amount of data that can be 
    sent on a specific stream.
    
    Args:
        stream_id: The stream ID
        max_stream_data: The new maximum data limit for this stream (cumulative)
        
    Returns:
        bytes: Complete MAX_STREAM_DATA frame
    """
    frame = encode_varint(0x11)  # Frame type: MAX_STREAM_DATA
    frame += encode_varint(stream_id)
    frame += encode_varint(max_stream_data)
    return frame


def build_retire_connection_id_frame(sequence: int) -> bytes:
    """
    Build QUIC RETIRE_CONNECTION_ID frame.
    
    Frame Type: 0x19
    
    This frame is used to indicate that the endpoint will no longer use
    a connection ID that was issued by its peer.
    
    Args:
        sequence: The sequence number of the connection ID being retired
        
    Returns:
        bytes: Complete RETIRE_CONNECTION_ID frame
    """
    frame = encode_varint(0x19)  # Frame type: RETIRE_CONNECTION_ID
    frame += encode_varint(sequence)
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


def build_path_challenge_frame(data: bytes) -> bytes:
    """
    Build QUIC PATH_CHALLENGE frame (RFC 9000 Section 19.17).
    
    Frame Type: 0x1a
    
    PATH_CHALLENGE frames are used to check reachability to the peer
    and for path validation during connection migration.
    
    Frame format:
    - Type (varint): 0x1a
    - Data (8 bytes): Arbitrary data to be echoed in PATH_RESPONSE
    
    Args:
        data: 8 bytes of arbitrary data
        
    Returns:
        bytes: Complete PATH_CHALLENGE frame
        
    Raises:
        ValueError: If data is not exactly 8 bytes
    """
    if len(data) != 8:
        raise ValueError(f"PATH_CHALLENGE data must be exactly 8 bytes, got {len(data)}")
    
    frame = encode_varint(0x1a)  # Frame type: PATH_CHALLENGE
    frame += data
    return frame


def build_path_response_frame(data: bytes) -> bytes:
    """
    Build QUIC PATH_RESPONSE frame (RFC 9000 Section 19.18).
    
    Frame Type: 0x1b
    
    PATH_RESPONSE frames are sent in response to PATH_CHALLENGE frames.
    The data field must contain the same data received in the PATH_CHALLENGE.
    
    Frame format:
    - Type (varint): 0x1b
    - Data (8 bytes): Data from received PATH_CHALLENGE
    
    Args:
        data: 8 bytes of data copied from PATH_CHALLENGE
        
    Returns:
        bytes: Complete PATH_RESPONSE frame
        
    Raises:
        ValueError: If data is not exactly 8 bytes
    """
    if len(data) != 8:
        raise ValueError(f"PATH_RESPONSE data must be exactly 8 bytes, got {len(data)}")
    
    frame = encode_varint(0x1b)  # Frame type: PATH_RESPONSE
    frame += data
    return frame


def build_datagram_frame(data: bytes, include_length: bool = True) -> bytes:
    """
    Build QUIC DATAGRAM frame (RFC 9221).
    
    DATAGRAM frames are used to transmit application data with unreliable delivery.
    They are not retransmitted on loss and are not subject to flow control.
    
    Frame Types:
    - 0x30: DATAGRAM without Length field (data extends to end of packet)
    - 0x31: DATAGRAM with Length field
    
    Frame format (with length):
    - Type (varint): 0x31
    - Length (varint): Length of data
    - Datagram Data: Application data
    
    Frame format (without length):
    - Type (varint): 0x30
    - Datagram Data: Application data (extends to end of packet)
    
    Args:
        data: Application data to send as datagram
        include_length: If True, include length field (0x31), otherwise (0x30)
        
    Returns:
        bytes: Complete DATAGRAM frame
        
    Notes:
        - DATAGRAM frames can only be sent after both endpoints have advertised
          max_datagram_frame_size transport parameter
        - The data size must not exceed the peer's max_datagram_frame_size
        - DATAGRAM frames are ack-eliciting but unreliable
    """
    if include_length:
        frame = encode_varint(0x31)  # DATAGRAM with Length
        frame += encode_varint(len(data))
        frame += data
    else:
        frame = encode_varint(0x30)  # DATAGRAM without Length
        frame += data
    
    return frame

