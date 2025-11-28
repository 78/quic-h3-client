"""
QUIC Frame Parsers (RFC 9000)
"""

from ..varint import decode_varint
from ..constants import TRANSPORT_PARAM_NAMES, TRANSPORT_PARAM_BINARY, TRANSPORT_PARAM_FLAGS


def parse_quic_frames(payload: bytes, debug: bool = False) -> list:
    """
    Parse QUIC frames from decrypted payload.
    
    Args:
        payload: Decrypted packet payload
        debug: Enable debug output
        
    Returns:
        list: List of parsed frame dicts
    """
    frames = []
    offset = 0
    
    while offset < len(payload):
        # Frame type is variable-length integer
        frame_type, type_len = decode_varint(payload, offset)
        offset += type_len
        
        if frame_type == 0x00:  # PADDING
            # Count consecutive padding bytes
            padding_count = 1
            while offset < len(payload) and payload[offset] == 0x00:
                padding_count += 1
                offset += 1
            frames.append({"type": "PADDING", "length": padding_count})
            
        elif frame_type == 0x01:  # PING
            frames.append({"type": "PING"})
            
        elif frame_type == 0x02 or frame_type == 0x03:  # ACK
            largest_ack, consumed = decode_varint(payload, offset)
            offset += consumed
            ack_delay, consumed = decode_varint(payload, offset)
            offset += consumed
            ack_range_count, consumed = decode_varint(payload, offset)
            offset += consumed
            first_ack_range, consumed = decode_varint(payload, offset)
            offset += consumed
            
            # Parse additional ACK ranges if any
            for _ in range(ack_range_count):
                gap, consumed = decode_varint(payload, offset)
                offset += consumed
                ack_range, consumed = decode_varint(payload, offset)
                offset += consumed
            
            # If ECN (type 0x03), parse ECN counts
            if frame_type == 0x03:
                for _ in range(3):
                    _, consumed = decode_varint(payload, offset)
                    offset += consumed
            
            frames.append({
                "type": "ACK",
                "largest_ack": largest_ack,
                "ack_delay": ack_delay,
                "first_ack_range": first_ack_range
            })
            
        elif frame_type == 0x06:  # CRYPTO
            crypto_offset, consumed = decode_varint(payload, offset)
            offset += consumed
            crypto_length, consumed = decode_varint(payload, offset)
            offset += consumed
            crypto_data = payload[offset:offset + crypto_length]
            offset += crypto_length
            frames.append({
                "type": "CRYPTO",
                "offset": crypto_offset,
                "length": crypto_length,
                "data": crypto_data
            })
            
        elif frame_type == 0x1c:  # CONNECTION_CLOSE
            error_code, consumed = decode_varint(payload, offset)
            offset += consumed
            frame_type_val, consumed = decode_varint(payload, offset)
            offset += consumed
            reason_len, consumed = decode_varint(payload, offset)
            offset += consumed
            reason = payload[offset:offset + reason_len]
            offset += reason_len
            frames.append({
                "type": "CONNECTION_CLOSE",
                "error_code": error_code,
                "frame_type": frame_type_val,
                "reason": reason.decode('utf-8', errors='replace')
            })
            
        else:
            frames.append({"type": f"UNKNOWN(0x{frame_type:02x})", "offset": offset - type_len})
            break  # Stop parsing on unknown frame
    
    return frames


def parse_quic_transport_params(data: bytes) -> dict:
    """
    Parse QUIC Transport Parameters (RFC 9000 Section 18).
    
    Args:
        data: Raw transport parameters data
        
    Returns:
        dict: Parsed parameters {name: value}
    """
    params = {}
    offset = 0
    
    while offset < len(data):
        # Parameter ID (varint)
        param_id, consumed = decode_varint(data, offset)
        if consumed == 0:
            break  # Insufficient data
        offset += consumed
        
        if offset >= len(data):
            break
            
        # Parameter length (varint)
        param_len, consumed = decode_varint(data, offset)
        if consumed == 0:
            break  # Insufficient data
        offset += consumed
        
        if offset + param_len > len(data):
            break
            
        # Parameter value
        param_value = data[offset:offset + param_len]
        offset += param_len
        
        param_name = TRANSPORT_PARAM_NAMES.get(param_id, f"unknown(0x{param_id:02x})")
        
        # Parse specific parameter values
        if param_id in TRANSPORT_PARAM_BINARY:
            # Connection IDs and tokens are raw bytes
            params[param_name] = param_value.hex()
        elif param_id in TRANSPORT_PARAM_FLAGS:
            # Flag parameters (presence means True)
            params[param_name] = True
        elif param_len > 0:
            # Integer values are encoded as varints within the value field
            value, value_consumed = decode_varint(param_value, 0)
            if value_consumed == 0 and len(param_value) > 0:
                # Fallback: treat as raw integer if varint decode fails
                value = int.from_bytes(param_value, 'big')
            
            # Add units for specific parameters
            if param_id == 0x01:  # max_idle_timeout
                params[param_name] = f"{value} ms"
            elif param_id == 0x0b:  # max_ack_delay
                params[param_name] = f"{value} ms"
            else:
                params[param_name] = value
        else:
            # Zero-length value
            params[param_name] = 0
    
    return params

