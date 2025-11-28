"""
QUIC Frame Processor - Parse and dispatch incoming frames

Handles parsing of all QUIC frame types from decrypted packet payloads
and dispatches to appropriate handlers via callbacks.
"""

from typing import Optional, Callable, Dict, Any
from dataclasses import dataclass, field

from quic.varint import decode_varint


@dataclass
class FrameEvent:
    """Event generated from parsing a frame."""
    type: str
    data: Dict[str, Any] = field(default_factory=dict)


class FrameProcessor:
    """
    Parses QUIC frames from decrypted payloads.
    
    Dispatches parsed frames to registered callbacks for handling.
    This separates low-level parsing from business logic.
    """
    
    def __init__(self, debug: bool = False):
        self.debug = debug
        
        # Callbacks for different frame types
        self.on_ack: Optional[Callable[[int, int, int, int], None]] = None  # largest, delay, first_range, range_count
        self.on_crypto: Optional[Callable[[int, bytes], None]] = None  # offset, data
        self.on_stream: Optional[Callable[[int, int, bytes, bool], None]] = None  # stream_id, offset, data, fin
        self.on_max_data: Optional[Callable[[int], None]] = None  # max_data
        self.on_max_stream_data: Optional[Callable[[int, int], None]] = None  # stream_id, max_data
        self.on_new_connection_id: Optional[Callable[[int, int, bytes, bytes], None]] = None  # seq, retire_prior, cid, token
        self.on_connection_close: Optional[Callable[[int, str, bool], None]] = None  # error_code, reason, is_app
        self.on_handshake_done: Optional[Callable[[], None]] = None
        self.on_data_blocked: Optional[Callable[[int], None]] = None  # blocked_at
        self.on_stream_data_blocked: Optional[Callable[[int, int], None]] = None  # stream_id, blocked_at
        self.on_path_challenge: Optional[Callable[[bytes], None]] = None  # 8-byte data
        self.on_path_response: Optional[Callable[[bytes], None]] = None  # 8-byte data
        self.on_ping: Optional[Callable[[], None]] = None
        self.on_reset_stream: Optional[Callable[[int, int, int], None]] = None  # stream_id, error, final_size
        self.on_stop_sending: Optional[Callable[[int, int], None]] = None  # stream_id, error
        self.on_max_streams_bidi: Optional[Callable[[int], None]] = None
        self.on_max_streams_uni: Optional[Callable[[int], None]] = None
        self.on_retire_connection_id: Optional[Callable[[int], None]] = None  # seq
        self.on_new_token: Optional[Callable[[bytes], None]] = None  # token
        self.on_datagram: Optional[Callable[[bytes], None]] = None  # datagram data
    
    def process_payload(self, payload: bytes) -> bool:
        """
        Parse all frames from a decrypted packet payload.
        
        Args:
            payload: Decrypted packet payload
            
        Returns:
            bool: True if any ack-eliciting frames were found
        """
        offset = 0
        ack_eliciting = False
        
        while offset < len(payload):
            frame_type, consumed = decode_varint(payload, offset)
            offset += consumed
            
            # PADDING (0x00)
            if frame_type == 0x00:
                continue
            
            # PING (0x01)
            elif frame_type == 0x01:
                ack_eliciting = True
                if self.debug:
                    print(f"        PING")
                if self.on_ping:
                    self.on_ping()
            
            # ACK (0x02, 0x03)
            elif frame_type == 0x02 or frame_type == 0x03:
                offset = self._parse_ack(payload, offset, frame_type == 0x03)
            
            # RESET_STREAM (0x04)
            elif frame_type == 0x04:
                ack_eliciting = True
                offset = self._parse_reset_stream(payload, offset)
            
            # STOP_SENDING (0x05)
            elif frame_type == 0x05:
                ack_eliciting = True
                offset = self._parse_stop_sending(payload, offset)
            
            # CRYPTO (0x06)
            elif frame_type == 0x06:
                ack_eliciting = True
                offset = self._parse_crypto(payload, offset)
            
            # NEW_TOKEN (0x07)
            elif frame_type == 0x07:
                ack_eliciting = True
                offset = self._parse_new_token(payload, offset)
            
            # STREAM (0x08-0x0f)
            elif frame_type >= 0x08 and frame_type <= 0x0f:
                ack_eliciting = True
                offset = self._parse_stream(payload, offset, frame_type)
            
            # MAX_DATA (0x10)
            elif frame_type == 0x10:
                ack_eliciting = True
                max_data, consumed = decode_varint(payload, offset)
                offset += consumed
                if self.debug:
                    print(f"        MAX_DATA: {max_data}")
                if self.on_max_data:
                    self.on_max_data(max_data)
            
            # MAX_STREAM_DATA (0x11)
            elif frame_type == 0x11:
                ack_eliciting = True
                stream_id, consumed = decode_varint(payload, offset)
                offset += consumed
                max_data, consumed = decode_varint(payload, offset)
                offset += consumed
                if self.debug:
                    print(f"        MAX_STREAM_DATA: stream={stream_id}, max={max_data}")
                if self.on_max_stream_data:
                    self.on_max_stream_data(stream_id, max_data)
            
            # MAX_STREAMS (BIDI) (0x12)
            elif frame_type == 0x12:
                ack_eliciting = True
                max_streams, consumed = decode_varint(payload, offset)
                offset += consumed
                if self.debug:
                    print(f"        MAX_STREAMS (BIDI): {max_streams}")
                if self.on_max_streams_bidi:
                    self.on_max_streams_bidi(max_streams)
            
            # MAX_STREAMS (UNI) (0x13)
            elif frame_type == 0x13:
                ack_eliciting = True
                max_streams, consumed = decode_varint(payload, offset)
                offset += consumed
                if self.debug:
                    print(f"        MAX_STREAMS (UNI): {max_streams}")
                if self.on_max_streams_uni:
                    self.on_max_streams_uni(max_streams)
            
            # DATA_BLOCKED (0x14)
            elif frame_type == 0x14:
                ack_eliciting = True
                blocked_at, consumed = decode_varint(payload, offset)
                offset += consumed
                if self.debug:
                    print(f"        DATA_BLOCKED: {blocked_at}")
                if self.on_data_blocked:
                    self.on_data_blocked(blocked_at)
            
            # STREAM_DATA_BLOCKED (0x15)
            elif frame_type == 0x15:
                ack_eliciting = True
                stream_id, consumed = decode_varint(payload, offset)
                offset += consumed
                blocked_at, consumed = decode_varint(payload, offset)
                offset += consumed
                if self.debug:
                    print(f"        STREAM_DATA_BLOCKED: stream={stream_id}, at={blocked_at}")
                if self.on_stream_data_blocked:
                    self.on_stream_data_blocked(stream_id, blocked_at)
            
            # NEW_CONNECTION_ID (0x18)
            elif frame_type == 0x18:
                ack_eliciting = True
                offset = self._parse_new_connection_id(payload, offset)
            
            # RETIRE_CONNECTION_ID (0x19)
            elif frame_type == 0x19:
                ack_eliciting = True
                seq_num, consumed = decode_varint(payload, offset)
                offset += consumed
                if self.debug:
                    print(f"        RETIRE_CONNECTION_ID: seq={seq_num}")
                if self.on_retire_connection_id:
                    self.on_retire_connection_id(seq_num)
            
            # PATH_CHALLENGE (0x1a)
            elif frame_type == 0x1a:
                ack_eliciting = True
                if offset + 8 > len(payload):
                    if self.debug:
                        print(f"        ⚠️ PATH_CHALLENGE: insufficient data")
                    break
                data = payload[offset:offset + 8]
                offset += 8
                if self.debug:
                    print(f"        PATH_CHALLENGE: {data.hex()}")
                if self.on_path_challenge:
                    self.on_path_challenge(data)
            
            # PATH_RESPONSE (0x1b)
            elif frame_type == 0x1b:
                ack_eliciting = True
                if offset + 8 > len(payload):
                    if self.debug:
                        print(f"        ⚠️ PATH_RESPONSE: insufficient data")
                    break
                data = payload[offset:offset + 8]
                offset += 8
                if self.debug:
                    print(f"        PATH_RESPONSE: {data.hex()}")
                if self.on_path_response:
                    self.on_path_response(data)
            
            # CONNECTION_CLOSE (0x1c - QUIC layer)
            elif frame_type == 0x1c:
                offset = self._parse_connection_close(payload, offset, is_app=False)
            
            # CONNECTION_CLOSE (0x1d - Application layer)
            elif frame_type == 0x1d:
                offset = self._parse_connection_close(payload, offset, is_app=True)
            
            # HANDSHAKE_DONE (0x1e)
            elif frame_type == 0x1e:
                ack_eliciting = True
                if self.debug:
                    print(f"        HANDSHAKE_DONE 🎉")
                if self.on_handshake_done:
                    self.on_handshake_done()
            
            # DATAGRAM (0x30 - without length, 0x31 - with length) - RFC 9221
            elif frame_type == 0x30 or frame_type == 0x31:
                ack_eliciting = True
                offset = self._parse_datagram(payload, offset, frame_type)
            
            # Unknown frame type
            else:
                if self.debug:
                    print(f"        Unknown frame: 0x{frame_type:02x}")
                ack_eliciting = True
                break
        
        return ack_eliciting
    
    def _parse_ack(self, payload: bytes, offset: int, has_ecn: bool) -> int:
        """Parse ACK frame."""
        largest_ack, consumed = decode_varint(payload, offset)
        offset += consumed
        ack_delay, consumed = decode_varint(payload, offset)
        offset += consumed
        ack_range_count, consumed = decode_varint(payload, offset)
        offset += consumed
        first_ack_range, consumed = decode_varint(payload, offset)
        offset += consumed
        
        # Skip additional ACK ranges
        for _ in range(ack_range_count):
            _, consumed = decode_varint(payload, offset)  # gap
            offset += consumed
            _, consumed = decode_varint(payload, offset)  # ack range
            offset += consumed
        
        # Skip ECN counts if present
        if has_ecn:
            for _ in range(3):
                _, consumed = decode_varint(payload, offset)
                offset += consumed
        
        if self.debug:
            print(f"        ACK: largest={largest_ack}, delay={ack_delay}, first_range={first_ack_range}")
        
        if self.on_ack:
            self.on_ack(largest_ack, ack_delay, first_ack_range, ack_range_count)
        
        return offset
    
    def _parse_crypto(self, payload: bytes, offset: int) -> int:
        """Parse CRYPTO frame."""
        crypto_offset, consumed = decode_varint(payload, offset)
        offset += consumed
        crypto_length, consumed = decode_varint(payload, offset)
        offset += consumed
        crypto_data = payload[offset:offset + crypto_length]
        offset += crypto_length
        
        if self.debug:
            print(f"        CRYPTO: offset={crypto_offset}, len={crypto_length}")
        
        if self.on_crypto:
            self.on_crypto(crypto_offset, crypto_data)
        
        return offset
    
    def _parse_stream(self, payload: bytes, offset: int, frame_type: int) -> int:
        """Parse STREAM frame."""
        has_off = (frame_type & 0x04) != 0
        has_len = (frame_type & 0x02) != 0
        has_fin = (frame_type & 0x01) != 0
        
        stream_id, consumed = decode_varint(payload, offset)
        offset += consumed
        
        stream_offset = 0
        if has_off:
            stream_offset, consumed = decode_varint(payload, offset)
            offset += consumed
        
        if has_len:
            length, consumed = decode_varint(payload, offset)
            offset += consumed
            data = payload[offset:offset + length]
            offset += length
        else:
            data = payload[offset:]
            offset = len(payload)
        
        if self.debug:
            print(f"        STREAM: id={stream_id}, off={stream_offset}, len={len(data)}, fin={has_fin}")
        
        if self.on_stream:
            self.on_stream(stream_id, stream_offset, data, has_fin)
        
        return offset
    
    def _parse_reset_stream(self, payload: bytes, offset: int) -> int:
        """Parse RESET_STREAM frame."""
        stream_id, consumed = decode_varint(payload, offset)
        offset += consumed
        error_code, consumed = decode_varint(payload, offset)
        offset += consumed
        final_size, consumed = decode_varint(payload, offset)
        offset += consumed
        
        if self.debug:
            print(f"        RESET_STREAM: stream={stream_id}, error={error_code}")
        
        if self.on_reset_stream:
            self.on_reset_stream(stream_id, error_code, final_size)
        
        return offset
    
    def _parse_stop_sending(self, payload: bytes, offset: int) -> int:
        """Parse STOP_SENDING frame."""
        stream_id, consumed = decode_varint(payload, offset)
        offset += consumed
        error_code, consumed = decode_varint(payload, offset)
        offset += consumed
        
        if self.debug:
            print(f"        STOP_SENDING: stream={stream_id}, error={error_code}")
        
        if self.on_stop_sending:
            self.on_stop_sending(stream_id, error_code)
        
        return offset
    
    def _parse_new_token(self, payload: bytes, offset: int) -> int:
        """Parse NEW_TOKEN frame."""
        token_length, consumed = decode_varint(payload, offset)
        offset += consumed
        token = payload[offset:offset + token_length]
        offset += token_length
        
        if self.debug:
            print(f"        NEW_TOKEN: {token_length} bytes")
        
        if self.on_new_token:
            self.on_new_token(token)
        
        return offset
    
    def _parse_new_connection_id(self, payload: bytes, offset: int) -> int:
        """Parse NEW_CONNECTION_ID frame."""
        seq_num, consumed = decode_varint(payload, offset)
        offset += consumed
        retire_prior, consumed = decode_varint(payload, offset)
        offset += consumed
        cid_len = payload[offset]
        offset += 1
        cid = payload[offset:offset + cid_len]
        offset += cid_len
        reset_token = payload[offset:offset + 16]
        offset += 16
        
        if self.debug:
            print(f"        NEW_CONNECTION_ID: seq={seq_num}, retire_prior={retire_prior}")
        
        if self.on_new_connection_id:
            self.on_new_connection_id(seq_num, retire_prior, cid, reset_token)
        
        return offset
    
    def _parse_connection_close(self, payload: bytes, offset: int, is_app: bool) -> int:
        """Parse CONNECTION_CLOSE frame."""
        error_code, consumed = decode_varint(payload, offset)
        offset += consumed
        
        # QUIC layer has frame_type field, application layer doesn't
        if not is_app:
            _, consumed = decode_varint(payload, offset)  # frame_type
            offset += consumed
        
        reason_len, consumed = decode_varint(payload, offset)
        offset += consumed
        reason = payload[offset:offset + reason_len].decode('utf-8', errors='replace')
        offset += reason_len
        
        layer = "Application" if is_app else "QUIC"
        if self.debug:
            print(f"        ❌ CONNECTION_CLOSE ({layer}): error={error_code}")
            if reason:
                print(f"           Reason: {reason}")
        
        if self.on_connection_close:
            self.on_connection_close(error_code, reason, is_app)
        
        return offset
    
    def _parse_datagram(self, payload: bytes, offset: int, frame_type: int) -> int:
        """
        Parse DATAGRAM frame (RFC 9221).
        
        Frame Types:
        - 0x30: DATAGRAM without Length field (data extends to end of packet)
        - 0x31: DATAGRAM with Length field
        
        Args:
            payload: Packet payload
            offset: Current offset after frame type
            frame_type: 0x30 or 0x31
            
        Returns:
            int: New offset after parsing
        """
        has_length = (frame_type == 0x31)
        
        if has_length:
            # DATAGRAM with Length field
            length, consumed = decode_varint(payload, offset)
            offset += consumed
            data = payload[offset:offset + length]
            offset += length
        else:
            # DATAGRAM without Length field - data extends to end of packet
            data = payload[offset:]
            offset = len(payload)
        
        if self.debug:
            print(f"        DATAGRAM: len={len(data)}, has_length={has_length}")
        
        if self.on_datagram:
            self.on_datagram(data)
        
        return offset

