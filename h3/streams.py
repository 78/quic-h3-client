"""
HTTP/3 Stream Management (RFC 9114)
"""

from quic.varint import decode_varint
from .constants import (
    H3_STREAM_TYPE_CONTROL, H3_STREAM_TYPE_QPACK_ENCODER, 
    H3_STREAM_TYPE_QPACK_DECODER, H3_STREAM_TYPE_NAMES,
    H3_SETTINGS_MAX_TABLE_CAPACITY, H3_SETTINGS_BLOCKED_STREAMS
)
from .frames import parse_h3_frames, decode_qpack_headers


def describe_stream_id(stream_id: int) -> str:
    """
    Describe a QUIC stream ID.
    
    Stream ID format (lowest 2 bits):
    - Bit 0: Initiator (0=client, 1=server)
    - Bit 1: Direction (0=bidirectional, 1=unidirectional)
    
    Args:
        stream_id: QUIC stream ID
        
    Returns:
        str: Human-readable description
    """
    initiator = "Client" if (stream_id & 0x01) == 0 else "Server"
    direction = "Bidirectional" if (stream_id & 0x02) == 0 else "Unidirectional"
    return f"Stream {stream_id} ({initiator}-initiated {direction})"


class H3StreamManager:
    """
    Manages HTTP/3 streams and reassembles data.
    """
    def __init__(self):
        self.streams = {}  # stream_id -> {"type": str, "data": bytes, "offset": int}
        self.control_stream_id = None
        self.qpack_encoder_stream_id = None
        self.qpack_decoder_stream_id = None
        self.peer_settings = {}
        self.local_settings = {
            H3_SETTINGS_MAX_TABLE_CAPACITY: 4096,
            H3_SETTINGS_BLOCKED_STREAMS: 100,
        }
        # Request stream responses
        self.responses = {}  # stream_id -> {"headers": [], "data": bytes, "complete": bool}
    
    def process_stream_data(self, stream_id: int, offset: int, data: bytes, 
                           fin: bool = False, debug: bool = False) -> list:
        """
        Process stream data and return parsed frames/content.
        
        Args:
            stream_id: QUIC stream ID
            offset: Byte offset in stream
            data: Stream data
            fin: True if this is the final data for the stream
            debug: Enable debug output
            
        Returns:
            list: List of parsed items (frames, stream types, etc.)
        """
        results = []
        
        # Initialize stream if needed
        if stream_id not in self.streams:
            self.streams[stream_id] = {
                "type": None,
                "buffer": bytearray(),
                "expected_offset": 0,
            }
        
        stream = self.streams[stream_id]
        
        # Check for out-of-order data
        if offset != stream["expected_offset"]:
            if debug:
                print(f"    ⚠️  Stream {stream_id}: Expected offset {stream['expected_offset']}, got {offset}")
            # For simplicity, we'll store the data at the correct position
            # In production, implement proper reassembly
        
        stream["buffer"].extend(data)
        stream["expected_offset"] = offset + len(data)
        
        # Determine stream type (client vs server, bidirectional vs unidirectional)
        initiator = "client" if (stream_id & 0x01) == 0 else "server"
        direction = "bidi" if (stream_id & 0x02) == 0 else "uni"
        
        if debug:
            print(f"    🔹 Stream {stream_id} ({initiator}-initiated {direction}): offset={offset}, len={len(data)}, fin={fin}")
        
        # For server-initiated unidirectional streams, first byte is stream type
        if direction == "uni" and stream["type"] is None and len(stream["buffer"]) > 0:
            # Parse stream type (varint)
            stream_type, consumed = decode_varint(bytes(stream["buffer"]), 0)
            stream["type"] = stream_type
            stream["type_name"] = H3_STREAM_TYPE_NAMES.get(stream_type, f"Unknown(0x{stream_type:02x})")
            
            if debug:
                print(f"        Stream type: {stream['type_name']} (0x{stream_type:02x})")
            
            # Track critical streams
            if stream_type == H3_STREAM_TYPE_CONTROL:
                if initiator == "server":
                    self.control_stream_id = stream_id
                results.append({
                    "type": "stream_type",
                    "stream_id": stream_id,
                    "stream_type": stream_type,
                    "stream_type_name": stream["type_name"],
                })
            elif stream_type == H3_STREAM_TYPE_QPACK_ENCODER:
                self.qpack_encoder_stream_id = stream_id
                results.append({
                    "type": "stream_type",
                    "stream_id": stream_id,
                    "stream_type": stream_type,
                    "stream_type_name": stream["type_name"],
                })
            elif stream_type == H3_STREAM_TYPE_QPACK_DECODER:
                self.qpack_decoder_stream_id = stream_id
                results.append({
                    "type": "stream_type",
                    "stream_id": stream_id,
                    "stream_type": stream_type,
                    "stream_type_name": stream["type_name"],
                })
        
        # Parse frames on control stream
        if stream["type"] == H3_STREAM_TYPE_CONTROL:
            # Skip the stream type byte for parsing
            frame_data = bytes(stream["buffer"])
            if len(frame_data) > 1:
                # Find where actual frame data starts (after stream type)
                _, type_len = decode_varint(frame_data, 0)
                frame_data = frame_data[type_len:]
                
                frames = parse_h3_frames(frame_data, debug)
                results.extend(frames)
                
                # Update settings from SETTINGS frames
                for frame in frames:
                    if frame.get("frame_type") == "SETTINGS":
                        self.peer_settings.update(frame.get("settings", {}))
        
        # Parse HTTP/3 response on bidirectional request streams
        elif direction == "bidi":
            self._process_request_stream_response(stream_id, stream, fin, debug, results)
        
        return results
    
    def _process_request_stream_response(self, stream_id: int, stream: dict, 
                                         fin: bool, debug: bool, results: list):
        """Process HTTP/3 response frames on a request stream."""
        frame_data = bytes(stream["buffer"])
        if len(frame_data) == 0:
            return
        
        # Initialize response tracking
        if stream_id not in self.responses:
            self.responses[stream_id] = {
                "headers": [],
                "data": bytearray(),
                "complete": False,
                "parsed_offset": 0,
            }
        
        response = self.responses[stream_id]
        
        # Parse HTTP/3 frames starting from where we left off
        offset = response["parsed_offset"]
        
        while offset < len(frame_data):
            # Need at least 2 bytes for type and length
            if offset + 1 > len(frame_data):
                break
            
            # Frame Type (varint)
            frame_type, type_consumed = decode_varint(frame_data, offset)
            if type_consumed == 0:
                break
            
            # Frame Length (varint)
            if offset + type_consumed >= len(frame_data):
                break
            frame_length, length_consumed = decode_varint(frame_data, offset + type_consumed)
            if length_consumed == 0:
                break
            
            header_size = type_consumed + length_consumed
            
            # Check if we have complete frame
            if offset + header_size + frame_length > len(frame_data):
                break  # Wait for more data
            
            payload = frame_data[offset + header_size:offset + header_size + frame_length]
            offset += header_size + frame_length
            response["parsed_offset"] = offset
            
            if frame_type == 0x01:  # HEADERS
                headers = decode_qpack_headers(payload, debug)
                response["headers"].extend(headers)
                
                if debug:
                    print(f"          📋 H3 Response Headers:")
                    for name, value in headers:
                        print(f"             {name}: {value}")
                
                results.append({
                    "type": "response_headers",
                    "stream_id": stream_id,
                    "headers": headers,
                })
            
            elif frame_type == 0x00:  # DATA
                response["data"].extend(payload)
                
                if debug:
                    preview = payload[:100]
                    try:
                        text_preview = preview.decode('utf-8')
                        print(f"          📦 H3 Response Data ({len(payload)} bytes): {text_preview[:80]}...")
                    except:
                        print(f"          📦 H3 Response Data ({len(payload)} bytes): {preview.hex()[:80]}...")
                
                results.append({
                    "type": "response_data",
                    "stream_id": stream_id,
                    "data": payload,
                })
        
        # Mark complete if FIN received
        if fin:
            response["complete"] = True
            if debug:
                print(f"          ✅ Response complete for stream {stream_id}")
            
            results.append({
                "type": "response_complete",
                "stream_id": stream_id,
                "headers": response["headers"],
                "body": bytes(response["data"]),
            })
    
    def get_stream_buffer(self, stream_id: int) -> bytes:
        """Get the buffer for a stream."""
        if stream_id in self.streams:
            return bytes(self.streams[stream_id]["buffer"])
        return b""
    
    def get_stream_type(self, stream_id: int):
        """Get the type of a unidirectional stream."""
        if stream_id in self.streams:
            return self.streams[stream_id].get("type")
        return None

