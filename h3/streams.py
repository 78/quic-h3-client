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
from .qpack import (
    QPACKDynamicTable, parse_qpack_encoder_instructions,
    build_section_acknowledgment, build_insert_count_increment
)


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
    
    Includes QPACK dynamic table management for proper header decompression.
    """
    def __init__(self, qpack_max_table_capacity: int = 4096):
        self.streams = {}  # stream_id -> {"type": str, "data": bytes, "offset": int}
        self.control_stream_id = None
        self.qpack_encoder_stream_id = None
        self.qpack_decoder_stream_id = None
        self.peer_settings = {}
        self.local_settings = {
            H3_SETTINGS_MAX_TABLE_CAPACITY: qpack_max_table_capacity,
            H3_SETTINGS_BLOCKED_STREAMS: 100,
        }
        
        # QPACK dynamic table for decoding server headers
        self.qpack_dynamic_table = QPACKDynamicTable(max_capacity=qpack_max_table_capacity)
        
        # Track encoder stream parsing state
        self._encoder_stream_parsed_offset = 0
        
        # Pending decoder instructions to send
        self._pending_decoder_instructions = bytearray()
        
        # Request stream responses
        self.responses = {}  # stream_id -> {"headers": [], "data": bytes, "complete": bool}
    
    def set_debug(self, debug: bool):
        """Enable/disable debug output for QPACK table."""
        self.qpack_dynamic_table.set_debug(debug)
    
    def _merge_pending_chunks(self, stream: dict, debug: bool = False):
        """
        Merge any pending out-of-order chunks that are now contiguous.
        
        Args:
            stream: Stream state dictionary
            debug: Enable debug output
        """
        pending = stream["pending_chunks"]
        merged = True
        
        while merged and pending:
            merged = False
            # Find chunks that can be merged
            for offset in sorted(pending.keys()):
                if offset <= stream["contiguous_end"]:
                    data = pending.pop(offset)
                    end_offset = offset + len(data)
                    
                    if end_offset > stream["contiguous_end"]:
                        # Append the non-overlapping part
                        new_start = stream["contiguous_end"] - offset
                        stream["buffer"].extend(data[new_start:])
                        stream["contiguous_end"] = end_offset
                        merged = True
                        
                        if debug:
                            print(f"    🔗 Merged buffered chunk at offset {offset}, contiguous_end now {stream['contiguous_end']}")
                    break
    
    def get_pending_decoder_instructions(self) -> bytes:
        """
        Get and clear pending QPACK decoder instructions.
        
        These should be sent on the decoder stream.
        
        Returns:
            bytes: Encoded decoder instructions
        """
        instructions = bytes(self._pending_decoder_instructions)
        self._pending_decoder_instructions.clear()
        return instructions
    
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
                "buffer": bytearray(),           # Contiguous data buffer
                "contiguous_end": 0,             # End of contiguous data
                "pending_chunks": {},            # offset -> data for out-of-order chunks
                "fin_offset": None,              # Final offset if FIN received
            }
        
        stream = self.streams[stream_id]
        
        # Store FIN offset if received
        if fin:
            stream["fin_offset"] = offset + len(data)
        
        # Handle data reassembly
        if offset == stream["contiguous_end"]:
            # Data is in order - append directly
            stream["buffer"].extend(data)
            stream["contiguous_end"] += len(data)
            
            # Check if any pending chunks can now be merged
            self._merge_pending_chunks(stream, debug)
        elif offset > stream["contiguous_end"]:
            # Out of order - store for later
            stream["pending_chunks"][offset] = data
            if debug:
                print(f"    📦 Stream {stream_id}: Buffering out-of-order data at offset {offset} (expecting {stream['contiguous_end']})")
        else:
            # Overlapping or duplicate data - check for gaps
            end_offset = offset + len(data)
            if end_offset > stream["contiguous_end"]:
                # Partial new data
                new_start = stream["contiguous_end"] - offset
                stream["buffer"].extend(data[new_start:])
                stream["contiguous_end"] = end_offset
                self._merge_pending_chunks(stream, debug)
        
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
            stream["type_len"] = consumed  # Store stream type length
            
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
        
        # Process QPACK encoder stream - this is critical for dynamic table
        elif stream["type"] == H3_STREAM_TYPE_QPACK_ENCODER:
            self._process_qpack_encoder_stream(stream, debug, results)
        
        # Parse HTTP/3 response on bidirectional request streams
        elif direction == "bidi":
            self._process_request_stream_response(stream_id, stream, fin, debug, results)
        
        return results
    
    def _process_qpack_encoder_stream(self, stream: dict, debug: bool, results: list):
        """
        Process QPACK encoder stream data.
        
        Parses encoder instructions and updates the dynamic table.
        """
        buffer = bytes(stream["buffer"])
        type_len = stream.get("type_len", 1)
        
        # Only process new data
        start_offset = type_len + self._encoder_stream_parsed_offset
        if start_offset >= len(buffer):
            return
        
        encoder_data = buffer[start_offset:]
        
        if debug:
            print(f"    📨 Processing QPACK encoder instructions ({len(encoder_data)} bytes)")
        
        # Parse encoder instructions
        prev_insert_count = self.qpack_dynamic_table.insert_count
        consumed = parse_qpack_encoder_instructions(
            encoder_data, 
            self.qpack_dynamic_table, 
            debug=debug
        )
        self._encoder_stream_parsed_offset += consumed
        
        # If new entries were inserted, send Insert Count Increment
        new_inserts = self.qpack_dynamic_table.insert_count - prev_insert_count
        if new_inserts > 0:
            self._pending_decoder_instructions.extend(
                build_insert_count_increment(new_inserts)
            )
            
            results.append({
                "type": "qpack_table_updated",
                "new_entries": new_inserts,
                "total_entries": len(self.qpack_dynamic_table),
                "table_size": self.qpack_dynamic_table.size,
            })
            
            if debug:
                print(f"    📊 QPACK dynamic table: {len(self.qpack_dynamic_table)} entries, {self.qpack_dynamic_table.size} bytes")
    
    def _process_request_stream_response(self, stream_id: int, stream: dict, 
                                         fin: bool, debug: bool, results: list):
        """Process HTTP/3 response frames on a request stream."""
        # Only process contiguous data from buffer
        frame_data = bytes(stream["buffer"])
        if len(frame_data) == 0:
            return
        
        # Check if we have gaps in the data
        has_pending = bool(stream.get("pending_chunks"))
        
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
                # Decode headers with dynamic table support
                headers = decode_qpack_headers(
                    payload, 
                    debug=debug, 
                    dynamic_table=self.qpack_dynamic_table
                )
                response["headers"].extend(headers)
                
                if debug:
                    print(f"          📋 H3 Response Headers:")
                    for name, value in headers:
                        print(f"             {name}: {value}")
                
                # Send Section Acknowledgment for this header block
                self._pending_decoder_instructions.extend(
                    build_section_acknowledgment(stream_id)
                )
                
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
        
        # Mark complete if FIN received and all data is contiguous
        fin_offset = stream.get("fin_offset")
        all_data_received = (fin_offset is not None and 
                            stream["contiguous_end"] >= fin_offset and
                            not stream.get("pending_chunks"))
        
        if all_data_received and not response["complete"]:
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

