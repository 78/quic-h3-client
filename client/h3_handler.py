"""
HTTP/3 Handler - HTTP/3 protocol layer

Handles:
- HTTP/3 stream management
- QPACK encoding/decoding
- HTTP/3 frame processing (HEADERS, DATA, GOAWAY, etc.)
- Request/Response handling
"""

import asyncio
from typing import Dict, Optional, List, Tuple, Callable, Any
from dataclasses import dataclass, field

from h3.frames import (
    build_h3_control_stream_data, build_h3_qpack_encoder_stream_data,
    build_h3_qpack_decoder_stream_data, build_qpack_request_headers,
    build_h3_headers_frame, build_h3_data_frame, build_h3_goaway_frame,
)
from h3.streams import H3StreamManager, describe_stream_id
from quic.frames import build_stream_frame


@dataclass
class H3Settings:
    """HTTP/3 SETTINGS parameters."""
    qpack_max_table_capacity: int = 0  # 0x01
    qpack_blocked_streams: int = 0      # 0x07
    enable_extended_connect: int = 0    # 0x08 (for WebTransport)
    
    def to_dict(self) -> Dict[int, int]:
        return {
            0x01: self.qpack_max_table_capacity,
            0x07: self.qpack_blocked_streams,
            0x08: self.enable_extended_connect,
        }


@dataclass
class H3Response:
    """HTTP/3 response data."""
    stream_id: int
    status: Optional[int] = None
    headers: List[Tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    complete: bool = False
    error: Optional[str] = None


class H3Handler:
    """
    Manages HTTP/3 protocol operations.
    
    Responsibilities:
    - Initialize HTTP/3 control and QPACK streams
    - Build and parse HTTP/3 frames
    - Manage request/response lifecycle
    - Handle GOAWAY for graceful shutdown
    """
    
    def __init__(self, hostname: str, debug: bool = False):
        self.hostname = hostname
        self.debug = debug
        
        # H3 stream manager for parsing
        self.stream_manager = H3StreamManager()
        
        # Settings
        self.settings = H3Settings()
        self.max_push_id = 0  # Server push is deprecated
        
        # Local unidirectional stream IDs (client-initiated)
        # Client unidirectional: 2, 6, 10, 14, ...
        self.control_stream_id = 2
        self.encoder_stream_id = 6
        self.decoder_stream_id = 10
        
        # Stream offsets for sending
        self._control_stream_offset = 0
        self._encoder_stream_offset = 0
        self._decoder_stream_offset = 0
        
        # Request stream management
        self._next_request_stream_id = 0  # Client bidi: 0, 4, 8, ...
        self._stream_write_offset: Dict[int, int] = {}
        
        # Response handling
        self._response_events: Dict[int, asyncio.Event] = {}
        self._responses: Dict[int, H3Response] = {}
        
        # GOAWAY state
        self.goaway_received = False
        self.goaway_sent = False
        self.goaway_last_stream_id: Optional[int] = None
        
        # Initialization state
        self.init_sent = False
        
        # Callback for sending QUIC STREAM frames
        self.on_send_stream: Optional[Callable[[int, bytes, int, bool], None]] = None
    
    # =========================================================================
    # Initialization
    # =========================================================================
    
    def build_init_frames(self) -> List[Tuple[int, bytes, bool]]:
        """
        Build HTTP/3 initialization frames.
        
        Returns:
            List of (stream_id, data, fin) tuples for STREAM frames
        """
        if self.init_sent:
            return []
        
        frames = []
        
        # Control stream (type + SETTINGS + MAX_PUSH_ID)
        control_data = build_h3_control_stream_data(
            self.settings.to_dict(),
            self.max_push_id
        )
        frames.append((self.control_stream_id, control_data, False))
        self._control_stream_offset = len(control_data)
        
        # QPACK Encoder stream
        encoder_data = build_h3_qpack_encoder_stream_data()
        frames.append((self.encoder_stream_id, encoder_data, False))
        self._encoder_stream_offset = len(encoder_data)
        
        # QPACK Decoder stream  
        decoder_data = build_h3_qpack_decoder_stream_data()
        frames.append((self.decoder_stream_id, decoder_data, False))
        self._decoder_stream_offset = len(decoder_data)
        
        self.init_sent = True
        
        if self.debug:
            print(f"    📋 H3 init frames:")
            print(f"       - Control Stream (id={self.control_stream_id}): {len(control_data)} bytes")
            print(f"         SETTINGS: {self.settings.to_dict()}")
            print(f"       - QPACK Encoder (id={self.encoder_stream_id}): {len(encoder_data)} bytes")
            print(f"       - QPACK Decoder (id={self.decoder_stream_id}): {len(decoder_data)} bytes")
        
        return frames
    
    # =========================================================================
    # Request building
    # =========================================================================
    
    def allocate_request_stream(self) -> int:
        """
        Allocate a new request stream ID.
        
        Returns:
            int: Stream ID for the request
        """
        stream_id = self._next_request_stream_id
        self._next_request_stream_id += 4  # Client bidi streams: 0, 4, 8, ...
        
        # Initialize response tracking
        self._response_events[stream_id] = asyncio.Event()
        self._responses[stream_id] = H3Response(stream_id=stream_id)
        
        return stream_id
    
    def build_request_frames(self, stream_id: int, method: str, path: str,
                              headers: Optional[Dict[str, str]] = None,
                              body: Optional[bytes] = None) -> bytes:
        """
        Build HTTP/3 request as stream data.
        
        Args:
            stream_id: Stream ID for the request
            method: HTTP method
            path: Request path
            headers: Additional headers
            body: Request body
            
        Returns:
            bytes: Stream data (HEADERS frame + optional DATA frame)
        """
        # Build headers
        extra_headers = headers or {}
        if "user-agent" not in extra_headers:
            extra_headers["user-agent"] = "http3-client/1.0"
        
        qpack_headers = build_qpack_request_headers(
            method=method,
            scheme="https",
            authority=self.hostname,
            path=path,
            extra_headers=extra_headers
        )
        
        headers_frame = build_h3_headers_frame(qpack_headers)
        
        stream_data = headers_frame
        if body:
            data_frame = build_h3_data_frame(body)
            stream_data += data_frame
        
        return stream_data
    
    def build_headers_only(self, stream_id: int, method: str, path: str,
                           headers: Optional[Dict[str, str]] = None) -> bytes:
        """
        Build HEADERS frame only (for streaming uploads).
        
        Args:
            stream_id: Stream ID
            method: HTTP method
            path: Request path
            headers: Additional headers
            
        Returns:
            bytes: HEADERS frame data
        """
        extra_headers = headers or {}
        if "user-agent" not in extra_headers:
            extra_headers["user-agent"] = "http3-client/1.0"
        
        qpack_headers = build_qpack_request_headers(
            method=method,
            scheme="https",
            authority=self.hostname,
            path=path,
            extra_headers=extra_headers
        )
        
        return build_h3_headers_frame(qpack_headers)
    
    def build_data_frame(self, data: bytes) -> bytes:
        """Build HTTP/3 DATA frame."""
        return build_h3_data_frame(data)
    
    # =========================================================================
    # Response handling
    # =========================================================================
    
    def process_stream_data(self, stream_id: int, offset: int, data: bytes,
                            fin: bool) -> List[Dict[str, Any]]:
        """
        Process received stream data.
        
        Args:
            stream_id: Stream ID
            offset: Data offset in stream
            data: Stream data
            fin: FIN flag
            
        Returns:
            List of processing results/events
        """
        try:
            results = self.stream_manager.process_stream_data(
                stream_id, offset, data, fin, self.debug
            )
            
            events = []
            for result in results:
                if result.get("type") == "response_complete":
                    # Update our response tracking
                    resp_stream_id = result.get("stream_id")
                    if resp_stream_id in self._responses:
                        resp = self._responses[resp_stream_id]
                        resp.headers = result.get("headers", [])
                        resp.body = result.get("body", b"")
                        resp.complete = True
                        
                        # Extract status
                        for name, value in resp.headers:
                            if name == ":status":
                                try:
                                    resp.status = int(value)
                                except:
                                    pass
                                break
                        
                        # Signal waiting coroutine
                        if resp_stream_id in self._response_events:
                            self._response_events[resp_stream_id].set()
                
                elif result.get("type") == "goaway_received":
                    self.goaway_received = True
                    self.goaway_last_stream_id = result.get("stream_id", 0)
                    if self.debug:
                        print(f"    🚪 GOAWAY received: last_stream_id={self.goaway_last_stream_id}")
                
                events.append(result)
            
            return events
            
        except Exception as e:
            if self.debug:
                print(f"    ⚠️ H3 stream processing error: {e}")
            return []
    
    def get_pending_decoder_instructions(self) -> bytes:
        """Get any pending QPACK decoder instructions to send."""
        return self.stream_manager.get_pending_decoder_instructions()
    
    def get_response(self, stream_id: int) -> Optional[H3Response]:
        """Get response for a stream."""
        return self._responses.get(stream_id)
    
    def get_response_event(self, stream_id: int) -> Optional[asyncio.Event]:
        """Get event for waiting on a response."""
        return self._response_events.get(stream_id)
    
    async def wait_response(self, stream_id: int, timeout: float = 10.0) -> H3Response:
        """
        Wait for a response on a stream.
        
        Args:
            stream_id: Stream ID
            timeout: Timeout in seconds
            
        Returns:
            H3Response: The response
        """
        if stream_id not in self._response_events:
            return H3Response(stream_id=stream_id, error="unknown_stream")
        
        try:
            await asyncio.wait_for(
                self._response_events[stream_id].wait(),
                timeout=timeout
            )
            return self._responses.get(stream_id, H3Response(stream_id=stream_id))
        except asyncio.TimeoutError:
            return H3Response(stream_id=stream_id, error="timeout")
    
    # =========================================================================
    # GOAWAY handling
    # =========================================================================
    
    def build_goaway_frame(self, last_stream_id: int = 0) -> bytes:
        """
        Build GOAWAY frame for graceful shutdown.
        
        Args:
            last_stream_id: Last stream ID (default 0 for client)
            
        Returns:
            bytes: GOAWAY frame
        """
        return build_h3_goaway_frame(last_stream_id)
    
    def get_goaway_stream_data(self, last_stream_id: int = 0) -> Tuple[int, bytes, int]:
        """
        Get GOAWAY as stream data for the control stream.
        
        Returns:
            Tuple: (stream_id, data, offset)
        """
        goaway_frame = self.build_goaway_frame(last_stream_id)
        offset = self._control_stream_offset
        self._control_stream_offset += len(goaway_frame)
        self.goaway_sent = True
        
        return (self.control_stream_id, goaway_frame, offset)
    
    # =========================================================================
    # Stream write tracking
    # =========================================================================
    
    def init_stream_write(self, stream_id: int, initial_offset: int = 0) -> None:
        """Initialize write tracking for a stream."""
        self._stream_write_offset[stream_id] = initial_offset
    
    def get_stream_write_offset(self, stream_id: int) -> int:
        """Get current write offset for a stream."""
        return self._stream_write_offset.get(stream_id, 0)
    
    def update_stream_write_offset(self, stream_id: int, bytes_written: int) -> None:
        """Update write offset after sending data."""
        if stream_id in self._stream_write_offset:
            self._stream_write_offset[stream_id] += bytes_written
    
    def close_stream_write(self, stream_id: int) -> None:
        """Close write tracking for a stream."""
        if stream_id in self._stream_write_offset:
            del self._stream_write_offset[stream_id]
    
    # =========================================================================
    # Decoder stream
    # =========================================================================
    
    def get_decoder_stream_data(self, instructions: bytes) -> Tuple[int, bytes, int]:
        """
        Get decoder instructions as stream data.
        
        Returns:
            Tuple: (stream_id, data, offset)
        """
        offset = self._decoder_stream_offset
        self._decoder_stream_offset += len(instructions)
        return (self.decoder_stream_id, instructions, offset)
    
    @property
    def decoder_stream_offset(self) -> int:
        return self._decoder_stream_offset
    
    # =========================================================================
    # State
    # =========================================================================
    
    @property
    def next_request_stream_id(self) -> int:
        """Next request stream ID that will be allocated."""
        return self._next_request_stream_id
    
    @property
    def responses(self) -> Dict[int, H3Response]:
        """All tracked responses."""
        return self._responses
    
    def describe_stream(self, stream_id: int) -> str:
        """Get human-readable description of a stream."""
        return describe_stream_id(stream_id)

