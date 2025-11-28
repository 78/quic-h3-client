"""
QUIC Flow Controller - Send and Receive side flow control

Handles:
- Connection-level flow control
- Per-stream flow control  
- MAX_DATA / MAX_STREAM_DATA frame generation
- DATA_BLOCKED / STREAM_DATA_BLOCKED handling
"""

from typing import Dict, Optional, Tuple, Callable

from quic.varint import encode_varint
from quic.constants import (
    TRANSPORT_INITIAL_MAX_DATA,
    TRANSPORT_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
    TRANSPORT_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
    TRANSPORT_INITIAL_MAX_STREAM_DATA_UNI,
)


class FlowController:
    """
    Manages flow control for a QUIC connection.
    
    Two aspects of flow control:
    1. RECEIVE side: Track how much data we've received, send MAX_DATA/MAX_STREAM_DATA
       to give peer permission to send more
    2. SEND side: Respect peer's limits, don't send more than allowed
    
    RFC 9000 Section 4: Flow Control
    """
    
    def __init__(self, debug: bool = False):
        self.debug = debug
        
        # =================================================================
        # RECEIVE side flow control (managing incoming data)
        # =================================================================
        
        # Initial values from our transport parameters
        # For embedded devices (2Mbps): BDP = 2Mbps × 200ms = 50KB, use 2×BDP = ~64KB
        self._initial_max_data: int = TRANSPORT_INITIAL_MAX_DATA
        self._initial_max_stream_data: int = TRANSPORT_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE
        
        # Connection level - receive side
        self._max_data_sent: int = self._initial_max_data  # Last MAX_DATA sent
        self._data_received: int = 0  # Total bytes received
        
        # Per-stream - receive side
        self._stream_received: Dict[int, int] = {}  # stream_id -> bytes received
        self._stream_max_sent: Dict[int, int] = {}  # stream_id -> last MAX_STREAM_DATA sent
        
        # Window update threshold (send update when consumed > threshold * limit)
        self._window_update_threshold: float = 0.5
        
        # =================================================================
        # SEND side flow control (respecting peer's limits)
        # =================================================================
        
        # Connection level - send side (set by server's transport params)
        self._peer_max_data: int = TRANSPORT_INITIAL_MAX_DATA  # Updated from EncryptedExtensions
        self._data_sent: int = 0  # Total bytes we've sent
        
        # Initial stream limits from peer's transport params
        self._peer_max_stream_data_bidi_local: int = TRANSPORT_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL  # Server-initiated bidi
        self._peer_max_stream_data_bidi_remote: int = TRANSPORT_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE  # Client-initiated bidi
        self._peer_max_stream_data_uni: int = TRANSPORT_INITIAL_MAX_STREAM_DATA_UNI  # Unidirectional
        
        # Per-stream - send side
        self._stream_sent: Dict[int, int] = {}  # stream_id -> bytes sent
        self._peer_stream_max: Dict[int, int] = {}  # stream_id -> peer's limit
        
        # Blocked state (to avoid sending duplicate BLOCKED frames)
        self._connection_blocked_at: Optional[int] = None
        self._stream_blocked_at: Dict[int, int] = {}
        
        # Callback for sending control frames
        self.on_send_frame: Optional[Callable[[bytes], None]] = None
    
    # =========================================================================
    # Configuration
    # =========================================================================
    
    def set_initial_limits(self, max_data: int, max_stream_data: int) -> None:
        """
        Set our initial flow control limits (for receive side).
        
        Args:
            max_data: Connection-level limit
            max_stream_data: Per-stream limit
        """
        self._initial_max_data = max_data
        self._initial_max_stream_data = max_stream_data
        self._max_data_sent = max_data
    
    def update_peer_transport_params(self, params: dict) -> None:
        """
        Update send-side limits from server's transport parameters.
        
        Called when processing EncryptedExtensions.
        
        Args:
            params: Parsed transport parameters dictionary
        """
        if "initial_max_data" in params:
            value = params["initial_max_data"]
            if isinstance(value, int):
                self._peer_max_data = value
                if self.debug:
                    print(f"    📊 peer_max_data: {value}")
        
        if "initial_max_stream_data_bidi_local" in params:
            value = params["initial_max_stream_data_bidi_local"]
            if isinstance(value, int):
                self._peer_max_stream_data_bidi_local = value
        
        if "initial_max_stream_data_bidi_remote" in params:
            value = params["initial_max_stream_data_bidi_remote"]
            if isinstance(value, int):
                self._peer_max_stream_data_bidi_remote = value
        
        if "initial_max_stream_data_uni" in params:
            value = params["initial_max_stream_data_uni"]
            if isinstance(value, int):
                self._peer_max_stream_data_uni = value
        
        if self.debug:
            print(f"    📊 Send limits: conn={self._peer_max_data}, "
                  f"bidi_remote={self._peer_max_stream_data_bidi_remote}")
    
    # =========================================================================
    # Stream type helpers
    # =========================================================================
    
    def _get_initial_stream_limit(self, stream_id: int) -> int:
        """
        Get initial flow control limit for a stream based on its type.
        
        Stream ID encoding (RFC 9000 Section 2.1):
        - Bit 0: Initiator (0 = client, 1 = server)
        - Bit 1: Direction (0 = bidirectional, 1 = unidirectional)
        """
        is_server_initiated = (stream_id & 0x01) == 1
        is_unidirectional = (stream_id & 0x02) == 2
        
        if is_unidirectional:
            return self._peer_max_stream_data_uni
        elif is_server_initiated:
            return self._peer_max_stream_data_bidi_local
        else:
            # Client-initiated bidirectional (our request streams)
            return self._peer_max_stream_data_bidi_remote
    
    def _get_stream_send_limit(self, stream_id: int) -> int:
        """Get current send limit for a stream."""
        if stream_id in self._peer_stream_max:
            return self._peer_stream_max[stream_id]
        return self._get_initial_stream_limit(stream_id)
    
    # =========================================================================
    # RECEIVE side: Track incoming data, send window updates
    # =========================================================================
    
    def on_data_received(self, stream_id: int, data_len: int) -> None:
        """
        Called when data is received on a stream.
        
        Updates counters and may trigger MAX_DATA/MAX_STREAM_DATA.
        
        Args:
            stream_id: Stream that received data
            data_len: Number of bytes received
        """
        # Update connection-level counter
        self._data_received += data_len
        
        # Update stream-level counter
        if stream_id not in self._stream_received:
            self._stream_received[stream_id] = 0
            self._stream_max_sent[stream_id] = self._initial_max_stream_data
        self._stream_received[stream_id] += data_len
        
        # Check if we need to send updates
        self._maybe_send_max_data()
        self._maybe_send_max_stream_data(stream_id)
    
    def on_data_blocked_received(self, blocked_at: int) -> None:
        """
        Called when peer sends DATA_BLOCKED frame.
        
        Should trigger immediate MAX_DATA update.
        """
        if self.debug:
            print(f"    📊 Peer blocked at connection level: {blocked_at}")
        self._send_max_data(force=True)
    
    def on_stream_data_blocked_received(self, stream_id: int, blocked_at: int) -> None:
        """
        Called when peer sends STREAM_DATA_BLOCKED frame.
        
        Should trigger immediate MAX_STREAM_DATA update.
        """
        if self.debug:
            print(f"    📊 Peer blocked on stream {stream_id}: {blocked_at}")
        self._send_max_stream_data(stream_id, force=True)
    
    def _maybe_send_max_data(self) -> None:
        """Send MAX_DATA if peer has consumed enough of the window."""
        consumed = self._data_received
        current_limit = self._max_data_sent
        
        if consumed > (self._window_update_threshold * current_limit):
            self._send_max_data()
    
    def _send_max_data(self, force: bool = False) -> None:
        """Send MAX_DATA frame to peer."""
        consumed = self._data_received
        current_limit = self._max_data_sent
        
        # Calculate new limit
        new_limit = max(
            current_limit + self._initial_max_data,
            consumed + self._initial_max_data
        )
        
        if new_limit <= self._max_data_sent and not force:
            return
        
        self._max_data_sent = new_limit
        
        # Build MAX_DATA frame (type 0x10)
        frame = encode_varint(0x10) + encode_varint(new_limit)
        
        if self.on_send_frame:
            self.on_send_frame(frame)
        
        if self.debug:
            print(f"    → MAX_DATA: {new_limit} (received={consumed})")
    
    def _maybe_send_max_stream_data(self, stream_id: int) -> None:
        """Send MAX_STREAM_DATA if peer has consumed enough."""
        consumed = self._stream_received.get(stream_id, 0)
        current_limit = self._stream_max_sent.get(stream_id, self._initial_max_stream_data)
        
        if consumed > (self._window_update_threshold * current_limit):
            self._send_max_stream_data(stream_id)
    
    def _send_max_stream_data(self, stream_id: int, force: bool = False) -> None:
        """Send MAX_STREAM_DATA frame for a stream."""
        consumed = self._stream_received.get(stream_id, 0)
        current_limit = self._stream_max_sent.get(stream_id, self._initial_max_stream_data)
        
        new_limit = max(
            current_limit + self._initial_max_stream_data,
            consumed + self._initial_max_stream_data
        )
        
        if new_limit <= self._stream_max_sent.get(stream_id, 0) and not force:
            return
        
        self._stream_max_sent[stream_id] = new_limit
        
        # Build MAX_STREAM_DATA frame (type 0x11)
        frame = encode_varint(0x11) + encode_varint(stream_id) + encode_varint(new_limit)
        
        if self.on_send_frame:
            self.on_send_frame(frame)
        
        if self.debug:
            print(f"    → MAX_STREAM_DATA: stream={stream_id}, limit={new_limit}")
    
    def build_max_data_frame(self, limit: int) -> bytes:
        """Build a MAX_DATA frame."""
        return encode_varint(0x10) + encode_varint(limit)
    
    def build_max_stream_data_frame(self, stream_id: int, limit: int) -> bytes:
        """Build a MAX_STREAM_DATA frame."""
        return encode_varint(0x11) + encode_varint(stream_id) + encode_varint(limit)
    
    # =========================================================================
    # SEND side: Check limits before sending, handle updates from peer
    # =========================================================================
    
    def can_send(self, stream_id: int, data_len: int) -> Tuple[bool, int, str]:
        """
        Check if we can send data, considering flow control limits.
        
        Does NOT check congestion control - that's separate.
        
        Args:
            stream_id: Stream to send on
            data_len: Number of bytes to send
            
        Returns:
            Tuple of (can_send, max_bytes, block_reason)
        """
        # Check connection-level limit
        connection_available = self._peer_max_data - self._data_sent
        if connection_available <= 0:
            # Send DATA_BLOCKED if we haven't already
            if self._connection_blocked_at != self._peer_max_data:
                self._send_data_blocked()
                self._connection_blocked_at = self._peer_max_data
            return (False, 0, "connection_flow_control")
        
        # Check stream-level limit
        stream_sent = self._stream_sent.get(stream_id, 0)
        stream_limit = self._get_stream_send_limit(stream_id)
        stream_available = stream_limit - stream_sent
        
        if stream_available <= 0:
            # Send STREAM_DATA_BLOCKED if we haven't already
            blocked_at = self._stream_blocked_at.get(stream_id, -1)
            if blocked_at != stream_limit:
                self._send_stream_data_blocked(stream_id, stream_limit)
                self._stream_blocked_at[stream_id] = stream_limit
            return (False, 0, "stream_flow_control")
        
        max_bytes = min(data_len, connection_available, stream_available)
        return (True, max_bytes, "")
    
    def on_data_sent(self, stream_id: int, data_len: int) -> None:
        """
        Called after data is sent on a stream.
        
        Updates send-side counters.
        """
        self._data_sent += data_len
        self._stream_sent[stream_id] = self._stream_sent.get(stream_id, 0) + data_len
    
    def on_max_data_received(self, max_data: int) -> bool:
        """
        Called when MAX_DATA frame is received.
        
        Args:
            max_data: New connection-level limit
            
        Returns:
            bool: True if limit increased
        """
        if max_data > self._peer_max_data:
            old_limit = self._peer_max_data
            self._peer_max_data = max_data
            self._connection_blocked_at = None  # Clear blocked state
            
            if self.debug:
                print(f"    📊 MAX_DATA: {max_data} (was {old_limit})")
            return True
        return False
    
    def on_max_stream_data_received(self, stream_id: int, max_data: int) -> bool:
        """
        Called when MAX_STREAM_DATA frame is received.
        
        Args:
            stream_id: Stream ID
            max_data: New limit for this stream
            
        Returns:
            bool: True if limit increased
        """
        current_limit = self._peer_stream_max.get(
            stream_id, self._get_initial_stream_limit(stream_id)
        )
        
        if max_data > current_limit:
            self._peer_stream_max[stream_id] = max_data
            if stream_id in self._stream_blocked_at:
                del self._stream_blocked_at[stream_id]
            
            if self.debug:
                print(f"    📊 MAX_STREAM_DATA: stream={stream_id}, {max_data} (was {current_limit})")
            return True
        return False
    
    def _send_data_blocked(self) -> None:
        """Send DATA_BLOCKED frame."""
        frame = encode_varint(0x14) + encode_varint(self._peer_max_data)
        if self.on_send_frame:
            self.on_send_frame(frame)
        if self.debug:
            print(f"    → DATA_BLOCKED: {self._peer_max_data}")
    
    def _send_stream_data_blocked(self, stream_id: int, limit: int) -> None:
        """Send STREAM_DATA_BLOCKED frame."""
        frame = encode_varint(0x15) + encode_varint(stream_id) + encode_varint(limit)
        if self.on_send_frame:
            self.on_send_frame(frame)
        if self.debug:
            print(f"    → STREAM_DATA_BLOCKED: stream={stream_id}, limit={limit}")
    
    # =========================================================================
    # Stats and debugging
    # =========================================================================
    
    @property
    def peer_max_data(self) -> int:
        return self._peer_max_data
    
    @property
    def data_sent(self) -> int:
        return self._data_sent
    
    @property
    def connection_available(self) -> int:
        return max(0, self._peer_max_data - self._data_sent)
    
    def get_stream_send_limit(self, stream_id: int) -> int:
        """Get current send limit for a stream (public API)."""
        return self._get_stream_send_limit(stream_id)
    
    def get_stats(self) -> dict:
        """Get flow control statistics."""
        return {
            "receive": {
                "data_received": self._data_received,
                "max_data_sent": self._max_data_sent,
            },
            "send": {
                "peer_max_data": self._peer_max_data,
                "data_sent": self._data_sent,
                "available": self.connection_available,
            }
        }

