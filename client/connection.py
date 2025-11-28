"""
QUIC Client Connection - Refactored with Component Architecture

This is the main orchestrator that composes:
- CryptoManager: Key derivation and encryption
- FlowController: Send/receive flow control
- AckManager: ACK generation
- H3Handler: HTTP/3 protocol layer
- LossDetector: Loss detection and congestion control
"""

import os
import socket
import struct
import hashlib
import asyncio
import time
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from quic.constants import QUIC_VERSION
from quic.varint import encode_varint
from quic.frames import (
    build_crypto_frame, build_ack_frame, build_padding_frame,
    build_stream_frame, build_new_connection_id_frame,
    build_retire_connection_id_frame, build_connection_close_frame,
    parse_quic_frames, build_path_challenge_frame, build_path_response_frame,
    build_datagram_frame,
)
from quic.packets import (
    build_initial_packet_with_secrets, build_handshake_packet,
    create_initial_packet, parse_long_header,
    build_0rtt_packet, create_initial_packet_with_psk,
    parse_retry_packet, create_initial_packet_with_retry_token,
)
from tls.handshake import parse_tls_handshake
from tls.session import SessionTicket, SessionTicketStore
from utils.keylog import write_keylog

from .loss_detection import LossDetector, PacketNumberSpace, SentPacketInfo
from .crypto_manager import CryptoManager
from .flow_controller import FlowController
from .ack_manager import AckManager
from .h3_handler import H3Handler
from .frame_processor import FrameProcessor


# =============================================================================
# State definitions (previously in state.py)
# =============================================================================

class HandshakeState:
    """QUIC Handshake State Machine"""
    INITIAL = "INITIAL"                        # Waiting for Initial response
    HANDSHAKE = "HANDSHAKE"                    # Processing Handshake packets
    HANDSHAKE_COMPLETE = "HANDSHAKE_COMPLETE"  # Received Finished, handshake done
    FAILED = "FAILED"


@dataclass
class CryptoBuffer:
    """
    Buffer for reassembling CRYPTO frame data.
    Handles out-of-order fragments.
    """
    data: bytearray = field(default_factory=bytearray)
    received_ranges: List[Tuple[int, int]] = field(default_factory=list)
    
    def add_fragment(self, offset: int, fragment: bytes) -> bool:
        """
        Add a CRYPTO fragment to the buffer.
        
        Returns:
            bool: True if this is new data, False if duplicate
        """
        end = offset + len(fragment)
        
        # Check for duplicate
        for start_r, end_r in self.received_ranges:
            if offset >= start_r and end <= end_r:
                return False
        
        # Expand buffer if needed
        if end > len(self.data):
            self.data.extend(b'\x00' * (end - len(self.data)))
        
        # Write fragment
        self.data[offset:end] = fragment
        self.received_ranges.append((offset, end))
        return True
    
    def get_contiguous_data(self) -> bytes:
        """Get contiguous data starting from offset 0."""
        if not self.received_ranges:
            return b""
        
        sorted_ranges = sorted(self.received_ranges, key=lambda x: x[0])
        contiguous_end = 0
        for start, end in sorted_ranges:
            if start <= contiguous_end:
                contiguous_end = max(contiguous_end, end)
            else:
                break
        
        return bytes(self.data[:contiguous_end])
    
    @property
    def total_received(self) -> int:
        """Total bytes received (may have gaps)."""
        if not self.received_ranges:
            return 0
        return max(end for _, end in self.received_ranges)


# =============================================================================
# Protocol handler (previously in protocol.py)
# =============================================================================

class QuicProtocol(asyncio.DatagramProtocol):
    """Asyncio protocol handler for QUIC UDP datagrams."""
    
    def __init__(self, client: 'QuicConnection'):
        self.client = client
        
    def connection_made(self, transport):
        """Called when connection is established."""
        pass
    
    def datagram_received(self, data: bytes, addr):
        """Process incoming UDP datagram."""
        self.client.process_udp_packet(data)
    
    def error_received(self, exc):
        """Called when a send/receive operation fails."""
        if self.client.debug:
            print(f"    ❌ UDP Error: {exc}")
        
    def connection_lost(self, exc):
        """Called when connection is lost."""
        if exc and self.client.debug:
            print(f"    Connection closed: {exc}")


# Backward compatibility alias


# =============================================================================
# Main connection class
# =============================================================================

class QuicConnection:
    """
    QUIC Client Connection with component-based architecture.
    
    Composes specialized components for different responsibilities:
    - CryptoManager: All cryptographic operations
    - FlowController: Flow control management
    - AckManager: ACK frame generation
    - H3Handler: HTTP/3 protocol handling
    - LossDetector: Loss detection and recovery
    
    This class orchestrates the components and handles:
    - Connection lifecycle (connect, close)
    - Packet sending and receiving
    - Handshake state machine
    - High-level request/response API
    - DATAGRAM support (RFC 9221)
    """
    
    # Default maximum DATAGRAM frame size (0 = disabled)
    # Set to 65535 to enable DATAGRAM with maximum size
    DEFAULT_MAX_DATAGRAM_FRAME_SIZE = 65535
    
    def __init__(self, hostname: str, port: int, debug: bool = True,
                 keylog_file: str = None, session_file: str = None,
                 enable_datagram: bool = False, max_datagram_frame_size: int = None):
        self.hostname = hostname
        self.port = port
        self.debug = debug
        self.keylog_file = keylog_file
        self.session_file = session_file
        
        # DATAGRAM configuration (RFC 9221)
        self.datagram_enabled = enable_datagram
        self.local_max_datagram_frame_size = (
            max_datagram_frame_size if max_datagram_frame_size is not None
            else (self.DEFAULT_MAX_DATAGRAM_FRAME_SIZE if enable_datagram else 0)
        )
        self.peer_max_datagram_frame_size = 0  # Will be set from peer's transport params
        
        # Network
        self.target_ip: Optional[str] = None
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.protocol: Optional[QuicProtocol] = None
        
        # Connection state
        self.state = HandshakeState.INITIAL
        self.original_dcid: Optional[bytes] = None
        self.our_scid: Optional[bytes] = None
        self.server_scid: Optional[bytes] = None
        
        # =====================================================================
        # Component instances
        # =====================================================================
        
        self.crypto = CryptoManager(debug=debug)
        self.flow = FlowController(debug=debug)
        self.ack = AckManager(debug=debug)
        self.h3 = H3Handler(hostname, debug=debug)
        self.loss_detector = LossDetector(debug=debug)
        self.frame_processor = FrameProcessor(debug=debug)
        
        # Wire up component callbacks
        self._setup_component_callbacks()
        
        # =====================================================================
        # Connection-level state
        # =====================================================================
        
        # Packet numbers for sending
        self.client_initial_pn = 0
        self.client_handshake_pn = 0
        self.client_app_pn = 0
        
        # CRYPTO buffers
        self.initial_crypto_buffer = CryptoBuffer()
        self.handshake_crypto_buffer = CryptoBuffer()
        self.initial_crypto_parsed_offset = 0
        self.handshake_crypto_parsed_offset = 0
        
        # Handshake state
        self.server_hello_received = False
        self.finished_received = False
        self.client_finished_sent = False
        
        # 0-RTT state
        self.zero_rtt_enabled = False
        self.zero_rtt_accepted = False
        self.zero_rtt_rejected = False
        
        # Session management
        self.session_ticket_store: Optional[SessionTicketStore] = None
        if session_file:
            self.session_ticket_store = SessionTicketStore(session_file)
        self.session_tickets = []
        
        # Events
        self.handshake_complete = asyncio.Event()
        self.connection_closed = asyncio.Event()
        self._cwnd_available = asyncio.Event()
        self._cwnd_available.set()
        
        # DATAGRAM receive queue
        self._datagram_queue: asyncio.Queue = asyncio.Queue()
        self._datagram_received = asyncio.Event()
        
        # Peer state
        self._peer_closed = False
        self._peer_close_error_code: Optional[int] = None
        self._peer_close_reason: str = ""
        self._stateless_reset_received = False
        
        # Key management
        self._handshake_confirmed = False
        self._initial_keys_discarded = False
        self._handshake_keys_discarded = False
        
        # Connection IDs
        self.alt_connection_ids = []
        self.peer_connection_ids: Dict[int, dict] = {}
        self.peer_stateless_reset_tokens: Dict[bytes, bytes] = {}
        self._peer_retire_prior_to = 0
        
        # Path validation
        self._pending_path_challenges: List[dict] = []
        self._path_validated = True
        
        # Retry state
        self._retry_received = False
        self._retry_source_cid: Optional[bytes] = None
        self._retry_token: Optional[bytes] = None
        
        # PTO timer
        self._pto_timer_task: Optional[asyncio.Task] = None
        
        # Reset streams tracking
        self._reset_streams: Dict[int, int] = {}
        
        # Stats
        self.packets_received = 0
        self.packets_sent = 0
        self.bytes_received = 0
        self.start_time = 0.0
    
    def _setup_component_callbacks(self):
        """Wire up callbacks between components."""
        # Crypto manager keylog callback
        self.crypto.on_keys_derived = self._on_keys_derived
        
        # Loss detector callbacks
        self.loss_detector.on_packets_lost = self._on_packets_lost
        self.loss_detector.on_pto_timeout = self._on_pto_timeout
        
        # Flow controller frame sending
        self.flow.on_send_frame = self._send_flow_control_frame
        
        # Frame processor callbacks
        self._setup_frame_processor_callbacks()
    
    def _setup_frame_processor_callbacks(self):
        """Wire up frame processor callbacks."""
        fp = self.frame_processor
        
        fp.on_ack = self._on_frame_ack
        fp.on_stream = self._on_frame_stream
        fp.on_crypto = self._on_frame_crypto_1rtt
        fp.on_max_data = lambda v: (self.flow.on_max_data_received(v) and self._cwnd_available.set())
        fp.on_max_stream_data = lambda sid, v: (self.flow.on_max_stream_data_received(sid, v) and self._cwnd_available.set())
        fp.on_data_blocked = self.flow.on_data_blocked_received
        fp.on_stream_data_blocked = self.flow.on_stream_data_blocked_received
        fp.on_new_connection_id = self._on_frame_new_connection_id
        fp.on_connection_close = self._on_frame_connection_close
        fp.on_handshake_done = self._on_frame_handshake_done
        fp.on_path_challenge = self._send_path_response
        fp.on_path_response = self._handle_path_response
        fp.on_reset_stream = self._on_frame_reset_stream
        fp.on_stop_sending = self._on_frame_stop_sending
        fp.on_retire_connection_id = self._on_frame_retire_connection_id
        fp.on_datagram = self._on_frame_datagram
    
    def _on_keys_derived(self, level: str, secrets: dict):
        """Callback when keys are derived - write to keylog."""
        if not self.crypto.client_random or not self.keylog_file:
            return
        
        if level == "handshake":
            write_keylog(
                self.keylog_file, self.crypto.client_random,
                client_hs_secret=secrets.get("client_secret"),
                server_hs_secret=secrets.get("server_secret")
            )
        elif level == "application":
            write_keylog(
                self.keylog_file, self.crypto.client_random,
                client_traffic_secret=secrets.get("client_secret"),
                server_traffic_secret=secrets.get("server_secret")
            )
        elif level == "early_data":
            write_keylog(
                self.keylog_file, self.crypto.client_random,
                client_early_secret=secrets.get("client_secret")
            )
    
    def _send_flow_control_frame(self, frame: bytes):
        """Send a flow control frame (MAX_DATA, etc.)."""
        if not self.crypto.has_application_keys:
            return
        
        dcid = self.server_scid or self.original_dcid
        packet = self.crypto.build_short_header_packet(dcid, self.client_app_pn, frame)
        self.send(packet)
        self.client_app_pn += 1
    
    # =========================================================================
    # Connection lifecycle
    # =========================================================================
    
    async def connect(self):
        """Establish UDP connection."""
        self.target_ip = socket.gethostbyname(self.hostname)
        if self.debug:
            print(f"    Resolved: {self.target_ip}")
        
        loop = asyncio.get_event_loop()
        self.transport, self.protocol = await loop.create_datagram_endpoint(
            lambda: QuicProtocol(self),
            remote_addr=(self.target_ip, self.port)
        )
    
    def send(self, data: bytes):
        """Send UDP packet."""
        if self._peer_closed:
            if self.debug:
                print(f"    ⚠️ Cannot send: peer has closed connection")
            return
        
        if self.transport:
            self.transport.sendto(data)
            self.packets_sent += 1
    
    def close(self):
        """Close the connection."""
        if self._pto_timer_task and not self._pto_timer_task.done():
            self._pto_timer_task.cancel()
        if self.transport:
            self.transport.close()
    
    # =========================================================================
    # Handshake
    # =========================================================================
    
    async def do_handshake(self, timeout: float = 5.0, force_0rtt: bool = False) -> bool:
        """Perform QUIC handshake."""
        self.start_time = time.time()
        
        session_ticket = self._try_load_session_ticket(force_0rtt)
        
        if session_ticket:
            return await self._do_handshake_0rtt(session_ticket, timeout)
        else:
            return await self._do_handshake_1rtt(timeout)
    
    async def _do_handshake_1rtt(self, timeout: float) -> bool:
        """Normal 1-RTT handshake."""
        # Generate Initial packet
        packet, dcid, scid, private_key, client_hello, client_random = \
            create_initial_packet(
                self.hostname, debug=self.debug,
                max_datagram_frame_size=self.local_max_datagram_frame_size
            )
        
        self.original_dcid = dcid
        self.our_scid = scid
        self.crypto.private_key = private_key
        self.crypto.client_hello = client_hello
        self.crypto.client_random = client_random
        
        # Derive initial keys
        self.crypto.derive_initial_keys(dcid)
        
        if self.debug:
            print(f"    DCID: {dcid.hex()}")
            print(f"    SCID: {scid.hex()}")
            print(f"    Initial packet size: {len(packet)} bytes")
        
        # Track sent packet
        self._track_sent_packet(
            PacketNumberSpace.INITIAL, 0, len(packet),
            frames=[{"type": "CRYPTO", "offset": 0, "data": client_hello}]
        )
        
        # Send
        self.send(packet)
        self.client_initial_pn += 1
        if self.debug:
            print(f"    → Sent Initial packet (PN=0)")
        
        # Start PTO timer
        self._start_pto_timer()
        
        # Wait for handshake
        try:
            await asyncio.wait_for(self.handshake_complete.wait(), timeout=timeout)
            elapsed = time.time() - self.start_time
            if self.debug:
                print(f"\n    ✅ Handshake complete! Time: {elapsed:.3f}s")
            return True
        except asyncio.TimeoutError:
            if self.debug:
                print(f"\n    ⏱️ Handshake timeout")
            return False
    
    async def _do_handshake_0rtt(self, session_ticket: SessionTicket, 
                                  timeout: float) -> bool:
        """0-RTT handshake with session resumption."""
        if self.debug:
            print(f"    🚀 Attempting 0-RTT handshake")
        
        self.zero_rtt_enabled = True
        self.crypto.zero_rtt_enabled = True
        
        # Generate Initial with PSK
        result = create_initial_packet_with_psk(
            self.hostname, session_ticket, debug=self.debug,
            max_datagram_frame_size=self.local_max_datagram_frame_size
        )
        packet, dcid, scid, private_key, client_hello, client_random, psk, early_secret = result
        
        self.original_dcid = dcid
        self.our_scid = scid
        self.crypto.private_key = private_key
        self.crypto.client_hello = client_hello
        self.crypto.client_random = client_random
        self.crypto.zero_rtt_psk = psk
        self.crypto.zero_rtt_early_secret = early_secret
        
        # Derive keys
        self.crypto.derive_initial_keys(dcid)
        self.crypto.derive_0rtt_keys(early_secret)
        
        if self.debug:
            print(f"    DCID: {dcid.hex()}")
            print(f"    SCID: {scid.hex()}")
        
        # Track and send
        self._track_sent_packet(
            PacketNumberSpace.INITIAL, 0, len(packet),
            frames=[{"type": "CRYPTO", "offset": 0, "data": client_hello}]
        )
        
        self.send(packet)
        self.client_initial_pn += 1
        
        self._start_pto_timer()
        
        try:
            await asyncio.wait_for(self.handshake_complete.wait(), timeout=timeout)
            elapsed = time.time() - self.start_time
            if self.debug:
                status = "accepted" if self.zero_rtt_accepted else "rejected"
                print(f"\n    ✅ 0-RTT Handshake complete ({status})! Time: {elapsed:.3f}s")
            return True
        except asyncio.TimeoutError:
            if self.debug:
                print(f"\n    ⏱️ 0-RTT Handshake timeout")
            return False
    
    def _try_load_session_ticket(self, force_0rtt: bool) -> Optional[SessionTicket]:
        """Try to load valid session ticket."""
        if not self.session_ticket_store:
            return None
        
        ticket = self.session_ticket_store.get_ticket(self.hostname)
        if ticket and ticket.is_valid(time.time()):
            if ticket.max_early_data_size > 0 or force_0rtt:
                if self.debug:
                    print(f"    📋 Found valid session ticket for 0-RTT")
                return ticket
        return None
    
    # =========================================================================
    # Packet processing
    # =========================================================================
    
    def process_udp_packet(self, data: bytes):
        """Process received UDP datagram."""
        if self._peer_closed:
            return
        
        recv_time = time.time()
        self.packets_received += 1
        self.bytes_received += len(data)
        
        offset = 0
        initial_largest_before = self.ack.initial_largest_pn
        handshake_largest_before = self.ack.handshake_largest_pn
        app_largest_before = self.ack.app_largest_pn
        client_finished_before = self.client_finished_sent
        
        while offset < len(data):
            remaining = data[offset:]
            if len(remaining) < 5:
                break
            
            first_byte = remaining[0]
            
            # Short header (1-RTT)
            if not (first_byte & 0x80):
                if not (first_byte & 0x40):
                    # Check for Stateless Reset
                    if self._is_stateless_reset(data):
                        self._handle_stateless_reset(data)
                        return
                    break
                
                if self.debug:
                    print(f"    📦 Short Header (1-RTT)")
                self._process_1rtt_packet(remaining, recv_time)
                break
            
            # Check for Retry
            packet_type = (first_byte & 0x30) >> 4
            if packet_type == 3:  # Retry
                if self._process_retry_packet(remaining):
                    break
                continue
            
            # Parse Long header
            header_info = parse_long_header(remaining)
            if not header_info["success"]:
                break
            
            packet_type_id = header_info["packet_type_id"]
            packet_len = header_info["pn_offset"] + header_info["length"]
            packet_data = remaining[:packet_len]
            
            if self.debug:
                print(f"    📦 {header_info['packet_type']} ({packet_len} bytes)")
            
            if packet_type_id == 0:  # Initial
                self._process_initial_packet(packet_data, header_info, recv_time)
            elif packet_type_id == 2:  # Handshake
                self._process_handshake_packet(packet_data, header_info, recv_time)
            
            offset += packet_len
        
        # Send ACKs
        need_initial = self.ack.initial_largest_pn > initial_largest_before
        need_handshake = self.ack.handshake_largest_pn > handshake_largest_before
        need_app = self.ack.app_largest_pn > app_largest_before
        
        if self.client_finished_sent and not client_finished_before:
            need_handshake = False
        
        if need_initial or need_handshake:
            self._send_combined_acks(need_initial, need_handshake)
        
        if need_app:
            self._send_1rtt_ack()
    
    def _process_initial_packet(self, packet: bytes, header_info: dict,
                                 recv_time: float) -> bool:
        """Process Initial packet."""
        # Extract server SCID
        if self.server_scid is None:
            self.server_scid = header_info["scid_bytes"]
            if self.debug:
                print(f"    📝 Server SCID: {self.server_scid.hex()}")
        
        # Decrypt
        plaintext, pn = self.crypto.decrypt_initial_packet(
            packet, header_info["pn_offset"],
            self.ack.initial_largest_pn
        )
        
        if plaintext is None:
            return False
        
        # Check duplicate
        if not self.ack.record_initial_packet(pn, recv_time, True):
            return True
        
        # Parse frames
        frames = parse_quic_frames(plaintext, False)
        self._process_frames(frames, "Initial")
        
        return True
    
    def _process_handshake_packet(self, packet: bytes, header_info: dict,
                                   recv_time: float) -> bool:
        """Process Handshake packet."""
        if not self.crypto.has_handshake_keys:
            if self.debug:
                print(f"    ⏳ Waiting for Handshake keys...")
            return False
        
        # Decrypt
        plaintext, pn = self.crypto.decrypt_handshake_packet(
            packet, header_info["pn_offset"],
            header_info["length"],
            self.ack.handshake_largest_pn
        )
        
        if plaintext is None:
            return False
        
        # Check duplicate
        if not self.ack.record_handshake_packet(pn, recv_time, True):
            return True
        
        # Parse frames
        frames = parse_quic_frames(plaintext, False)
        self._process_frames(frames, "Handshake")
        
        return True
    
    def _process_1rtt_packet(self, packet: bytes, recv_time: float) -> bool:
        """Process 1-RTT packet."""
        if not self.crypto.has_application_keys:
            if self.debug:
                print(f"    ⚠️ No application keys")
            return False
        
        dcid_len = len(self.our_scid) if self.our_scid else 8
        
        plaintext, pn, key_phase = self.crypto.decrypt_1rtt_packet(
            packet, dcid_len, self.ack.app_largest_pn
        )
        
        if plaintext is None:
            return False
        
        # Check duplicate
        if not self.ack.record_app_packet(pn, recv_time, True):
            return True
        
        if self.debug:
            print(f"    ✓ 1-RTT decrypted PN={pn}, {len(plaintext)} bytes")
        
        # Parse frames using frame processor
        self.frame_processor.process_payload(plaintext)
        
        return True
    
    def _process_frames(self, frames: list, level: str):
        """Process QUIC frames."""
        for frame in frames:
            if frame["type"] == "CRYPTO":
                self._process_crypto_frame(frame, level)
            elif frame["type"] == "ACK":
                space = PacketNumberSpace.INITIAL if level == "Initial" else PacketNumberSpace.HANDSHAKE
                self._process_ack_frame(frame, space)
            elif frame["type"] == "CONNECTION_CLOSE":
                self._handle_connection_close(frame)
    
    def _process_crypto_frame(self, frame: dict, level: str):
        """Process CRYPTO frame."""
        offset = frame["offset"]
        data = frame["data"]
        
        if level == "Initial":
            if self.initial_crypto_buffer.add_fragment(offset, data):
                self._parse_initial_crypto()
        else:
            if self.handshake_crypto_buffer.add_fragment(offset, data):
                self._parse_handshake_crypto()
    
    def _parse_initial_crypto(self):
        """Parse Initial CRYPTO for ServerHello."""
        data = self.initial_crypto_buffer.get_contiguous_data()
        if len(data) <= self.initial_crypto_parsed_offset:
            return
        
        try:
            messages = parse_tls_handshake(data, False)
            offset = 0
            
            for msg in messages:
                msg_end = offset + 4 + msg["length"]
                
                if msg_end <= self.initial_crypto_parsed_offset:
                    offset = msg_end
                    continue
                
                if msg["type"] == "ServerHello" and not self.server_hello_received:
                    self.server_hello_received = True
                    if self.debug:
                        print(f"    📨 ServerHello received!")
                    
                    if "extensions" in msg:
                        for ext in msg["extensions"]:
                            if ext["name"] == "key_share" and "key_exchange_bytes" in ext:
                                server_hello_data = data[offset:msg_end]
                                self.crypto.derive_handshake_keys(
                                    ext["key_exchange_bytes"],
                                    server_hello_data
                                )
                                self.state = HandshakeState.HANDSHAKE
                
                offset = msg_end
            
            self.initial_crypto_parsed_offset = len(data)
            
        except Exception as e:
            if self.debug:
                print(f"    ⚠️ Parse Initial CRYPTO failed: {e}")
    
    def _parse_handshake_crypto(self):
        """Parse Handshake CRYPTO for Finished."""
        data = self.handshake_crypto_buffer.get_contiguous_data()
        if len(data) <= self.handshake_crypto_parsed_offset:
            return
        
        try:
            messages = parse_tls_handshake(data, False)
            offset = 0
            
            for msg in messages:
                msg_end = offset + 4 + msg["length"]
                
                if msg_end <= self.handshake_crypto_parsed_offset:
                    offset = msg_end
                    continue
                
                if msg["type"] == "EncryptedExtensions":
                    extensions = msg.get("extensions", [])
                    # Check 0-RTT acceptance
                    if self.zero_rtt_enabled:
                        for ext in extensions:
                            if ext.get("name") == "early_data":
                                self.zero_rtt_accepted = True
                                if self.debug:
                                    print(f"    🎉 Server accepted 0-RTT!")
                                break
                        if not self.zero_rtt_accepted:
                            self.zero_rtt_rejected = True
                    
                    # Update flow control limits
                    self._process_transport_params(extensions)
                
                if msg["type"] == "Finished" and not self.finished_received:
                    self.finished_received = True
                    if self.debug:
                        print(f"    🎉 Server Finished received!")
                    
                    self.handshake_crypto_parsed_offset = len(data)
                    self._send_client_finished()
                    
                    self.state = HandshakeState.HANDSHAKE_COMPLETE
                    self._discard_initial_keys()
                    self.handshake_complete.set()
                    return
                
                offset = msg_end
            
            self.handshake_crypto_parsed_offset = len(data)
            
        except Exception as e:
            if self.debug:
                print(f"    ⚠️ Parse Handshake CRYPTO failed: {e}")
    
    def _process_transport_params(self, extensions: list):
        """Process transport parameters from EncryptedExtensions."""
        for ext in extensions:
            if ext.get("name") == "quic_transport_params":
                params = ext.get("params", {})
                self.flow.update_peer_transport_params(params)
                
                # Update max_ack_delay
                if "max_ack_delay" in params:
                    value = params["max_ack_delay"]
                    if isinstance(value, str) and "ms" in value:
                        ms = int(value.replace("ms", "").strip())
                        self.loss_detector.max_ack_delay = ms / 1000.0
                
                # Update DATAGRAM support (RFC 9221)
                if "max_datagram_frame_size" in params:
                    peer_value = params["max_datagram_frame_size"]
                    if isinstance(peer_value, int):
                        self.peer_max_datagram_frame_size = peer_value
                        if self.debug and self.datagram_enabled:
                            print(f"    📦 Peer supports DATAGRAM (max_size={peer_value})")
                
                break
    
    def _send_client_finished(self):
        """Send Client Finished message."""
        if self.client_finished_sent:
            return
        
        # Derive application keys and build Finished
        handshake_data = self.handshake_crypto_buffer.get_contiguous_data()
        finished_msg = self.crypto.derive_application_keys(handshake_data)
        
        # Build frames
        crypto_frame = build_crypto_frame(0, finished_msg)
        frames = crypto_frame
        
        if self.ack.handshake_largest_pn >= 0:
            ack_frame = self.ack.build_handshake_ack_frame()
            if ack_frame:
                frames = ack_frame + crypto_frame
        
        dcid = self.server_scid or self.original_dcid
        
        # Build Handshake packet
        handshake_packet = build_handshake_packet(
            self.crypto.handshake_secrets["client"],
            dcid, self.our_scid,
            self.client_handshake_pn, frames
        )
        
        self._track_sent_packet(
            PacketNumberSpace.HANDSHAKE,
            self.client_handshake_pn,
            len(handshake_packet),
            frames=[{"type": "CRYPTO", "offset": 0, "data": finished_msg}]
        )
        self.client_handshake_pn += 1
        self.client_finished_sent = True
        
        # Build H3 init packet
        h3_packet = self._build_h3_init_packet()
        
        # Send combined
        self.send(handshake_packet + h3_packet)
        
        if self.debug:
            print(f"    → Sent Client Finished")
            if h3_packet:
                print(f"    → Sent HTTP/3 init")
    
    def _build_h3_init_packet(self) -> bytes:
        """Build HTTP/3 initialization packet."""
        if self.h3.init_sent:
            return b""
        
        dcid = self.server_scid or self.original_dcid
        frames = b""
        
        # NEW_CONNECTION_ID
        alt_cid = os.urandom(8)
        reset_token = os.urandom(16)
        self.alt_connection_ids.append((1, alt_cid, reset_token))
        
        frames += build_new_connection_id_frame(
            sequence=1, retire_prior_to=0,
            connection_id=alt_cid, stateless_reset_token=reset_token
        )
        
        # H3 init streams
        for stream_id, data, fin in self.h3.build_init_frames():
            frames += build_stream_frame(stream_id, data, 0, fin)
        
        packet = self.crypto.build_short_header_packet(dcid, self.client_app_pn, frames)
        self._track_sent_packet(
            PacketNumberSpace.APPLICATION,
            self.client_app_pn,
            len(packet),
            frames=[]  # Simplified
        )
        self.client_app_pn += 1
        
        return packet
    
    # =========================================================================
    # HTTP/3 API
    # =========================================================================
    
    def send_request(self, method: str = "GET", path: str = "/",
                     headers: dict = None, body: bytes = None) -> int:
        """Send HTTP/3 request."""
        if not self.crypto.has_application_keys:
            raise RuntimeError("Handshake not complete")
        
        stream_id = self.h3.allocate_request_stream()
        stream_data = self.h3.build_request_frames(stream_id, method, path, headers, body)
        
        dcid = self.server_scid or self.original_dcid
        
        # Build and send
        stream_frame = build_stream_frame(stream_id, stream_data, 0, True)
        packet = self.crypto.build_short_header_packet(dcid, self.client_app_pn, stream_frame)
        
        self._track_sent_packet(
            PacketNumberSpace.APPLICATION,
            self.client_app_pn,
            len(packet),
            frames=[{"type": "STREAM", "stream_id": stream_id, "data": stream_data, "fin": True}]
        )
        
        self.send(packet)
        self.flow.on_data_sent(stream_id, len(stream_data))
        self.client_app_pn += 1
        
        if self.debug:
            print(f"    → Sent HTTP/3 {method} {path} (stream={stream_id})")
        
        return stream_id
    
    async def request(self, method: str = "GET", path: str = "/",
                      headers: dict = None, body: bytes = None,
                      timeout: float = 10.0) -> dict:
        """Send request and wait for response."""
        stream_id = self.send_request(method, path, headers, body)
        
        try:
            response = await self.h3.wait_response(stream_id, timeout)
            return {
                "status": response.status,
                "headers": response.headers,
                "body": response.body,
                "error": response.error,
            }
        except Exception as e:
            return {"status": None, "headers": [], "body": b"", "error": str(e)}
    
    # =========================================================================
    # ACK handling
    # =========================================================================
    
    def _send_combined_acks(self, need_initial: bool, need_handshake: bool):
        """Send combined ACKs."""
        dcid = self.server_scid or self.original_dcid
        
        # Build Handshake ACK
        handshake_packet = b""
        if need_handshake and self.crypto.has_handshake_keys:
            ack_frame = self.ack.build_handshake_ack_frame()
            if ack_frame:
                handshake_packet = build_handshake_packet(
                    self.crypto.handshake_secrets["client"],
                    dcid, self.our_scid,
                    self.client_handshake_pn, ack_frame
                )
                self.client_handshake_pn += 1
                self.ack.mark_handshake_ack_sent()
        
        # Build Initial ACK with padding
        initial_packet = b""
        if need_initial and self.crypto.has_initial_keys:
            ack_frame = self.ack.build_initial_ack_frame()
            if ack_frame:
                # Add padding for 1200 byte minimum
                total = len(ack_frame)
                if len(handshake_packet) + total < 1150:
                    ack_frame += build_padding_frame(1150 - len(handshake_packet) - total)
                
                initial_packet = build_initial_packet_with_secrets(
                    self.crypto.client_initial_secrets,
                    dcid, self.our_scid,
                    self.client_initial_pn, ack_frame
                )
                self.client_initial_pn += 1
                self.ack.mark_initial_ack_sent()
        
        if initial_packet or handshake_packet:
            self.send(initial_packet + handshake_packet)
    
    def _send_1rtt_ack(self):
        """Send 1-RTT ACK."""
        if not self.crypto.has_application_keys:
            return
        
        ack_frame = self.ack.build_app_ack_frame()
        if not ack_frame:
            return
        
        dcid = self.server_scid or self.original_dcid
        packet = self.crypto.build_short_header_packet(dcid, self.client_app_pn, ack_frame)
        self.send(packet)
        self.client_app_pn += 1
        self.ack.mark_app_ack_sent()
    
    def _process_ack_frame(self, frame: dict, space: PacketNumberSpace):
        """Process received ACK frame."""
        if self.debug:
            print(f"    ← ACK largest={frame['largest_ack']}")
        
        ack_ranges = [(frame['largest_ack'] - frame.get('first_ack_range', 0), 
                       frame['largest_ack'])]
        ack_delay = (frame.get('ack_delay', 0) << 3) / 1_000_000
        
        newly_acked = self.loss_detector.on_ack_received(space, ack_ranges, ack_delay)
        
        if newly_acked and self.loss_detector.cc.available_cwnd() > 0:
            self._cwnd_available.set()
        
        # Check for handshake confirmation
        if space == PacketNumberSpace.HANDSHAKE and not self._handshake_confirmed:
            for pkt in newly_acked:
                if any(f.get("type") == "CRYPTO" for f in pkt.frames):
                    if self.client_finished_sent:
                        self._discard_handshake_keys()
                        break
    
    # =========================================================================
    # Frame processor callback handlers
    # =========================================================================
    
    def _on_frame_ack(self, largest_ack: int, ack_delay: int, 
                      first_ack_range: int, ack_range_count: int):
        """Handle ACK frame from frame processor."""
        self._process_ack_frame(
            {"largest_ack": largest_ack, "first_ack_range": first_ack_range, "ack_delay": ack_delay},
            PacketNumberSpace.APPLICATION
        )
    
    def _on_frame_stream(self, stream_id: int, stream_offset: int, 
                         data: bytes, fin: bool):
        """Handle STREAM frame from frame processor."""
        # Process through H3 handler
        self.h3.process_stream_data(stream_id, stream_offset, data, fin)
        
        # Send QPACK decoder instructions if any
        instructions = self.h3.get_pending_decoder_instructions()
        if instructions:
            stream_id_dec, instr_data, instr_offset = self.h3.get_decoder_stream_data(instructions)
            frame = build_stream_frame(stream_id_dec, instr_data, instr_offset, False)
            dcid = self.server_scid or self.original_dcid
            packet = self.crypto.build_short_header_packet(dcid, self.client_app_pn, frame)
            self.send(packet)
            self.client_app_pn += 1
        
        # Update flow control
        self.flow.on_data_received(stream_id, len(data))
    
    def _on_frame_crypto_1rtt(self, crypto_offset: int, crypto_data: bytes):
        """Handle CRYPTO frame in 1-RTT packet (session tickets)."""
        try:
            tls_messages = parse_tls_handshake(crypto_data, False)
            for msg in tls_messages:
                if msg.get("type") == "NewSessionTicket" and "session_ticket" in msg:
                    ticket = msg["session_ticket"]
                    ticket.server_name = self.hostname
                    ticket.alpn = "h3"
                    if self.crypto.resumption_master_secret:
                        ticket.resumption_master_secret = self.crypto.resumption_master_secret
                    self.session_tickets.append(ticket)
                    
                    if self.session_ticket_store:
                        self.session_ticket_store.add_ticket(ticket)
                    
                    if self.debug:
                        print(f"        📋 NewSessionTicket received")
        except:
            pass
    
    def _on_frame_new_connection_id(self, seq_num: int, retire_prior: int,
                                     cid: bytes, reset_token: bytes):
        """Handle NEW_CONNECTION_ID frame."""
        self.peer_connection_ids[seq_num] = {
            'cid': cid, 'reset_token': reset_token, 'retired': False
        }
        self.peer_stateless_reset_tokens[reset_token] = cid
        
        if retire_prior > self._peer_retire_prior_to:
            self._peer_retire_prior_to = retire_prior
            self._retire_connection_ids_prior_to(retire_prior)
    
    def _on_frame_connection_close(self, error_code: int, reason: str, is_app: bool):
        """Handle CONNECTION_CLOSE frame."""
        self._peer_closed = True
        self._peer_close_error_code = error_code
        self._peer_close_reason = reason
        self.state = HandshakeState.FAILED
        self.connection_closed.set()
        
        if self._pto_timer_task and not self._pto_timer_task.done():
            self._pto_timer_task.cancel()
    
    def _on_frame_handshake_done(self):
        """Handle HANDSHAKE_DONE frame."""
        if not self._handshake_confirmed:
            self._discard_handshake_keys()
    
    def _on_frame_reset_stream(self, stream_id: int, error_code: int, final_size: int):
        """Handle RESET_STREAM frame."""
        self._reset_streams[stream_id] = error_code
        self._cwnd_available.set()
    
    def _on_frame_stop_sending(self, stream_id: int, error_code: int):
        """Handle STOP_SENDING frame."""
        self._reset_streams[stream_id] = error_code
        self._cwnd_available.set()
    
    def _on_frame_retire_connection_id(self, seq_num: int):
        """Handle RETIRE_CONNECTION_ID frame from peer."""
        # Peer is retiring one of our connection IDs
        self.alt_connection_ids = [(s, c, t) for s, c, t in self.alt_connection_ids if s != seq_num]
    
    def _on_frame_datagram(self, data: bytes):
        """Handle DATAGRAM frame."""
        if self.debug:
            print(f"    📨 DATAGRAM received: {len(data)} bytes")
        
        # Add to queue for async consumption
        try:
            self._datagram_queue.put_nowait(data)
            self._datagram_received.set()
        except asyncio.QueueFull:
            if self.debug:
                print(f"    ⚠️ DATAGRAM queue full, dropping")
            pass
    
    # =========================================================================
    # Key discard
    # =========================================================================
    
    def _discard_initial_keys(self):
        """Discard Initial keys."""
        if self._initial_keys_discarded:
            return
        if self.debug:
            print(f"    🗑️ Discarding INITIAL keys")
        self.loss_detector.spaces[PacketNumberSpace.INITIAL].sent_packets.clear()
        self._initial_keys_discarded = True
    
    def _discard_handshake_keys(self):
        """Discard Handshake keys."""
        if self._handshake_keys_discarded:
            return
        if self.debug:
            print(f"    🗑️ Discarding HANDSHAKE keys")
        self.loss_detector.spaces[PacketNumberSpace.HANDSHAKE].sent_packets.clear()
        self._handshake_confirmed = True
        self._handshake_keys_discarded = True
    
    # =========================================================================
    # Loss detection callbacks
    # =========================================================================
    
    def _track_sent_packet(self, space: PacketNumberSpace, pn: int, size: int,
                           frames: List[Dict]):
        """Track sent packet for loss detection."""
        self.loss_detector.on_packet_sent(space, pn, size, True, frames)
    
    def _on_packets_lost(self, space: PacketNumberSpace, lost: List[SentPacketInfo]):
        """Handle lost packets."""
        if self.debug:
            print(f"    ❌ {len(lost)} packets lost in {space.value}")
        
        for pkt in lost:
            for frame in pkt.frames:
                if frame.get("type") == "STREAM":
                    data = frame.get("data", b"")
                    if data:
                        self._retransmit_stream(
                            frame["stream_id"],
                            frame.get("offset", 0),
                            data,
                            frame.get("fin", False)
                        )
    
    def _on_pto_timeout(self, space: PacketNumberSpace):
        """Handle PTO timeout."""
        self.loss_detector.pto_count += 1
        if self.debug:
            print(f"    ⏰ PTO timeout (count={self.loss_detector.pto_count})")
        
        if space == PacketNumberSpace.APPLICATION:
            self._send_ping_probe()
    
    def _retransmit_stream(self, stream_id: int, offset: int, data: bytes, fin: bool):
        """Retransmit stream data."""
        if not self.crypto.has_application_keys:
            return
        
        dcid = self.server_scid or self.original_dcid
        frame = build_stream_frame(stream_id, data, offset, fin)
        packet = self.crypto.build_short_header_packet(dcid, self.client_app_pn, frame)
        
        self._track_sent_packet(
            PacketNumberSpace.APPLICATION,
            self.client_app_pn,
            len(packet),
            frames=[{"type": "STREAM", "stream_id": stream_id, "data": data, "fin": fin}]
        )
        
        self.send(packet)
        self.client_app_pn += 1
    
    def _send_ping_probe(self):
        """Send PING probe."""
        if not self.crypto.has_application_keys:
            return
        
        dcid = self.server_scid or self.original_dcid
        packet = self.crypto.build_short_header_packet(dcid, self.client_app_pn, b'\x01')
        self.send(packet)
        self.client_app_pn += 1
        
        if self.debug:
            print(f"    → PING probe")
    
    # =========================================================================
    # PTO timer
    # =========================================================================
    
    def _start_pto_timer(self):
        """Start PTO timer."""
        if self._pto_timer_task and not self._pto_timer_task.done():
            self._pto_timer_task.cancel()
        self._pto_timer_task = asyncio.create_task(self._pto_timer_loop())
    
    async def _pto_timer_loop(self):
        """PTO timer loop."""
        try:
            while not self._peer_closed:
                pto_time = self.loss_detector.get_pto_time(self._handshake_confirmed)
                delay = max(0.01, pto_time - time.time())
                
                await asyncio.sleep(delay)
                
                if self._peer_closed:
                    break
                
                if time.time() >= pto_time:
                    if self.loss_detector.has_unacked_packets(PacketNumberSpace.APPLICATION):
                        self._on_pto_timeout(PacketNumberSpace.APPLICATION)
        except asyncio.CancelledError:
            pass
    
    # =========================================================================
    # Path validation
    # =========================================================================
    
    def send_path_challenge(self) -> bytes:
        """Send PATH_CHALLENGE."""
        if not self.crypto.has_application_keys:
            return b""
        
        data = os.urandom(8)
        self._pending_path_challenges.append({
            'data': data, 'sent_time': time.time()
        })
        
        dcid = self.server_scid or self.original_dcid
        frame = build_path_challenge_frame(data)
        packet = self.crypto.build_short_header_packet(dcid, self.client_app_pn, frame)
        self.send(packet)
        self.client_app_pn += 1
        
        return data
    
    def _send_path_response(self, data: bytes):
        """Send PATH_RESPONSE."""
        if not self.crypto.has_application_keys:
            return
        
        dcid = self.server_scid or self.original_dcid
        frame = build_path_response_frame(data)
        packet = self.crypto.build_short_header_packet(dcid, self.client_app_pn, frame)
        self.send(packet)
        self.client_app_pn += 1
    
    def _handle_path_response(self, data: bytes):
        """Handle PATH_RESPONSE."""
        for i, challenge in enumerate(self._pending_path_challenges):
            if challenge['data'] == data:
                rtt = time.time() - challenge['sent_time']
                if self.debug:
                    print(f"    ✅ Path validated! RTT={rtt*1000:.2f}ms")
                self._pending_path_challenges.pop(i)
                self._path_validated = True
                break
    
    # =========================================================================
    # Stateless reset
    # =========================================================================
    
    def _is_stateless_reset(self, data: bytes) -> bool:
        """Check if packet is Stateless Reset."""
        if len(data) < 21:
            return False
        if not self.peer_stateless_reset_tokens:
            return False
        return data[-16:] in self.peer_stateless_reset_tokens
    
    def _handle_stateless_reset(self, data: bytes):
        """Handle Stateless Reset."""
        if self.debug:
            print(f"    ⚡ STATELESS RESET detected!")
        
        self.state = HandshakeState.FAILED
        self.connection_closed.set()
        self._stateless_reset_received = True
    
    def _handle_connection_close(self, frame: dict):
        """Handle CONNECTION_CLOSE frame."""
        error_code = frame.get('error_code', 0)
        reason = frame.get('reason', '')
        
        if self.debug:
            print(f"    ❌ CONNECTION_CLOSE error={error_code}")
        
        self._peer_closed = True
        self._peer_close_error_code = error_code
        self._peer_close_reason = reason
        self.connection_closed.set()
        
        if self._pto_timer_task:
            self._pto_timer_task.cancel()
    
    # =========================================================================
    # Retry handling
    # =========================================================================
    
    def _process_retry_packet(self, packet: bytes) -> bool:
        """Process Retry packet."""
        if self._retry_received:
            return False
        
        result = parse_retry_packet(packet, self.original_dcid, debug=self.debug)
        if not result["success"]:
            return False
        
        self._retry_received = True
        self._retry_source_cid = result["scid_bytes"]
        self._retry_token = result["retry_token"]
        
        # Re-derive keys with new DCID
        self.crypto.derive_initial_keys(self._retry_source_cid)
        
        # Send new Initial
        self.client_initial_pn = 0
        new_packet = create_initial_packet_with_retry_token(
            self.hostname, self._retry_source_cid, self.our_scid,
            self._retry_token, self.crypto.private_key,
            self.crypto.client_hello, debug=self.debug
        )
        
        self.send(new_packet)
        self.client_initial_pn += 1
        
        return True
    
    # =========================================================================
    # Connection ID management
    # =========================================================================
    
    def _retire_connection_ids_prior_to(self, retire_prior_to: int):
        """Retire connection IDs."""
        for seq, info in self.peer_connection_ids.items():
            if seq < retire_prior_to and not info.get('retired'):
                info['retired'] = True
                self._send_retire_connection_id(seq)
    
    def _send_retire_connection_id(self, seq: int):
        """Send RETIRE_CONNECTION_ID."""
        if not self.crypto.has_application_keys:
            return
        
        dcid = self.server_scid or self.original_dcid
        frame = build_retire_connection_id_frame(seq)
        packet = self.crypto.build_short_header_packet(dcid, self.client_app_pn, frame)
        self.send(packet)
        self.client_app_pn += 1
    
    def send_connection_close(self, error_code: int = 0, reason: str = "",
                               is_application: bool = True):
        """Send CONNECTION_CLOSE."""
        if not self.crypto.has_application_keys:
            return
        
        dcid = self.server_scid or self.original_dcid
        frame = build_connection_close_frame(error_code, None, reason, is_application)
        packet = self.crypto.build_short_header_packet(dcid, self.client_app_pn, frame)
        self.send(packet)
        self.client_app_pn += 1
        self.connection_closed.set()
    
    def send_retire_connection_id(self, seq: int):
        """Public API: Send RETIRE_CONNECTION_ID."""
        self._send_retire_connection_id(seq)
    
    # =========================================================================
    # Streaming API (for large uploads)
    # =========================================================================
    
    def open_stream(self, method: str = "POST", path: str = "/",
                    headers: dict = None) -> int:
        """
        Open a new HTTP/3 request stream and send headers (without FIN).
        
        Use write() to send body data, then finish() to complete.
        
        Args:
            method: HTTP method
            path: Request path
            headers: Additional headers
            
        Returns:
            int: Stream ID
        """
        if not self.crypto.has_application_keys:
            raise RuntimeError("Handshake not complete")
        
        stream_id = self.h3.allocate_request_stream()
        headers_frame = self.h3.build_headers_only(stream_id, method, path, headers)
        
        dcid = self.server_scid or self.original_dcid
        
        # Send HEADERS without FIN
        frame = build_stream_frame(stream_id, headers_frame, 0, False)
        packet = self.crypto.build_short_header_packet(dcid, self.client_app_pn, frame)
        
        self._track_sent_packet(
            PacketNumberSpace.APPLICATION,
            self.client_app_pn,
            len(packet),
            frames=[{"type": "STREAM", "stream_id": stream_id, "data": headers_frame, "fin": False}]
        )
        
        self.send(packet)
        self.flow.on_data_sent(stream_id, len(headers_frame))
        self.client_app_pn += 1
        
        # Initialize stream write state
        self.h3.init_stream_write(stream_id, len(headers_frame))
        
        if self.debug:
            print(f"    → Opened stream {stream_id} for {method} {path}")
        
        return stream_id
    
    async def write(self, stream_id: int, data: bytes, timeout: float = 30.0) -> int:
        """
        Write data to an open stream.
        
        Args:
            stream_id: Stream ID
            data: Data to write (wrapped in H3 DATA frame)
            timeout: Timeout in seconds
            
        Returns:
            int: Bytes written
        """
        # Build H3 DATA frame
        data_frame = self.h3.build_data_frame(data)
        
        dcid = self.server_scid or self.original_dcid
        offset = self.h3.get_stream_write_offset(stream_id)
        
        MAX_CHUNK = 1100
        total = len(data_frame)
        sent = 0
        
        while sent < total:
            # Check for stream reset
            if stream_id in self._reset_streams:
                raise RuntimeError(f"Stream {stream_id} reset by peer")
            
            # Check flow control
            can_send, allowed, reason = self.flow.can_send(stream_id, total - sent)
            
            if not can_send or allowed <= 0:
                self._cwnd_available.clear()
                try:
                    await asyncio.wait_for(self._cwnd_available.wait(), timeout=1.0)
                except asyncio.TimeoutError:
                    pass
                continue
            
            # Send chunk
            chunk_size = min(MAX_CHUNK, allowed, total - sent)
            chunk = data_frame[sent:sent + chunk_size]
            
            frame = build_stream_frame(stream_id, chunk, offset, False)
            packet = self.crypto.build_short_header_packet(dcid, self.client_app_pn, frame)
            
            self._track_sent_packet(
                PacketNumberSpace.APPLICATION,
                self.client_app_pn,
                len(packet),
                frames=[{"type": "STREAM", "stream_id": stream_id, "offset": offset, "data": chunk, "fin": False}]
            )
            
            self.send(packet)
            self.flow.on_data_sent(stream_id, chunk_size)
            self.client_app_pn += 1
            
            sent += chunk_size
            offset += chunk_size
        
        self.h3.update_stream_write_offset(stream_id, total)
        
        return len(data)
    
    async def finish(self, stream_id: int):
        """Finish writing to a stream (send FIN)."""
        dcid = self.server_scid or self.original_dcid
        offset = self.h3.get_stream_write_offset(stream_id)
        
        # Send empty frame with FIN
        frame = build_stream_frame(stream_id, b"", offset, True)
        packet = self.crypto.build_short_header_packet(dcid, self.client_app_pn, frame)
        
        self._track_sent_packet(
            PacketNumberSpace.APPLICATION,
            self.client_app_pn,
            len(packet),
            frames=[{"type": "STREAM", "stream_id": stream_id, "offset": offset, "data": b"", "fin": True}]
        )
        
        self.send(packet)
        self.client_app_pn += 1
        
        self.h3.close_stream_write(stream_id)
        
        if self.debug:
            print(f"    ✅ Stream {stream_id} finished (FIN)")
    
    async def read_response(self, stream_id: int, timeout: float = 60.0) -> dict:
        """
        Wait for and return response for a stream.
        
        Args:
            stream_id: Stream ID
            timeout: Response timeout
            
        Returns:
            dict: Response with status, headers, body
        """
        try:
            response = await self.h3.wait_response(stream_id, timeout)
            return {
                "status": response.status,
                "headers": response.headers,
                "body": response.body,
                "error": response.error,
            }
        except Exception as e:
            return {"status": None, "headers": [], "body": b"", "error": str(e)}
    
    # =========================================================================
    # 0-RTT API
    # =========================================================================
    
    def send_0rtt_request(self, method: str = "GET", path: str = "/",
                          headers: dict = None, body: bytes = None) -> int:
        """
        Send HTTP/3 request using 0-RTT early data.
        
        Args:
            method: HTTP method
            path: Request path
            headers: Additional headers
            body: Request body
            
        Returns:
            int: Stream ID
        """
        if not self.crypto.has_0rtt_keys:
            raise RuntimeError("0-RTT not enabled")
        
        stream_id = self.h3.allocate_request_stream()
        stream_data = self.h3.build_request_frames(stream_id, method, path, headers, body)
        
        # Build 0-RTT packet
        frame = build_stream_frame(stream_id, stream_data, 0, True)
        packet = build_0rtt_packet(
            self.crypto.zero_rtt_secrets["client"],
            self.original_dcid,
            self.our_scid,
            self.client_app_pn,
            frame,
            debug=self.debug
        )
        
        self.send(packet)
        self.client_app_pn += 1
        
        if self.debug:
            print(f"    → Sent 0-RTT {method} {path} (stream={stream_id})")
        
        return stream_id
    
    async def request_0rtt(self, method: str = "GET", path: str = "/",
                           headers: dict = None, body: bytes = None,
                           timeout: float = 10.0) -> dict:
        """
        Send 0-RTT HTTP/3 request with session resumption.
        
        Args:
            method: HTTP method
            path: Request path
            headers: Additional headers
            body: Request body
            timeout: Timeout
            
        Returns:
            dict: Response with 0rtt status
        """
        session_ticket = self._try_load_session_ticket(force_0rtt=False)
        
        if not session_ticket:
            # No ticket, use normal request
            if self.debug:
                print(f"    ⚠️ No valid session ticket, using 1-RTT")
            
            success = await self._do_handshake_1rtt(timeout / 2)
            if not success:
                return {"status": None, "headers": [], "body": b"", "error": "handshake failed", "0rtt": False}
            
            response = await self.request(method, path, headers, body, timeout / 2)
            response["0rtt"] = False
            return response
        
        # Do 0-RTT handshake
        self.start_time = time.time()
        self.zero_rtt_enabled = True
        self.crypto.zero_rtt_enabled = True
        
        # Generate Initial with PSK
        result = create_initial_packet_with_psk(
            self.hostname, session_ticket, debug=self.debug,
            max_datagram_frame_size=self.local_max_datagram_frame_size
        )
        packet, dcid, scid, private_key, client_hello, client_random, psk, early_secret = result
        
        self.original_dcid = dcid
        self.our_scid = scid
        self.crypto.private_key = private_key
        self.crypto.client_hello = client_hello
        self.crypto.client_random = client_random
        self.crypto.zero_rtt_psk = psk
        self.crypto.zero_rtt_early_secret = early_secret
        
        self.crypto.derive_initial_keys(dcid)
        self.crypto.derive_0rtt_keys(early_secret)
        
        # Send Initial
        self.send(packet)
        self.client_initial_pn += 1
        
        # Send 0-RTT request
        stream_id = self.send_0rtt_request(method, path, headers, body)
        
        # Wait for handshake
        try:
            await asyncio.wait_for(self.handshake_complete.wait(), timeout=timeout / 2)
        except asyncio.TimeoutError:
            return {"status": None, "headers": [], "body": b"", "error": "handshake timeout", "0rtt": True}
        
        # Wait for response
        try:
            response = await self.h3.wait_response(stream_id, timeout / 2)
            return {
                "status": response.status,
                "headers": response.headers,
                "body": response.body,
                "error": response.error,
                "0rtt": True,
                "0rtt_accepted": self.zero_rtt_accepted,
            }
        except asyncio.TimeoutError:
            return {"status": None, "headers": [], "body": b"", "error": "response timeout", "0rtt": True}


    # =========================================================================
    # DATAGRAM API (RFC 9221)
    # =========================================================================
    
    def can_send_datagram(self, size: int = 0) -> bool:
        """
        Check if DATAGRAM can be sent.
        
        DATAGRAM can only be sent if:
        1. We have enabled DATAGRAM support (datagram_enabled=True)
        2. Peer has advertised max_datagram_frame_size > 0
        3. (Optional) The data size fits within peer's limit
        
        Args:
            size: Size of data to send (0 to just check if enabled)
            
        Returns:
            bool: True if DATAGRAM can be sent
        """
        if not self.datagram_enabled:
            return False
        if self.peer_max_datagram_frame_size == 0:
            return False
        if size > 0 and size > self.peer_max_datagram_frame_size:
            return False
        return True
    
    def send_datagram(self, data: bytes) -> bool:
        """
        Send an unreliable DATAGRAM.
        
        DATAGRAM frames provide unreliable delivery of application data.
        They are ack-eliciting but NOT retransmitted on loss.
        
        Args:
            data: Application data to send
            
        Returns:
            bool: True if sent successfully, False if DATAGRAM not available
            
        Raises:
            ValueError: If data exceeds peer's max_datagram_frame_size
            RuntimeError: If handshake not complete
        """
        if not self.crypto.has_application_keys:
            raise RuntimeError("Handshake not complete")
        
        if not self.can_send_datagram(len(data)):
            if not self.datagram_enabled:
                if self.debug:
                    print(f"    ⚠️ DATAGRAM not enabled")
                return False
            if self.peer_max_datagram_frame_size == 0:
                if self.debug:
                    print(f"    ⚠️ Peer doesn't support DATAGRAM")
                return False
            if len(data) > self.peer_max_datagram_frame_size:
                raise ValueError(
                    f"DATAGRAM data ({len(data)} bytes) exceeds peer limit "
                    f"({self.peer_max_datagram_frame_size} bytes)"
                )
        
        # Build and send DATAGRAM frame
        dcid = self.server_scid or self.original_dcid
        frame = build_datagram_frame(data, include_length=True)
        packet = self.crypto.build_short_header_packet(dcid, self.client_app_pn, frame)
        
        # Track sent packet (but DATAGRAM is not retransmitted)
        self._track_sent_packet(
            PacketNumberSpace.APPLICATION,
            self.client_app_pn,
            len(packet),
            frames=[{"type": "DATAGRAM", "data": data, "retransmit": False}]
        )
        
        self.send(packet)
        self.client_app_pn += 1
        
        if self.debug:
            print(f"    → DATAGRAM sent: {len(data)} bytes")
        
        return True
    
    async def recv_datagram(self, timeout: float = None) -> Optional[bytes]:
        """
        Receive a DATAGRAM.
        
        Waits for and returns the next received DATAGRAM.
        
        Args:
            timeout: Timeout in seconds (None = wait forever)
            
        Returns:
            bytes: Received datagram data, or None on timeout
        """
        try:
            if timeout is not None:
                return await asyncio.wait_for(
                    self._datagram_queue.get(), timeout=timeout
                )
            else:
                return await self._datagram_queue.get()
        except asyncio.TimeoutError:
            return None
    
    def recv_datagram_nowait(self) -> Optional[bytes]:
        """
        Receive a DATAGRAM without waiting.
        
        Returns:
            bytes: Received datagram data, or None if no datagrams available
        """
        try:
            return self._datagram_queue.get_nowait()
        except asyncio.QueueEmpty:
            return None
    
    @property
    def datagram_available(self) -> bool:
        """Check if DATAGRAM is available (both sides support it)."""
        return self.datagram_enabled and self.peer_max_datagram_frame_size > 0
    
    @property
    def max_datagram_size(self) -> int:
        """
        Get the maximum DATAGRAM size that can be sent.
        
        Returns minimum of local and peer limits, or 0 if not available.
        """
        if not self.datagram_available:
            return 0
        return min(self.local_max_datagram_frame_size, self.peer_max_datagram_frame_size)


# Alias for backward compatibility

