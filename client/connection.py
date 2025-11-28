"""
QUIC Client Connection Implementation
"""

import os
import socket
import struct
import hashlib
import asyncio
import time
from typing import Optional, Dict, List, Any
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from quic.constants import QUIC_VERSION
from quic.varint import encode_varint, decode_varint, decode_packet_number
from quic.crypto import (
    derive_initial_secrets, derive_server_initial_secrets,
    derive_handshake_secrets, derive_application_secrets,
    build_client_finished_message, perform_ecdh,
    remove_header_protection, decrypt_payload, encrypt_payload,
    apply_header_protection,
    derive_resumption_master_secret, derive_0rtt_secrets,
    derive_0rtt_application_secrets, derive_handshake_secrets_with_psk,
)
from quic.frames import (
    build_crypto_frame, build_ack_frame, build_padding_frame,
    build_stream_frame, build_new_connection_id_frame,
    build_connection_close_frame, parse_quic_frames,
    build_max_data_frame, build_max_stream_data_frame,
)
from quic.packets import (
    build_initial_packet_with_secrets, build_handshake_packet,
    create_initial_packet, parse_long_header,
    build_0rtt_packet, create_initial_packet_with_psk,
)
from tls.handshake import parse_tls_handshake
from tls.session import SessionTicket, SessionTicketStore
from h3.frames import (
    build_h3_control_stream_data, build_h3_qpack_encoder_stream_data,
    build_h3_qpack_decoder_stream_data, build_qpack_request_headers,
    build_h3_headers_frame, build_h3_data_frame,
)
from h3.streams import H3StreamManager, describe_stream_id
from utils.keylog import write_keylog

from .state import HandshakeState, CryptoBuffer, PacketTracker
from .protocol import RealtimeQUICProtocol
from .loss_detection import LossDetector, PacketNumberSpace, SentPacketInfo


class RealtimeQUICClient:
    """
    QUIC Client with real-time packet processing.
    Processes packets as they arrive, sends ACKs immediately.
    Supports 0-RTT session resumption.
    """
    
    def __init__(self, hostname: str, port: int, debug: bool = True, 
                 keylog_file: str = None, session_file: str = None):
        self.hostname = hostname
        self.port = port
        self.debug = debug
        self.keylog_file = keylog_file
        self.session_file = session_file  # Path to session ticket file for 0-RTT
        self.target_ip: Optional[str] = None
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.protocol: Optional[RealtimeQUICProtocol] = None
        
        # Connection state
        self.state = HandshakeState.INITIAL
        self.original_dcid: Optional[bytes] = None
        self.our_scid: Optional[bytes] = None
        self.server_scid: Optional[bytes] = None
        
        # Keys
        self.private_key: Optional[X25519PrivateKey] = None
        self.client_hello: Optional[bytes] = None
        self.client_random: Optional[bytes] = None
        self.client_initial_secrets: Optional[dict] = None
        self.server_initial_secrets: Optional[dict] = None
        self.handshake_secrets: Optional[dict] = None
        self.application_secrets: Optional[dict] = None
        
        # 0-RTT related
        self.zero_rtt_secrets: Optional[dict] = None  # 0-RTT encryption secrets
        self.zero_rtt_psk: Optional[bytes] = None  # PSK for this connection
        self.zero_rtt_early_secret: Optional[bytes] = None  # Early secret
        self.zero_rtt_enabled: bool = False  # Whether 0-RTT is being attempted
        self.zero_rtt_accepted: bool = False  # Whether server accepted 0-RTT
        self.zero_rtt_rejected: bool = False  # Whether server rejected 0-RTT
        # NOTE: 0-RTT and 1-RTT share the same packet number space (RFC 9000 Section 12.3)
        # So we use client_app_pn for both, no separate client_0rtt_pn needed
        
        # Session ticket store
        self.session_ticket_store: Optional[SessionTicketStore] = None
        if session_file:
            self.session_ticket_store = SessionTicketStore(session_file)
        
        # TLS handshake transcript
        self.server_hello_data: Optional[bytes] = None
        self.client_finished_sent: bool = False
        self.client_finished_message: Optional[bytes] = None
        
        # Packet tracking per encryption level
        self.initial_tracker = PacketTracker()
        self.handshake_tracker = PacketTracker()
        self.app_tracker = PacketTracker()
        self.zero_rtt_tracker = PacketTracker()  # Track 0-RTT packets
        
        # CRYPTO buffers per encryption level
        self.initial_crypto_buffer = CryptoBuffer()
        self.handshake_crypto_buffer = CryptoBuffer()
        
        # Packet number for sending
        self.client_initial_pn = 0
        self.client_handshake_pn = 0
        self.client_app_pn = 0
        
        # TLS handshake messages received
        self.server_hello_received = False
        self.finished_received = False
        
        # Track parsed offsets
        self.initial_crypto_parsed_offset = 0
        self.handshake_crypto_parsed_offset = 0
        
        # Events
        self.handshake_complete = asyncio.Event()
        self.connection_closed = asyncio.Event()
        
        # Stats
        self.packets_received = 0
        self.packets_sent = 0
        self.bytes_received = 0
        self.start_time = 0.0
        
        # HTTP/3 stream manager
        self.h3_manager = H3StreamManager()
        
        # HTTP/3 initialization state
        self.h3_init_sent: bool = False
        self.h3_local_control_stream_id = 2
        self.h3_local_encoder_stream_id = 6
        self.h3_local_decoder_stream_id = 10
        self.h3_local_decoder_stream_offset = 0  # Track offset for decoder stream
        self.h3_settings = {
            0x01: 4096,  # QPACK_MAX_TABLE_CAPACITY
            0x07: 16,    # QPACK_BLOCKED_STREAMS
            0x08: 1,     # EXTENDED_CONNECT
        }
        self.h3_max_push_id = 8
        
        # Alternative connection IDs
        self.alt_connection_ids = []
        
        # Session tickets for 0-RTT
        self.session_tickets = []
        self.resumption_master_secret = None
        
        # Next client-initiated bidirectional stream ID (0, 4, 8, ...)
        self.next_request_stream_id = 0
        
        # Response events for waiting on responses
        self.response_events = {}  # stream_id -> asyncio.Event
        self.pending_responses = {}  # stream_id -> response data
        
        # Pending 0-RTT requests (sent before handshake completes)
        self.pending_0rtt_requests = []  # List of (stream_id, request_info)
        
        # Loss detection and recovery
        self.loss_detector = LossDetector(debug=debug)
        self.loss_detector.on_packets_lost = self._on_packets_lost
        self.loss_detector.on_pto_timeout = self._on_pto_timeout
        
        # Handshake confirmation flag (set when Client Finished is ACKed)
        self._handshake_confirmed: bool = False
        
        # Key discard flags (to avoid using discarded keys)
        self._initial_keys_discarded: bool = False
        self._handshake_keys_discarded: bool = False
        
        # PTO timer task
        self._pto_timer_task: Optional[asyncio.Task] = None
        
        # Track frames for retransmission
        self._pending_crypto_data: Dict[str, bytes] = {
            "initial": b"",
            "handshake": b"",
        }
        
        # Stream data for retransmission (stream_id -> {offset: data})
        self._pending_stream_data: Dict[int, Dict[int, bytes]] = {}
        
        # Flow control state - connection level
        # Initial values from QUIC transport parameters (see tls/extensions.py)
        # For embedded devices with 2Mbps bandwidth:
        #   BDP = 2Mbps × 200ms = 50KB, recommend 2×BDP = ~64KB
        # For high-bandwidth devices: use 1MB (1048576)
        self._fc_initial_max_data = 65536  # 64KB - suitable for 2Mbps embedded devices
        self._fc_max_data_sent = self._fc_initial_max_data  # Last MAX_DATA value sent to peer
        self._fc_data_received = 0  # Total bytes received on all streams
        self._fc_window_update_threshold = 0.5  # Update when 50% consumed
        
        # Flow control state - per stream level
        self._fc_initial_max_stream_data = 65536  # 64KB - suitable for 2Mbps embedded devices
        self._fc_stream_max_sent: Dict[int, int] = {}  # stream_id -> last MAX_STREAM_DATA sent
        self._fc_stream_received: Dict[int, int] = {}  # stream_id -> bytes received on stream
        
    async def connect(self):
        """Resolve hostname and create UDP socket."""
        self.target_ip = socket.gethostbyname(self.hostname)
        if self.debug:
            print(f"    Resolved: {self.target_ip}")
        
        loop = asyncio.get_event_loop()
        self.transport, self.protocol = await loop.create_datagram_endpoint(
            lambda: RealtimeQUICProtocol(self),
            remote_addr=(self.target_ip, self.port)
        )
        
    def send(self, data: bytes):
        """Send UDP packet."""
        if self.transport:
            self.transport.sendto(data)
            self.packets_sent += 1
            
    def close(self):
        """Close the connection."""
        # Cancel PTO timer if running
        if self._pto_timer_task and not self._pto_timer_task.done():
            self._pto_timer_task.cancel()
        if self.transport:
            self.transport.close()
    
    def _start_pto_timer(self):
        """Start or restart the PTO timer."""
        if self._pto_timer_task and not self._pto_timer_task.done():
            self._pto_timer_task.cancel()
        
        self._pto_timer_task = asyncio.create_task(self._pto_timer_loop())
    
    async def _pto_timer_loop(self):
        """PTO timer loop - checks for timeouts and triggers retransmission.
        
        RFC 9002 Section 6.2.2.1: When no ack-eliciting packets are in flight,
        the client MUST send an ack-eliciting packet to allow the server to
        detect lost packets.
        """
        try:
            while True:
                pto_time = self.loss_detector.get_pto_time(self._handshake_confirmed)
                now = time.time()
                delay = max(0.01, pto_time - now)  # At least 10ms
                
                await asyncio.sleep(delay)
                
                # Check if we need to retransmit
                now = time.time()
                if now >= pto_time:
                    # Determine which space to probe
                    if self.loss_detector.has_unacked_packets(PacketNumberSpace.INITIAL):
                        self._handle_pto_timeout(PacketNumberSpace.INITIAL)
                    elif self.loss_detector.has_unacked_packets(PacketNumberSpace.HANDSHAKE):
                        self._handle_pto_timeout(PacketNumberSpace.HANDSHAKE)
                    elif self.loss_detector.has_unacked_packets(PacketNumberSpace.APPLICATION):
                        self._handle_pto_timeout(PacketNumberSpace.APPLICATION)
                    elif not self.handshake_complete.is_set():
                        # RFC 9002: During handshake, even if no unacked packets,
                        # client MUST send ack-eliciting packets to help server
                        # detect packet loss and retransmit
                        self._send_handshake_probe()
                    else:
                        # Handshake complete, no unacked packets, sleep longer
                        await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            if self.debug:
                print(f"    ⚠️ PTO timer error: {e}")
    
    def _handle_pto_timeout(self, space: PacketNumberSpace):
        """Handle PTO timeout by sending probe packets."""
        self.loss_detector.pto_count += 1
        
        if self.debug:
            print(f"\n    ⏰ PTO timeout (count={self.loss_detector.pto_count}): space={space.value}")
        
        if space == PacketNumberSpace.INITIAL:
            self._retransmit_initial_crypto()
        elif space == PacketNumberSpace.HANDSHAKE:
            self._retransmit_handshake_crypto()
        elif space == PacketNumberSpace.APPLICATION:
            # Try to retransmit unacked STREAM data first, otherwise send PING
            self._retransmit_application_data()
    
    def _retransmit_initial_crypto(self):
        """Retransmit Initial CRYPTO data."""
        if not self.client_hello:
            return
        
        if self.debug:
            print(f"    🔄 Retransmitting Initial CRYPTO (ClientHello)")
        
        dcid = self.server_scid if self.server_scid else self.original_dcid
        
        # Rebuild CRYPTO frame with ClientHello
        crypto_frame = build_crypto_frame(0, self.client_hello)
        
        # Calculate padding needed to meet 1200 byte minimum
        # Header size: 1 (first byte) + 4 (version) + 1 (dcid len) + len(dcid) + 
        #              1 (scid len) + len(scid) + 1-2 (token len varint) + 2 (length field) + 
        #              1-2 (packet number)
        # Auth tag: 16 bytes
        header_size = 1 + 4 + 1 + len(dcid) + 1 + len(self.our_scid) + 1 + 2 + 2
        auth_tag_size = 16
        min_packet_size = 1200
        
        current_payload_size = len(crypto_frame)
        overhead = header_size + auth_tag_size
        padding_needed = min_packet_size - overhead - current_payload_size
        
        if padding_needed > 0:
            crypto_frame += build_padding_frame(padding_needed)
        
        # Build and send Initial packet
        packet = build_initial_packet_with_secrets(
            self.client_initial_secrets,
            dcid,
            self.our_scid,
            self.client_initial_pn,
            crypto_frame
        )
        
        # Ensure packet is at least 1200 bytes
        if len(packet) < 1200:
            # Rebuild with more padding
            extra_padding = 1200 - len(packet) + 10  # Add a bit extra to be safe
            crypto_frame = build_crypto_frame(0, self.client_hello)
            crypto_frame += build_padding_frame(padding_needed + extra_padding)
            packet = build_initial_packet_with_secrets(
                self.client_initial_secrets,
                dcid,
                self.our_scid,
                self.client_initial_pn,
                crypto_frame
            )
        
        # Track the sent packet
        self._track_sent_packet(
            PacketNumberSpace.INITIAL,
            self.client_initial_pn,
            len(packet),
            frames=[{"type": "CRYPTO", "offset": 0, "data": self.client_hello}]
        )
        
        self.send(packet)
        self.client_initial_pn += 1
        
        if self.debug:
            print(f"    → Sent Initial retransmit (PN={self.client_initial_pn - 1}, size={len(packet)} bytes)")
    
    def _retransmit_handshake_crypto(self):
        """Retransmit Handshake CRYPTO data (Client Finished)."""
        if not self.handshake_secrets or not self.client_finished_message:
            return
        
        if self.debug:
            print(f"    🔄 Retransmitting Handshake CRYPTO (Client Finished)")
        
        dcid = self.server_scid if self.server_scid else self.original_dcid
        
        # Rebuild CRYPTO frame with Client Finished
        crypto_frame = build_crypto_frame(0, self.client_finished_message)
        
        # Include ACK if we have received handshake packets
        frames = crypto_frame
        if self.handshake_tracker.largest_pn >= 0:
            hs_ack_ranges = self.handshake_tracker.get_ack_ranges()
            ack_frame = build_ack_frame(
                largest_ack=self.handshake_tracker.largest_pn,
                ack_delay=self.handshake_tracker.get_ack_delay(),
                first_ack_range=self.handshake_tracker.get_first_ack_range(),
                ack_ranges=hs_ack_ranges
            )
            frames = ack_frame + crypto_frame
        
        # Build and send Handshake packet
        packet = build_handshake_packet(
            self.handshake_secrets["client"],
            dcid,
            self.our_scid,
            self.client_handshake_pn,
            frames
        )
        
        # Track the sent packet
        self._track_sent_packet(
            PacketNumberSpace.HANDSHAKE,
            self.client_handshake_pn,
            len(packet),
            frames=[{"type": "CRYPTO", "offset": 0, "data": self.client_finished_message}]
        )
        
        self.send(packet)
        self.client_handshake_pn += 1
        
        if self.debug:
            print(f"    → Sent Handshake retransmit (PN={self.client_handshake_pn - 1})")
    
    def _retransmit_application_data(self):
        """
        Retransmit unacked APPLICATION data on PTO timeout.
        
        Per RFC 9002, PTO should send ack-eliciting packets.
        We prefer retransmitting actual data over just PING.
        
        Note: If client's request was ACKed but server's response was lost,
        the SERVER will detect the loss (response not ACKed) and retransmit.
        Client should NOT resend the request - that would be wasteful and
        potentially cause duplicate processing.
        """
        if not self.application_secrets:
            return
        
        # Get unacked packets in APPLICATION space
        unacked = self.loss_detector.get_unacked_packets(PacketNumberSpace.APPLICATION)
        
        # Find STREAM frames to retransmit
        retransmitted = False
        for pkt in unacked:
            for frame in pkt.frames:
                if frame.get("type") == "STREAM":
                    stream_id = frame.get("stream_id")
                    offset = frame.get("offset", 0)
                    data = frame.get("data", b"")
                    fin = frame.get("fin", False)
                    
                    if data:
                        self._retransmit_stream_data(stream_id, offset, data, fin)
                        retransmitted = True
                        # Only retransmit one STREAM frame per PTO to avoid burst
                        break
            if retransmitted:
                break
        
        # If no STREAM data to retransmit, send PING to keep connection alive
        # and help server detect if its packets were lost
        if not retransmitted:
            self._send_ping_probe()
    
    def _send_ping_probe(self):
        """Send a PING frame as a probe packet."""
        if not self.application_secrets:
            return
        
        if self.debug:
            print(f"    🔄 Sending PING probe")
        
        dcid = self.server_scid if self.server_scid else self.original_dcid
        
        # Build PING frame (just 0x01)
        ping_frame = b'\x01'
        
        # Build and send 1-RTT packet
        packet = self._build_short_header_packet(dcid, self.client_app_pn, ping_frame)
        
        # Track the sent packet
        self._track_sent_packet(
            PacketNumberSpace.APPLICATION,
            self.client_app_pn,
            len(packet),
            frames=[{"type": "PING"}]
        )
        
        self.send(packet)
        self.client_app_pn += 1
        
        if self.debug:
            print(f"    → Sent PING probe (PN={self.client_app_pn - 1})")
    
    def _send_handshake_probe(self):
        """
        Send a probe packet during handshake when no ack-eliciting packets are in flight.
        
        RFC 9002 Section 6.2.2.1: During the handshake, if no ack-eliciting packets
        are in flight, the client MUST send an ack-eliciting packet.
        
        This helps the server detect lost packets and retransmit them.
        """
        self.loss_detector.pto_count += 1
        
        if self.debug:
            print(f"\n    ⏰ Handshake probe (PTO count={self.loss_detector.pto_count})")
        
        dcid = self.server_scid if self.server_scid else self.original_dcid
        
        # Prefer Handshake space if keys are available
        if self.handshake_secrets and not self._handshake_keys_discarded:
            # Send Handshake PING with ACK
            frames = b'\x01'  # PING frame
            
            # Add ACK if we've received handshake packets
            if self.handshake_tracker.largest_pn >= 0:
                hs_ack_ranges = self.handshake_tracker.get_ack_ranges()
                ack_frame = build_ack_frame(
                    largest_ack=self.handshake_tracker.largest_pn,
                    ack_delay=self.handshake_tracker.get_ack_delay(),
                    first_ack_range=self.handshake_tracker.get_first_ack_range(),
                    ack_ranges=hs_ack_ranges
                )
                frames = ack_frame + frames
            
            packet = build_handshake_packet(
                self.handshake_secrets["client"],
                dcid,
                self.our_scid,
                self.client_handshake_pn,
                frames
            )
            
            # Track the sent packet
            self._track_sent_packet(
                PacketNumberSpace.HANDSHAKE,
                self.client_handshake_pn,
                len(packet),
                frames=[{"type": "PING"}]
            )
            
            self.send(packet)
            pn_used = self.client_handshake_pn
            self.client_handshake_pn += 1
            
            if self.debug:
                print(f"    → Sent Handshake PING probe (PN={pn_used})")
        
        elif self.client_initial_secrets and not self._initial_keys_discarded:
            # Fall back to Initial space - resend ClientHello
            self._retransmit_initial_crypto()
        
        else:
            if self.debug:
                print(f"    ⚠️ No keys available for handshake probe")
    
    def _track_sent_packet(self, space: PacketNumberSpace, packet_number: int,
                           sent_bytes: int, frames: List[Dict[str, Any]], 
                           ack_eliciting: bool = True):
        """Track a sent packet for loss detection."""
        self.loss_detector.on_packet_sent(
            space=space,
            packet_number=packet_number,
            sent_bytes=sent_bytes,
            ack_eliciting=ack_eliciting,
            frames=frames
        )
    
    def _discard_initial_keys(self):
        """
        Discard INITIAL keys after handshake keys are available.
        
        Per RFC 9001 Section 4.9.1:
        - Initial keys are discarded when handshake keys become available
        """
        if self._initial_keys_discarded:
            return  # Already discarded
        
        if self.debug:
            print(f"    🗑️ Discarding INITIAL packet space")
        
        # Clear sent packets in INITIAL space
        initial_state = self.loss_detector.spaces[PacketNumberSpace.INITIAL]
        unacked_initial = len([p for p in initial_state.sent_packets.values() 
                               if not p.acknowledged and not p.declared_lost])
        if unacked_initial > 0 and self.debug:
            print(f"      - Clearing {unacked_initial} unacked INITIAL packets")
        initial_state.sent_packets.clear()
        initial_state.bytes_in_flight = 0
        
        self._initial_keys_discarded = True
    
    def _discard_handshake_keys(self):
        """
        Discard HANDSHAKE keys after handshake is confirmed.
        
        Per RFC 9001 Section 4.9.2:
        - Handshake keys are discarded when the handshake is confirmed
        - For clients, this is when they receive HANDSHAKE_DONE or 
          when their Client Finished is acknowledged
        """
        if self._handshake_keys_discarded:
            return  # Already discarded
        
        if self.debug:
            print(f"    🗑️ Discarding HANDSHAKE packet space")
        
        # Clear sent packets in HANDSHAKE space
        handshake_state = self.loss_detector.spaces[PacketNumberSpace.HANDSHAKE]
        unacked_handshake = len([p for p in handshake_state.sent_packets.values() 
                                  if not p.acknowledged and not p.declared_lost])
        if unacked_handshake > 0 and self.debug:
            print(f"      - Clearing {unacked_handshake} unacked HANDSHAKE packets")
        handshake_state.sent_packets.clear()
        handshake_state.bytes_in_flight = 0
        
        # Mark handshake as confirmed and keys as discarded
        self._handshake_confirmed = True
        self._handshake_keys_discarded = True
    
    def _on_packets_lost(self, space: PacketNumberSpace, lost_packets: List[SentPacketInfo]):
        """Handle lost packets by retransmitting their frames."""
        if self.debug:
            print(f"\n    ❌ {len(lost_packets)} packet(s) lost in {space.value} space")
        
        for lost_packet in lost_packets:
            if self.debug:
                print(f"      - PN={lost_packet.packet_number}, frames={len(lost_packet.frames)}")
            
            # Retransmit frames from lost packet
            for frame in lost_packet.frames:
                self._retransmit_frame(space, frame)
    
    def _retransmit_frame(self, space: PacketNumberSpace, frame: Dict[str, Any]):
        """Retransmit a specific frame."""
        frame_type = frame.get("type")
        
        if frame_type == "CRYPTO":
            # Retransmit CRYPTO data
            if space == PacketNumberSpace.INITIAL:
                self._retransmit_initial_crypto()
            elif space == PacketNumberSpace.HANDSHAKE:
                self._retransmit_handshake_crypto()
        
        elif frame_type == "STREAM":
            # Retransmit STREAM data
            stream_id = frame.get("stream_id")
            offset = frame.get("offset", 0)
            data = frame.get("data", b"")
            fin = frame.get("fin", False)
            
            if data and self.application_secrets:
                self._retransmit_stream_data(stream_id, offset, data, fin)
        
        elif frame_type == "PING":
            # PING doesn't need retransmission, just send new probe
            pass
    
    def _retransmit_stream_data(self, stream_id: int, offset: int, data: bytes, fin: bool):
        """Retransmit STREAM frame data."""
        if not self.application_secrets:
            return
        
        if self.debug:
            print(f"    🔄 Retransmitting STREAM data: stream={stream_id}, offset={offset}, len={len(data)}")
        
        dcid = self.server_scid if self.server_scid else self.original_dcid
        
        # Build STREAM frame
        stream_frame = build_stream_frame(
            stream_id=stream_id,
            data=data,
            offset=offset,
            fin=fin
        )
        
        # Build and send 1-RTT packet
        packet = self._build_short_header_packet(dcid, self.client_app_pn, stream_frame)
        
        # Track the sent packet
        self._track_sent_packet(
            PacketNumberSpace.APPLICATION,
            self.client_app_pn,
            len(packet),
            frames=[{"type": "STREAM", "stream_id": stream_id, "offset": offset, "data": data, "fin": fin}]
        )
        
        self.send(packet)
        self.client_app_pn += 1
    
    def _on_pto_timeout(self, space: PacketNumberSpace):
        """Callback when PTO timeout fires."""
        self._handle_pto_timeout(space)
    
    def _process_ack_for_loss_detection(self, space: PacketNumberSpace, 
                                         largest_ack: int, first_ack_range: int,
                                         ack_delay: int = 0):
        """Process ACK frame for loss detection."""
        # Build ACK ranges from largest_ack and first_ack_range
        # For simplicity, assume contiguous range from (largest_ack - first_ack_range) to largest_ack
        ack_start = largest_ack - first_ack_range
        ack_ranges = [(ack_start, largest_ack)]
        
        # Convert ack_delay from encoded value to seconds
        # ack_delay_exponent default is 3, so delay_us = ack_delay << 3
        ack_delay_us = ack_delay << 3
        ack_delay_seconds = ack_delay_us / 1_000_000
        
        # Process the ACK
        newly_acked = self.loss_detector.on_ack_received(space, ack_ranges, ack_delay_seconds)
        
        if self.debug and newly_acked:
            print(f"      ✓ Acknowledged {len(newly_acked)} packet(s) in {space.value} space")
        
        # Check if Client Finished was ACKed (Handshake confirmation for client)
        # RFC 9001 Section 4.9.2: Client confirms handshake when Finished is ACKed
        if space == PacketNumberSpace.HANDSHAKE and not self._handshake_confirmed:
            # Check if our Client Finished packet was acknowledged
            for acked_pkt in newly_acked:
                for frame in acked_pkt.frames:
                    if frame.get("type") == "CRYPTO" and self.client_finished_sent:
                        # Client Finished was acknowledged, handshake is confirmed
                        if self.debug:
                            print(f"    ✅ Client Finished acknowledged - handshake confirmed!")
                        self._discard_handshake_keys()
                        break
    
    def send_connection_close(self, error_code: int = 0, reason: str = "", 
                               is_application: bool = True):
        """
        Send CONNECTION_CLOSE frame to gracefully close the connection.
        
        Args:
            error_code: Error code (0 = NO_ERROR for graceful close)
            reason: Human-readable reason phrase (optional)
            is_application: If True, use application-level close (0x1d)
        """
        if not self.application_secrets:
            if self.debug:
                print(f"    ⚠️ Cannot send CONNECTION_CLOSE: no application secrets")
            return
        
        # Build CONNECTION_CLOSE frame
        close_frame = build_connection_close_frame(
            error_code=error_code,
            frame_type=None,
            reason=reason,
            is_application=is_application
        )
        
        dcid = self.server_scid if self.server_scid else self.original_dcid
        
        # Build and send the 1-RTT packet with CONNECTION_CLOSE
        packet = self._build_short_header_packet(dcid, self.client_app_pn, close_frame)
        pn = self.client_app_pn
        self.client_app_pn += 1
        
        self.send(packet)
        
        if self.debug:
            close_type = "Application" if is_application else "QUIC"
            print(f"    → Sent CONNECTION_CLOSE ({close_type} layer)")
            print(f"      Error code: 0x{error_code:04x}")
            if reason:
                print(f"      Reason: {reason}")
            print(f"      PN: {pn}, Packet size: {len(packet)} bytes")
        
        # Mark connection as closed
        self.connection_closed.set()
    
    def _derive_initial_keys(self):
        """Derive Initial encryption keys."""
        self.client_initial_secrets = derive_initial_secrets(self.original_dcid)
        self.server_initial_secrets = derive_server_initial_secrets(self.original_dcid)
        if self.debug:
            print(f"    ✓ Initial keys derived")
    
    def _derive_handshake_keys(self, server_public_key: bytes, server_hello_data: bytes):
        """Derive Handshake encryption keys from ECDH."""
        self.server_hello_data = server_hello_data
        
        shared_secret = perform_ecdh(self.private_key, server_public_key)
        transcript = self.client_hello + server_hello_data
        transcript_hash = hashlib.sha256(transcript).digest()
        
        # Use PSK-aware key derivation if we're doing 0-RTT
        if self.zero_rtt_enabled and self.zero_rtt_psk:
            hs_secrets = derive_handshake_secrets_with_psk(
                shared_secret, transcript_hash, 
                psk=self.zero_rtt_psk, debug=self.debug
            )
        else:
            hs_secrets = derive_handshake_secrets(shared_secret, transcript_hash, debug=self.debug)
        
        self.handshake_secrets = hs_secrets
        
        if self.debug:
            print(f"    ✓ Handshake keys derived")
            print(f"      ECDH shared secret: {shared_secret.hex()[:32]}...")
            if self.zero_rtt_enabled:
                print(f"      (with PSK for 0-RTT)")
        
        # Write keys to keylog file
        if self.client_random and self.keylog_file:
            lines = write_keylog(
                self.keylog_file, self.client_random,
                client_hs_secret=hs_secrets["client"]["traffic_secret"],
                server_hs_secret=hs_secrets["server"]["traffic_secret"]
            )
            if self.debug:
                print(f"    📝 Keys written to {self.keylog_file}:")
                for line in lines:
                    print(f"       {line}")
    
    def _send_initial_ack(self):
        """Send ACK for Initial packets."""
        if self.initial_tracker.largest_pn < 0:
            return
        
        ack_ranges = self.initial_tracker.get_ack_ranges()
        ack_frame = build_ack_frame(
            largest_ack=self.initial_tracker.largest_pn,
            ack_delay=self.initial_tracker.get_ack_delay(),
            first_ack_range=self.initial_tracker.get_first_ack_range(),
            ack_ranges=ack_ranges
        )
        
        dcid = self.server_scid if self.server_scid else self.original_dcid
        
        packet = build_initial_packet_with_secrets(
            self.client_initial_secrets,
            dcid,
            self.our_scid,
            self.client_initial_pn,
            ack_frame
        )
        
        self.send(packet)
        self.client_initial_pn += 1
        
        if self.debug:
            print(f"    → Sent Initial ACK (largest={self.initial_tracker.largest_pn})")
    
    def _send_handshake_ack(self):
        """Send ACK for Handshake packets."""
        if self.handshake_tracker.largest_pn < 0:
            return
        
        if not self.handshake_secrets:
            return
        
        ack_ranges = self.handshake_tracker.get_ack_ranges()
        ack_frame = build_ack_frame(
            largest_ack=self.handshake_tracker.largest_pn,
            ack_delay=self.handshake_tracker.get_ack_delay(),
            first_ack_range=self.handshake_tracker.get_first_ack_range(),
            ack_ranges=ack_ranges
        )
        
        dcid = self.server_scid if self.server_scid else self.original_dcid
        
        packet = build_handshake_packet(
            self.handshake_secrets["client"],
            dcid,
            self.our_scid, 
            self.client_handshake_pn,
            ack_frame
        )
        
        self.send(packet)
        self.client_handshake_pn += 1
        
        if self.debug:
            print(f"    → Sent Handshake ACK (largest={self.handshake_tracker.largest_pn})")
    
    def _send_client_finished(self):
        """Send Client Finished message after receiving Server Finished."""
        if self.client_finished_sent:
            return
        
        if not self.handshake_secrets:
            if self.debug:
                print(f"    ⚠️ Cannot send Client Finished: no handshake secrets")
            return
        
        if not self.server_hello_data:
            if self.debug:
                print(f"    ⚠️ Cannot send Client Finished: no ServerHello data")
            return
        
        # Build full transcript for client Finished
        handshake_crypto_data = self.handshake_crypto_buffer.get_contiguous_data()
        
        transcript = self.client_hello + self.server_hello_data + handshake_crypto_data
        transcript_hash = hashlib.sha256(transcript).digest()
        
        if self.debug:
            print(f"    📝 Transcript hash for Client Finished: {transcript_hash.hex()[:32]}...")
        
        # Build Client Finished TLS message
        client_hs_traffic_secret = self.handshake_secrets["client"]["traffic_secret"]
        finished_msg = build_client_finished_message(client_hs_traffic_secret, transcript_hash)
        self.client_finished_message = finished_msg
        
        if self.debug:
            print(f"    📝 Client Finished message: {len(finished_msg)} bytes")
        
        # Derive Application (1-RTT) secrets
        if self.debug:
            print(f"    📝 Deriving Application (1-RTT) secrets...")
        
        self.application_secrets = derive_application_secrets(
            self.handshake_secrets["handshake_secret"],
            transcript_hash,
            debug=self.debug
        )
        
        # Compute transcript hash including Client Finished for resumption master secret
        transcript_with_client_finished = transcript + finished_msg
        transcript_hash_with_cf = hashlib.sha256(transcript_with_client_finished).digest()
        
        # Derive Resumption Master Secret for session tickets
        self.resumption_master_secret = derive_resumption_master_secret(
            self.application_secrets["master_secret"],
            transcript_hash_with_cf,
            debug=self.debug
        )
        
        if self.debug:
            print(f"    📝 Resumption Master Secret derived for session resumption")
        
        # Write application traffic secrets to keylog file
        if self.client_random and self.keylog_file:
            lines = write_keylog(
                self.keylog_file, self.client_random,
                client_traffic_secret=self.application_secrets["client"]["traffic_secret"],
                server_traffic_secret=self.application_secrets["server"]["traffic_secret"]
            )
            if self.debug:
                print(f"    📝 Application keys written to {self.keylog_file}:")
                for line in lines:
                    print(f"       {line}")
        
        # Build CRYPTO frame containing the Finished message
        crypto_frame = build_crypto_frame(0, finished_msg)
        
        # Include ACK for handshake packets
        frames = crypto_frame
        if self.handshake_tracker.largest_pn >= 0:
            hs_ack_ranges = self.handshake_tracker.get_ack_ranges()
            ack_frame = build_ack_frame(
                largest_ack=self.handshake_tracker.largest_pn,
                ack_delay=self.handshake_tracker.get_ack_delay(),
                first_ack_range=self.handshake_tracker.get_first_ack_range(),
                ack_ranges=hs_ack_ranges
            )
            frames = ack_frame + crypto_frame
        
        dcid = self.server_scid if self.server_scid else self.original_dcid
        
        # Build Handshake packet with Client Finished
        handshake_packet = build_handshake_packet(
            self.handshake_secrets["client"],
            dcid,
            self.our_scid,
            self.client_handshake_pn,
            frames
        )
        handshake_pn = self.client_handshake_pn
        
        # Track the sent Handshake packet for loss detection
        self._track_sent_packet(
            PacketNumberSpace.HANDSHAKE,
            handshake_pn,
            len(handshake_packet),
            frames=[{"type": "CRYPTO", "offset": 0, "data": finished_msg}]
        )
        
        self.client_handshake_pn += 1
        self.client_finished_sent = True
        
        # Build 1-RTT packet with HTTP/3 initialization
        h3_init_packet, h3_init_frames = self._build_h3_init_packet_with_frames()
        h3_init_pn = self.client_app_pn - 1 if h3_init_packet else None
        
        # Track the H3 init packet for loss detection (APPLICATION space)
        if h3_init_packet:
            self._track_sent_packet(
                PacketNumberSpace.APPLICATION,
                h3_init_pn,
                len(h3_init_packet),
                frames=h3_init_frames
            )
        
        # Combine packets into single UDP datagram
        combined_datagram = handshake_packet + h3_init_packet
        
        self.send(combined_datagram)
        
        if self.debug:
            print(f"    → Sent Client Finished (Handshake PN={handshake_pn})")
            if h3_init_packet:
                print(f"    → Sent HTTP/3 init (1-RTT PN={h3_init_pn}, {len(h3_init_packet)} bytes)")
    
    def _build_h3_init_packet_with_frames(self) -> tuple:
        """
        Build 1-RTT packet containing HTTP/3 initialization streams.
        
        Returns:
            tuple: (packet_bytes, frame_list) for loss detection tracking
        """
        if self.h3_init_sent:
            return b"", []
        
        if not self.application_secrets:
            return b"", []
        
        dcid = self.server_scid if self.server_scid else self.original_dcid
        
        # Build all frames for the 1-RTT packet
        frames = b""
        frame_info_list = []  # For loss detection
        
        # 1. NEW_CONNECTION_ID frame
        alt_cid = os.urandom(8)
        stateless_reset_token = os.urandom(16)
        self.alt_connection_ids.append((1, alt_cid, stateless_reset_token))
        
        new_cid_frame = build_new_connection_id_frame(
            sequence=1,
            retire_prior_to=0,
            connection_id=alt_cid,
            stateless_reset_token=stateless_reset_token
        )
        frames += new_cid_frame
        # NEW_CONNECTION_ID doesn't need retransmission as is (can send new one)
        
        # 2. STREAM frame for HTTP/3 Control stream (id=2)
        control_stream_data = build_h3_control_stream_data(
            self.h3_settings,
            self.h3_max_push_id
        )
        control_stream_frame = build_stream_frame(
            stream_id=self.h3_local_control_stream_id,
            data=control_stream_data,
            offset=0,
            fin=False
        )
        frames += control_stream_frame
        frame_info_list.append({
            "type": "STREAM",
            "stream_id": self.h3_local_control_stream_id,
            "offset": 0,
            "data": control_stream_data,
            "fin": False
        })
        
        # 3. STREAM frame for QPACK Encoder stream (id=6)
        # Note: Don't send Set Dynamic Table Capacity here - we haven't received
        # server's SETTINGS yet. Just send the stream type byte.
        encoder_stream_data = build_h3_qpack_encoder_stream_data()
        encoder_stream_frame = build_stream_frame(
            stream_id=self.h3_local_encoder_stream_id,
            data=encoder_stream_data,
            offset=0,
            fin=False
        )
        frames += encoder_stream_frame
        frame_info_list.append({
            "type": "STREAM",
            "stream_id": self.h3_local_encoder_stream_id,
            "offset": 0,
            "data": encoder_stream_data,
            "fin": False
        })
        
        # 4. STREAM frame for QPACK Decoder stream (id=10)
        decoder_stream_data = build_h3_qpack_decoder_stream_data()
        decoder_stream_frame = build_stream_frame(
            stream_id=self.h3_local_decoder_stream_id,
            data=decoder_stream_data,
            offset=self.h3_local_decoder_stream_offset,
            fin=False
        )
        frames += decoder_stream_frame
        self.h3_local_decoder_stream_offset += len(decoder_stream_data)
        frame_info_list.append({
            "type": "STREAM",
            "stream_id": self.h3_local_decoder_stream_id,
            "offset": 0,
            "data": decoder_stream_data,
            "fin": False
        })
        
        # Build the 1-RTT (Short Header) packet
        packet = self._build_short_header_packet(dcid, self.client_app_pn, frames)
        self.client_app_pn += 1
        self.h3_init_sent = True
        
        if self.debug:
            print(f"    📋 H3 init content:")
            print(f"       - NEW_CONNECTION_ID: seq=1, cid={alt_cid.hex()}")
            print(f"       - Control Stream (id=2): {len(control_stream_data)} bytes")
            print(f"         SETTINGS: {self.h3_settings}")
            print(f"         MAX_PUSH_ID: {self.h3_max_push_id}")
            print(f"       - QPACK Encoder Stream (id=6): {len(encoder_stream_data)} bytes")
            print(f"       - QPACK Decoder Stream (id=10): {len(decoder_stream_data)} bytes")
        
        return packet, frame_info_list
    
    def _build_h3_init_packet(self) -> bytes:
        """Build 1-RTT packet containing HTTP/3 initialization streams."""
        packet, _ = self._build_h3_init_packet_with_frames()
        return packet
    
    def _send_combined_acks(self, need_initial_ack: bool, need_handshake_ack: bool):
        """Send combined ACKs after processing a UDP datagram."""
        if not need_initial_ack and not need_handshake_ack:
            return
        
        dcid = self.server_scid if self.server_scid else self.original_dcid
        min_datagram_size = 1200
        
        # Build Handshake ACK
        handshake_packet = b""
        handshake_pn_used = None
        if need_handshake_ack and self.handshake_tracker.largest_pn >= 0 and self.handshake_secrets:
            hs_ack_ranges = self.handshake_tracker.get_ack_ranges()
            ack_frame = build_ack_frame(
                largest_ack=self.handshake_tracker.largest_pn,
                ack_delay=self.handshake_tracker.get_ack_delay(),
                first_ack_range=self.handshake_tracker.get_first_ack_range(),
                ack_ranges=hs_ack_ranges
            )
            handshake_pn_used = self.client_handshake_pn
            handshake_packet = build_handshake_packet(
                self.handshake_secrets["client"],
                dcid,
                self.our_scid,
                self.client_handshake_pn,
                ack_frame
            )
            self.client_handshake_pn += 1
        
        # Build Initial ACK with padding
        initial_packet = b""
        initial_pn_used = None
        if need_initial_ack and self.initial_tracker.largest_pn >= 0:
            init_ack_ranges = self.initial_tracker.get_ack_ranges()
            ack_delay = self.initial_tracker.get_ack_delay()
            ack_frame = build_ack_frame(
                largest_ack=self.initial_tracker.largest_pn,
                ack_delay=ack_delay,
                first_ack_range=self.initial_tracker.get_first_ack_range(),
                ack_ranges=init_ack_ranges
            )
            
            initial_pn_used = self.client_initial_pn
            initial_packet_base = build_initial_packet_with_secrets(
                self.client_initial_secrets,
                dcid,
                self.our_scid,
                self.client_initial_pn,
                ack_frame
            )
            
            # Calculate padding needed
            current_total = len(initial_packet_base) + len(handshake_packet)
            if current_total < min_datagram_size:
                padding_needed = min_datagram_size - current_total
                ack_frame_with_padding = build_ack_frame(
                    largest_ack=self.initial_tracker.largest_pn,
                    ack_delay=ack_delay,
                    first_ack_range=self.initial_tracker.get_first_ack_range(),
                    ack_ranges=init_ack_ranges
                )
                ack_frame_with_padding += build_padding_frame(padding_needed)
                initial_packet = build_initial_packet_with_secrets(
                    self.client_initial_secrets,
                    dcid,
                    self.our_scid,
                    self.client_initial_pn,
                    ack_frame_with_padding
                )
            else:
                initial_packet = initial_packet_base
            
            self.client_initial_pn += 1
        
        # Combine packets
        combined_packet = initial_packet + handshake_packet
        
        if len(combined_packet) == 0:
            return
        
        self.send(combined_packet)
        
        if self.debug:
            msgs = []
            if initial_pn_used is not None:
                msgs.append(f"Initial ACK(PN={initial_pn_used}, largest={self.initial_tracker.largest_pn})")
            if handshake_pn_used is not None:
                msgs.append(f"Handshake ACK(PN={handshake_pn_used}, largest={self.handshake_tracker.largest_pn})")
            print(f"    → Sent combined ACK: {' + '.join(msgs)} ({len(combined_packet)} bytes)")
    
    def _process_initial_packet(self, packet: bytes, recv_time: float = None) -> bool:
        """Process a received Initial packet."""
        header_info = parse_long_header(packet)
        if not header_info["success"]:
            return False
        
        # Extract server's SCID
        if self.server_scid is None:
            self.server_scid = header_info["scid_bytes"]
            if self.debug:
                print(f"    📝 Server SCID: {self.server_scid.hex()}")
        
        try:
            header, truncated_pn, pn_len = remove_header_protection(
                self.server_initial_secrets, packet, header_info["pn_offset"]
            )
            
            # Reconstruct full packet number (RFC 9000 Appendix A.3)
            # Note: header keeps truncated PN bytes for AEAD, full PN used for nonce
            pn = decode_packet_number(
                self.initial_tracker.largest_pn,
                truncated_pn,
                pn_len * 8
            )
            
            # Check for duplicate
            if pn in self.initial_tracker.received_pns:
                if self.debug:
                    print(f"    ⚠️ Duplicate Initial packet PN={pn}, ignoring")
                return True
            
            # Decrypt payload
            encrypted_payload = packet[header_info["pn_offset"] + pn_len:header_info["pn_offset"] + header_info["length"]]
            plaintext = decrypt_payload(self.server_initial_secrets, pn, header, encrypted_payload)
            
            if plaintext is None:
                if self.debug:
                    print(f"    ❌ Initial decryption failed PN={pn}")
                return False
            
            if self.debug:
                print(f"    ✓ Initial decrypted PN={pn}, {len(plaintext)} bytes")
            
            # Parse frames
            frames = parse_quic_frames(plaintext, False)
            ack_eliciting = self._process_frames(frames, "Initial")
            
            if ack_eliciting:
                self.initial_tracker.record(pn, recv_time)
            
            return True
            
        except Exception as e:
            if self.debug:
                print(f"    ❌ Initial processing exception: {e}")
            return False
    
    def _process_handshake_packet(self, packet: bytes, recv_time: float = None) -> bool:
        """Process a received Handshake packet."""
        if not self.handshake_secrets:
            if self.debug:
                print(f"    ⏳ Waiting for Handshake keys...")
            return False
        
        header_info = parse_long_header(packet)
        if not header_info["success"]:
            return False
        
        try:
            header, truncated_pn, pn_len = remove_header_protection(
                self.handshake_secrets["server"], packet, header_info["pn_offset"]
            )
            
            # Reconstruct full packet number (RFC 9000 Appendix A.3)
            # Note: header keeps truncated PN bytes for AEAD, full PN used for nonce
            pn = decode_packet_number(
                self.handshake_tracker.largest_pn,
                truncated_pn,
                pn_len * 8
            )
            
            # Check for duplicate
            if pn in self.handshake_tracker.received_pns:
                if self.debug:
                    print(f"    ⚠️ Duplicate Handshake packet PN={pn}, ignoring")
                return True
            
            # Decrypt payload
            encrypted_payload = packet[header_info["pn_offset"] + pn_len:header_info["pn_offset"] + header_info["length"]]
            plaintext = decrypt_payload(self.handshake_secrets["server"], pn, header, encrypted_payload)
            
            if plaintext is None:
                if self.debug:
                    print(f"    ❌ Handshake decryption failed PN={pn}")
                return False
            
            if self.debug:
                print(f"    ✓ Handshake decrypted PN={pn}, {len(plaintext)} bytes")
            
            # Parse frames
            frames = parse_quic_frames(plaintext, False)
            ack_eliciting = self._process_frames(frames, "Handshake")
            
            if ack_eliciting:
                self.handshake_tracker.record(pn, recv_time)
            
            return True
            
        except Exception as e:
            if self.debug:
                print(f"    ❌ Handshake processing exception: {e}")
            return False
    
    def _process_frames(self, frames: list, level: str) -> bool:
        """Process QUIC frames from a decrypted packet."""
        ack_eliciting = False
        for frame in frames:
            if frame["type"] == "CRYPTO":
                ack_eliciting = True
                self._process_crypto_frame(frame, level)
            elif frame["type"] == "ACK":
                if self.debug:
                    print(f"      ← ACK largest={frame['largest_ack']}, first_range={frame.get('first_ack_range', 0)}")
                
                # Process ACK for loss detection
                space = PacketNumberSpace.INITIAL if level == "Initial" else PacketNumberSpace.HANDSHAKE
                self._process_ack_for_loss_detection(
                    space,
                    frame['largest_ack'],
                    frame.get('first_ack_range', 0),
                    frame.get('ack_delay', 0)
                )
            elif frame["type"] == "PADDING":
                pass
            elif frame["type"] == "CONNECTION_CLOSE":
                error_code = frame.get('error_code', 'unknown')
                reason = frame.get('reason', '')
                # Map common QUIC error codes
                error_names = {
                    0x00: "NO_ERROR",
                    0x01: "INTERNAL_ERROR", 
                    0x02: "CONNECTION_REFUSED",
                    0x03: "FLOW_CONTROL_ERROR",
                    0x04: "STREAM_LIMIT_ERROR",
                    0x05: "STREAM_STATE_ERROR",
                    0x06: "FINAL_SIZE_ERROR",
                    0x07: "FRAME_ENCODING_ERROR",
                    0x08: "TRANSPORT_PARAMETER_ERROR",
                    0x09: "CONNECTION_ID_LIMIT_ERROR",
                    0x0a: "PROTOCOL_VIOLATION",
                    0x0b: "INVALID_TOKEN",
                    0x0c: "APPLICATION_ERROR",
                    0x0d: "CRYPTO_BUFFER_EXCEEDED",
                    0x0e: "KEY_UPDATE_ERROR",
                    0x0f: "AEAD_LIMIT_REACHED",
                    0x10: "NO_VIABLE_PATH",
                }
                # TLS alert codes (0x100 + TLS alert)
                tls_alerts = {
                    0x100 + 10: "TLS_UNEXPECTED_MESSAGE",
                    0x100 + 20: "TLS_BAD_RECORD_MAC",
                    0x100 + 40: "TLS_HANDSHAKE_FAILURE",
                    0x100 + 42: "TLS_BAD_CERTIFICATE",
                    0x100 + 43: "TLS_UNSUPPORTED_CERTIFICATE",
                    0x100 + 44: "TLS_CERTIFICATE_REVOKED",
                    0x100 + 45: "TLS_CERTIFICATE_EXPIRED",
                    0x100 + 46: "TLS_CERTIFICATE_UNKNOWN",
                    0x100 + 47: "TLS_ILLEGAL_PARAMETER",
                    0x100 + 48: "TLS_UNKNOWN_CA",
                    0x100 + 50: "TLS_DECODE_ERROR",
                    0x100 + 51: "TLS_DECRYPT_ERROR",
                    0x100 + 70: "TLS_PROTOCOL_VERSION",
                    0x100 + 71: "TLS_INSUFFICIENT_SECURITY",
                    0x100 + 80: "TLS_INTERNAL_ERROR",
                    0x100 + 86: "TLS_INAPPROPRIATE_FALLBACK",
                    0x100 + 109: "TLS_MISSING_EXTENSION",
                    0x100 + 110: "TLS_UNSUPPORTED_EXTENSION",
                    0x100 + 112: "TLS_UNRECOGNIZED_NAME",
                    0x100 + 120: "TLS_NO_APPLICATION_PROTOCOL",
                }
                error_names.update(tls_alerts)
                error_name = error_names.get(error_code, f"0x{error_code:02x}" if isinstance(error_code, int) else str(error_code))
                # Add helpful hint for common errors
                hint = ""
                if error_code == 0x128:  # TLS handshake_failure
                    hint = " (server may not support HTTP/3)"
                elif error_code == 0x178:  # TLS no_application_protocol
                    hint = " (server doesn't support h3 ALPN)"
                if self.debug:
                    print(f"      ❌ CONNECTION_CLOSE: {error_name} (code={error_code}){hint}")
                self.state = HandshakeState.FAILED
                self.connection_closed.set()
            else:
                ack_eliciting = True
        return ack_eliciting
    
    def _process_crypto_frame(self, frame: dict, level: str):
        """Process a CRYPTO frame."""
        offset = frame["offset"]
        data = frame["data"]
        
        if level == "Initial":
            is_new = self.initial_crypto_buffer.add_fragment(offset, data)
            if is_new:
                self._parse_initial_crypto()
        else:
            is_new = self.handshake_crypto_buffer.add_fragment(offset, data)
            if is_new:
                self._parse_handshake_crypto()
    
    def _parse_initial_crypto(self):
        """Parse Initial CRYPTO data (looking for ServerHello)."""
        data = self.initial_crypto_buffer.get_contiguous_data()
        if len(data) < 4:
            return
        
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
                        print(f"      📨 ServerHello received!")
                        print(f"         Cipher: {msg.get('cipher_suite', 'N/A')}")
                    
                    if "extensions" in msg:
                        for ext in msg["extensions"]:
                            if ext["name"] == "key_share" and "key_exchange_bytes" in ext:
                                server_public_key = ext["key_exchange_bytes"]
                                server_hello_data = data[offset:msg_end]
                                self._derive_handshake_keys(server_public_key, server_hello_data)
                                self.state = HandshakeState.HANDSHAKE
                            # Check for pre_shared_key extension (indicates PSK was selected)
                            elif ext["name"] == "pre_shared_key":
                                if self.zero_rtt_enabled:
                                    if self.debug:
                                        print(f"         ✓ Server selected PSK")
                                    # PSK selected means our resumption is working
                
                offset = msg_end
            
            self.initial_crypto_parsed_offset = len(data)
            
        except Exception as e:
            if self.debug:
                print(f"      ⚠️ Parse Initial CRYPTO failed: {e}")
    
    def _parse_handshake_crypto(self):
        """Parse Handshake CRYPTO data (looking for Finished)."""
        data = self.handshake_crypto_buffer.get_contiguous_data()
        total_received = self.handshake_crypto_buffer.total_received
        
        if self.debug:
            print(f"      📊 Handshake CRYPTO: contiguous={len(data)}, total_received={total_received}, parsed_offset={self.handshake_crypto_parsed_offset}")
        
        if len(data) < 4:
            return
        
        if len(data) <= self.handshake_crypto_parsed_offset:
            return
        
        try:
            messages = parse_tls_handshake(data, False)
            
            if self.debug:
                print(f"      📊 Parsed {len(messages)} TLS message(s)")
            
            offset = 0
            for msg in messages:
                msg_end = offset + 4 + msg["length"]
                
                if msg_end <= self.handshake_crypto_parsed_offset:
                    offset = msg_end
                    continue
                
                if self.debug and msg["type"] not in ["PADDING"]:
                    print(f"      📨 {msg['type']} ({msg['length']} bytes)")
                
                # Check for early_data acceptance in EncryptedExtensions
                if msg["type"] == "EncryptedExtensions" and self.zero_rtt_enabled:
                    extensions = msg.get("extensions", [])
                    for ext in extensions:
                        if ext.get("name") == "early_data":
                            self.zero_rtt_accepted = True
                            if self.debug:
                                print(f"         🎉 Server accepted 0-RTT early data!")
                            break
                    if not self.zero_rtt_accepted:
                        self.zero_rtt_rejected = True
                        if self.debug:
                            print(f"         ⚠️ Server did not accept 0-RTT (no early_data extension)")
                
                if msg["type"] == "Finished" and not self.finished_received:
                    self.finished_received = True
                    if self.debug:
                        print(f"      🎉 Server Finished received!")
                    
                    self.handshake_crypto_parsed_offset = len(data)
                    self._send_client_finished()
                    
                    self.state = HandshakeState.HANDSHAKE_COMPLETE
                    if self.debug:
                        print(f"      ✅ TLS 1.3 handshake complete!")
                    
                    # Clean up INITIAL space (RFC 9001 Section 4.9.1)
                    # Initial keys are discarded when handshake keys become available
                    self._discard_initial_keys()
                    
                    # Note: HANDSHAKE space is kept until Client Finished is ACKed
                    # This happens in _process_ack_for_loss_detection
                    
                    self.handshake_complete.set()
                    return
                
                offset = msg_end
            
            self.handshake_crypto_parsed_offset = len(data)
                    
        except Exception as e:
            if self.debug:
                import traceback
                print(f"      ❌ Parse Handshake CRYPTO failed: {e}")
                traceback.print_exc()
    
    def _process_1rtt_packet(self, packet: bytes, recv_time: float = None) -> bool:
        """Process a received 1-RTT (Short Header) packet."""
        if not self.application_secrets:
            if self.debug:
                print(f"      ⚠️ Cannot process 1-RTT packet: no application secrets")
            return False
        
        if len(packet) < 1:
            return False
        
        first_byte = packet[0]
        dcid_len = len(self.our_scid) if self.our_scid else 8
        if len(packet) < 1 + dcid_len:
            return False
        
        dcid = packet[1:1+dcid_len]
        pn_offset = 1 + dcid_len
        
        try:
            sample_offset = pn_offset + 4
            if sample_offset + 16 > len(packet):
                if self.debug:
                    print(f"      ❌ 1-RTT packet too short for sample")
                return False
            
            sample = packet[sample_offset:sample_offset + 16]
            hp_key = self.application_secrets["server"]["hp"]
            
            cipher = Cipher(algorithms.AES(hp_key), modes.ECB())
            encryptor = cipher.encryptor()
            mask = encryptor.update(sample) + encryptor.finalize()
            
            decrypted_first_byte = first_byte ^ (mask[0] & 0x1f)
            pn_length = (decrypted_first_byte & 0x03) + 1
            
            pn_bytes = bytearray(packet[pn_offset:pn_offset + pn_length])
            for i in range(pn_length):
                pn_bytes[i] ^= mask[1 + i]
            
            # Decode truncated PN from wire
            truncated_pn = 0
            for b in pn_bytes:
                truncated_pn = (truncated_pn << 8) | b
            
            # Reconstruct full packet number (RFC 9000 Appendix A.3)
            pn = decode_packet_number(
                self.app_tracker.largest_pn,
                truncated_pn,
                pn_length * 8
            )
            
            # Header uses truncated PN bytes from wire (for AEAD additional data)
            header = bytes([decrypted_first_byte]) + packet[1:pn_offset] + bytes(pn_bytes)
            
            if pn in self.app_tracker.received_pns:
                if self.debug:
                    print(f"      ⚠️ Duplicate 1-RTT packet PN={pn}, ignoring")
                return True
            
            encrypted_payload = packet[pn_offset + pn_length:]
            plaintext = decrypt_payload(self.application_secrets["server"], pn, header, encrypted_payload)
            
            if plaintext is None:
                if self.debug:
                    print(f"      ❌ 1-RTT decryption failed PN={pn}")
                return False
            
            if self.debug:
                print(f"      ✓ 1-RTT decrypted PN={pn}, payload {len(plaintext)} bytes")
            
            ack_eliciting = self._parse_1rtt_frames(plaintext)
            
            if ack_eliciting:
                self.app_tracker.record(pn, recv_time)
            
            return True
            
        except Exception as e:
            if self.debug:
                print(f"      ❌ 1-RTT processing exception: {e}")
            return False
    
    def _parse_1rtt_frames(self, payload: bytes) -> bool:
        """Parse frames from 1-RTT packet payload."""
        offset = 0
        ack_eliciting = False
        
        while offset < len(payload):
            frame_type, consumed = decode_varint(payload, offset)
            offset += consumed
            
            if frame_type == 0x00:  # PADDING
                continue
            elif frame_type == 0x01:  # PING
                ack_eliciting = True
                if self.debug:
                    print(f"        PING frame")
            elif frame_type == 0x02 or frame_type == 0x03:  # ACK
                largest_ack, consumed = decode_varint(payload, offset)
                offset += consumed
                ack_delay, consumed = decode_varint(payload, offset)
                offset += consumed
                ack_range_count, consumed = decode_varint(payload, offset)
                offset += consumed
                first_ack_range, consumed = decode_varint(payload, offset)
                offset += consumed
                
                for _ in range(ack_range_count):
                    gap, consumed = decode_varint(payload, offset)
                    offset += consumed
                    ack_range_len, consumed = decode_varint(payload, offset)
                    offset += consumed
                
                if frame_type == 0x03:
                    for _ in range(3):
                        _, consumed = decode_varint(payload, offset)
                        offset += consumed
                
                if self.debug:
                    print(f"        ACK frame: largest={largest_ack}, delay={ack_delay}µs, first_range={first_ack_range}")
                
                # Process ACK for loss detection
                self._process_ack_for_loss_detection(
                    PacketNumberSpace.APPLICATION,
                    largest_ack,
                    first_ack_range,
                    ack_delay
                )
            elif frame_type == 0x06:  # CRYPTO
                ack_eliciting = True
                crypto_offset, consumed = decode_varint(payload, offset)
                offset += consumed
                crypto_length, consumed = decode_varint(payload, offset)
                offset += consumed
                crypto_data = payload[offset:offset + crypto_length]
                offset += crypto_length
                if self.debug:
                    print(f"        CRYPTO frame: offset={crypto_offset}, length={crypto_length}")
                
                try:
                    tls_messages = parse_tls_handshake(crypto_data, self.debug)
                    for msg in tls_messages:
                        if msg.get("type") == "NewSessionTicket" and "session_ticket" in msg:
                            session_ticket = msg["session_ticket"]
                            session_ticket.server_name = self.hostname
                            session_ticket.alpn = "h3"
                            if self.resumption_master_secret:
                                session_ticket.resumption_master_secret = self.resumption_master_secret
                            self.session_tickets.append(session_ticket)
                            
                            # Save to session ticket store if configured
                            if self.session_ticket_store and self.resumption_master_secret:
                                self.session_ticket_store.add_ticket(session_ticket)
                                if self.debug:
                                    print(f"          💾 Session ticket saved to {self.session_file}")
                            
                            if self.debug:
                                print(f"          📋 NewSessionTicket received: lifetime={session_ticket.ticket_lifetime}s, "
                                      f"ticket_len={len(session_ticket.ticket)}, "
                                      f"max_early_data={session_ticket.max_early_data_size}")
                except Exception as e:
                    if self.debug:
                        print(f"          ⚠️ Parse TLS message failed: {e}")
            elif frame_type == 0x1c or frame_type == 0x1d:  # CONNECTION_CLOSE
                error_code, consumed = decode_varint(payload, offset)
                offset += consumed
                if frame_type == 0x1c:
                    frame_type_field, consumed = decode_varint(payload, offset)
                    offset += consumed
                reason_length, consumed = decode_varint(payload, offset)
                offset += consumed
                reason = payload[offset:offset + reason_length].decode('utf-8', errors='replace')
                offset += reason_length
                if self.debug:
                    print(f"        CONNECTION_CLOSE: error={error_code}, reason='{reason}'")
            elif frame_type == 0x18 or frame_type == 0x19:  # NEW_CONNECTION_ID
                ack_eliciting = True
                seq_num, consumed = decode_varint(payload, offset)
                offset += consumed
                retire_prior, consumed = decode_varint(payload, offset)
                offset += consumed
                cid_len = payload[offset]
                offset += 1
                cid = payload[offset:offset + cid_len]
                offset += cid_len
                stateless_reset = payload[offset:offset + 16]
                offset += 16
                if self.debug:
                    print(f"        NEW_CONNECTION_ID: seq={seq_num}, cid={cid.hex()[:16]}...")
            elif frame_type == 0x07:  # NEW_TOKEN
                ack_eliciting = True
                token_length, consumed = decode_varint(payload, offset)
                offset += consumed
                token = payload[offset:offset + token_length]
                offset += token_length
                if self.debug:
                    print(f"        NEW_TOKEN: {token_length} bytes")
            elif frame_type == 0x04:  # RESET_STREAM
                ack_eliciting = True
                stream_id, consumed = decode_varint(payload, offset)
                offset += consumed
                app_error, consumed = decode_varint(payload, offset)
                offset += consumed
                final_size, consumed = decode_varint(payload, offset)
                offset += consumed
                if self.debug:
                    print(f"        RESET_STREAM: stream={stream_id}, error={app_error}")
            elif frame_type == 0x10:  # MAX_DATA
                ack_eliciting = True
                max_data, consumed = decode_varint(payload, offset)
                offset += consumed
                if self.debug:
                    print(f"        MAX_DATA: {max_data}")
            elif frame_type == 0x11:  # MAX_STREAM_DATA
                ack_eliciting = True
                stream_id, consumed = decode_varint(payload, offset)
                offset += consumed
                max_stream_data, consumed = decode_varint(payload, offset)
                offset += consumed
                if self.debug:
                    print(f"        MAX_STREAM_DATA: stream={stream_id}, max={max_stream_data}")
            elif frame_type == 0x12:  # MAX_STREAMS (BIDI)
                ack_eliciting = True
                max_streams, consumed = decode_varint(payload, offset)
                offset += consumed
                if self.debug:
                    print(f"        MAX_STREAMS (BIDI): {max_streams}")
            elif frame_type == 0x13:  # MAX_STREAMS (UNI)
                ack_eliciting = True
                max_streams, consumed = decode_varint(payload, offset)
                offset += consumed
                if self.debug:
                    print(f"        MAX_STREAMS (UNI): {max_streams}")
            elif frame_type == 0x1e:  # HANDSHAKE_DONE
                ack_eliciting = True
                if self.debug:
                    print(f"        HANDSHAKE_DONE frame 🎉")
                # Discard HANDSHAKE keys when we receive HANDSHAKE_DONE
                if not self._handshake_confirmed:
                    self._discard_handshake_keys()
            elif frame_type >= 0x08 and frame_type <= 0x0f:  # STREAM
                ack_eliciting = True
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
                    stream_length, consumed = decode_varint(payload, offset)
                    offset += consumed
                    stream_data = payload[offset:offset + stream_length]
                    offset += stream_length
                else:
                    stream_data = payload[offset:]
                    offset = len(payload)
                
                if self.debug:
                    print(f"        STREAM frame: id={stream_id}, off={stream_offset}, len={len(stream_data)}, fin={has_fin}")
                    print(f"          {describe_stream_id(stream_id)}")
                
                try:
                    h3_results = self.h3_manager.process_stream_data(
                        stream_id, stream_offset, stream_data, has_fin, self.debug
                    )
                    for result in h3_results:
                        if result.get("type") == "stream_type":
                            if self.debug:
                                print(f"          🌐 H3 Stream Type: {result.get('stream_type_name')}")
                        elif result.get("frame_type") == "SETTINGS":
                            if self.debug:
                                print(f"          ⚙️ H3 SETTINGS: {result.get('settings')}")
                        elif result.get("type") == "response_complete":
                            # Response complete - trigger the waiting event
                            resp_stream_id = result.get("stream_id")
                            resp_headers = result.get("headers", [])
                            resp_body = result.get("body", b"")
                            
                            # Extract status from headers
                            status = None
                            for name, value in resp_headers:
                                if name == ":status":
                                    try:
                                        status = int(value)
                                    except:
                                        status = value
                                    break
                            
                            self.pending_responses[resp_stream_id] = {
                                "status": status,
                                "headers": resp_headers,
                                "body": resp_body,
                            }
                            
                            # Signal that response is ready
                            if resp_stream_id in self.response_events:
                                self.response_events[resp_stream_id].set()
                        elif result.get("type") == "qpack_table_updated":
                            if self.debug:
                                print(f"          📊 QPACK table updated: {result.get('new_entries')} new entries")
                    
                    # Send any pending QPACK decoder instructions
                    self._send_qpack_decoder_instructions()
                    
                    # Update flow control and send window updates if needed
                    self._update_flow_control(stream_id, len(stream_data))
                    
                except Exception as e:
                    if self.debug:
                        print(f"          ⚠️ H3 parsing error: {e}")
            elif frame_type == 0x14:  # DATA_BLOCKED
                ack_eliciting = True
                blocked_at, consumed = decode_varint(payload, offset)
                offset += consumed
                if self.debug:
                    print(f"        DATA_BLOCKED: limit={blocked_at}")
                # Peer is blocked - send MAX_DATA immediately
                self._send_max_data_update(force=True)
            elif frame_type == 0x15:  # STREAM_DATA_BLOCKED
                ack_eliciting = True
                blocked_stream_id, consumed = decode_varint(payload, offset)
                offset += consumed
                blocked_at, consumed = decode_varint(payload, offset)
                offset += consumed
                if self.debug:
                    print(f"        STREAM_DATA_BLOCKED: stream={blocked_stream_id}, limit={blocked_at}")
                # Peer is blocked on this stream - send MAX_STREAM_DATA immediately
                self._send_max_stream_data_update(blocked_stream_id, force=True)
            else:
                if self.debug:
                    print(f"        Unknown frame type: 0x{frame_type:02x}")
                ack_eliciting = True
                break
        
        return ack_eliciting
    
    def _send_qpack_decoder_instructions(self):
        """
        Send pending QPACK decoder instructions on the decoder stream.
        
        These include Section Acknowledgment and Insert Count Increment.
        """
        if not self.application_secrets:
            return
        
        instructions = self.h3_manager.get_pending_decoder_instructions()
        if not instructions:
            return
        
        dcid = self.server_scid if self.server_scid else self.original_dcid
        
        # Build STREAM frame for decoder stream
        stream_frame = build_stream_frame(
            stream_id=self.h3_local_decoder_stream_id,
            data=instructions,
            offset=self.h3_local_decoder_stream_offset,
            fin=False
        )
        self.h3_local_decoder_stream_offset += len(instructions)
        
        # Build and send 1-RTT packet
        packet = self._build_short_header_packet(dcid, self.client_app_pn, stream_frame)
        self.send(packet)
        self.client_app_pn += 1
        
        if self.debug:
            print(f"    → Sent QPACK decoder instructions ({len(instructions)} bytes)")
    
    def _update_flow_control(self, stream_id: int, data_len: int):
        """
        Update flow control counters and send window updates if needed.
        
        Args:
            stream_id: The stream that received data
            data_len: Number of bytes received
        """
        # Update connection-level counter
        self._fc_data_received += data_len
        
        # Update stream-level counter
        if stream_id not in self._fc_stream_received:
            self._fc_stream_received[stream_id] = 0
            self._fc_stream_max_sent[stream_id] = self._fc_initial_max_stream_data
        self._fc_stream_received[stream_id] += data_len
        
        # Check if we need to send MAX_DATA
        self._send_max_data_update()
        
        # Check if we need to send MAX_STREAM_DATA
        self._send_max_stream_data_update(stream_id)
    
    def _send_max_data_update(self, force: bool = False):
        """
        Send MAX_DATA frame if the peer has consumed enough of the window.
        
        Args:
            force: If True, send update immediately regardless of threshold
        """
        if not self.application_secrets:
            return
        
        # Calculate how much of the window has been consumed
        consumed = self._fc_data_received
        current_limit = self._fc_max_data_sent
        
        # Send update when consumed > threshold * current_limit
        threshold_reached = consumed > (self._fc_window_update_threshold * current_limit)
        
        if force or threshold_reached:
            # Double the window or add initial window size
            new_limit = max(
                current_limit + self._fc_initial_max_data,
                consumed + self._fc_initial_max_data
            )
            
            if new_limit > self._fc_max_data_sent:
                self._fc_max_data_sent = new_limit
                
                # Build and send MAX_DATA frame
                max_data_frame = build_max_data_frame(new_limit)
                dcid = self.server_scid if self.server_scid else self.original_dcid
                packet = self._build_short_header_packet(dcid, self.client_app_pn, max_data_frame)
                self.send(packet)
                self.client_app_pn += 1
                
                if self.debug:
                    print(f"    → Sent MAX_DATA: {new_limit} (received={consumed})")
    
    def _send_max_stream_data_update(self, stream_id: int, force: bool = False):
        """
        Send MAX_STREAM_DATA frame if the peer has consumed enough of the stream window.
        
        Args:
            stream_id: The stream to update
            force: If True, send update immediately regardless of threshold
        """
        if not self.application_secrets:
            return
        
        # Initialize if needed
        if stream_id not in self._fc_stream_received:
            self._fc_stream_received[stream_id] = 0
            self._fc_stream_max_sent[stream_id] = self._fc_initial_max_stream_data
        
        # Calculate how much of the window has been consumed
        consumed = self._fc_stream_received[stream_id]
        current_limit = self._fc_stream_max_sent[stream_id]
        
        # Send update when consumed > threshold * current_limit
        threshold_reached = consumed > (self._fc_window_update_threshold * current_limit)
        
        if force or threshold_reached:
            # Increase window
            new_limit = max(
                current_limit + self._fc_initial_max_stream_data,
                consumed + self._fc_initial_max_stream_data
            )
            
            if new_limit > self._fc_stream_max_sent[stream_id]:
                self._fc_stream_max_sent[stream_id] = new_limit
                
                # Build and send MAX_STREAM_DATA frame
                max_stream_data_frame = build_max_stream_data_frame(stream_id, new_limit)
                dcid = self.server_scid if self.server_scid else self.original_dcid
                packet = self._build_short_header_packet(dcid, self.client_app_pn, max_stream_data_frame)
                self.send(packet)
                self.client_app_pn += 1
                
                if self.debug:
                    print(f"    → Sent MAX_STREAM_DATA: stream={stream_id}, limit={new_limit} (received={consumed})")
    
    def _send_1rtt_ack(self):
        """Send ACK for 1-RTT packets using Short Header."""
        if self.app_tracker.largest_pn < 0:
            return
        
        if not self.application_secrets:
            return
        
        ack_ranges = self.app_tracker.get_ack_ranges()
        ack_frame = build_ack_frame(
            largest_ack=self.app_tracker.largest_pn,
            ack_delay=self.app_tracker.get_ack_delay(),
            first_ack_range=self.app_tracker.get_first_ack_range(),
            ack_ranges=ack_ranges
        )
        
        dcid = self.server_scid if self.server_scid else self.original_dcid
        
        packet = self._build_short_header_packet(dcid, self.client_app_pn, ack_frame)
        
        self.send(packet)
        self.client_app_pn += 1
        
        if self.debug:
            print(f"    → Sent 1-RTT ACK (PN={self.client_app_pn - 1}, largest={self.app_tracker.largest_pn})")
    
    def _build_short_header_packet(self, dcid: bytes, pn: int, payload: bytes) -> bytes:
        """Build a Short Header (1-RTT) packet."""
        # Determine packet number length
        if pn < 0x100:
            pn_len = 1
            pn_bytes = bytes([pn])
        elif pn < 0x10000:
            pn_len = 2
            pn_bytes = struct.pack(">H", pn)
        elif pn < 0x1000000:
            pn_len = 3
            pn_bytes = struct.pack(">I", pn)[1:]
        else:
            pn_len = 4
            pn_bytes = struct.pack(">I", pn)
        
        # Short header first byte
        first_byte = 0x40 | (pn_len - 1)
        
        # Build header (unprotected)
        header = bytes([first_byte]) + dcid + pn_bytes
        
        # Encrypt payload with AEAD
        key = self.application_secrets["client"]["key"]
        iv = self.application_secrets["client"]["iv"]
        hp_key = self.application_secrets["client"]["hp"]
        
        # Ensure payload is large enough for header protection sample
        # The sample needs 4 + 16 = 20 bytes after encryption (including auth tag)
        # Payload must be at least 4 bytes to ensure ciphertext >= 20 bytes (4 + 16 tag)
        # Since sample_offset = 4 - pn_len, we need ciphertext >= sample_offset + 16
        min_payload_len = 4  # Add padding if payload is too small
        if len(payload) < min_payload_len:
            # Add PADDING frames (0x00) to ensure enough bytes for header protection
            padding_needed = min_payload_len - len(payload)
            payload = payload + (b'\x00' * padding_needed)
        
        # Build nonce
        nonce = bytearray(iv)
        pn_bytes_padded = pn.to_bytes(len(iv), 'big')
        for i in range(len(nonce)):
            nonce[i] ^= pn_bytes_padded[i]
        
        # Encrypt
        cipher = AESGCM(key)
        ciphertext = cipher.encrypt(bytes(nonce), payload, header)
        
        # Apply header protection
        sample_offset = 4 - pn_len
        if sample_offset < 0:
            sample_offset = 0
        sample = ciphertext[sample_offset:sample_offset + 16]
        
        hp_cipher = Cipher(algorithms.AES(hp_key), modes.ECB())
        encryptor = hp_cipher.encryptor()
        mask = encryptor.update(sample) + encryptor.finalize()
        
        protected_first_byte = first_byte ^ (mask[0] & 0x1f)
        
        protected_pn = bytearray(pn_bytes)
        for i in range(pn_len):
            protected_pn[i] ^= mask[1 + i]
        
        protected_header = bytes([protected_first_byte]) + dcid + bytes(protected_pn)
        return protected_header + ciphertext
    
    def send_request(self, method: str = "GET", path: str = "/", 
                     headers: dict = None, body: bytes = None) -> int:
        """
        Send an HTTP/3 request.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path
            headers: Additional headers dict
            body: Request body (for POST, PUT, etc.)
            
        Returns:
            int: Stream ID used for this request
        """
        if not self.application_secrets:
            raise RuntimeError("Cannot send request: handshake not complete")
        
        # Allocate stream ID (client-initiated bidirectional: 0, 4, 8, ...)
        stream_id = self.next_request_stream_id
        self.next_request_stream_id += 4
        
        # Build request headers
        extra_headers = headers or {}
        if "user-agent" not in extra_headers:
            extra_headers["user-agent"] = "http3-client/1.0"
        
        # Build QPACK encoded headers
        qpack_headers = build_qpack_request_headers(
            method=method,
            scheme="https",
            authority=self.hostname,
            path=path,
            extra_headers=extra_headers
        )
        
        # Build HTTP/3 HEADERS frame
        headers_frame = build_h3_headers_frame(qpack_headers)
        
        # Build stream data
        stream_data = headers_frame
        if body:
            data_frame = build_h3_data_frame(body)
            stream_data += data_frame
        
        # Determine if this is the final frame
        has_body = body is not None and len(body) > 0
        fin = True  # For simple requests, we send everything in one shot
        
        # Build STREAM frame
        stream_frame = build_stream_frame(
            stream_id=stream_id,
            data=stream_data,
            offset=0,
            fin=fin
        )
        
        dcid = self.server_scid if self.server_scid else self.original_dcid
        
        # Build and send the 1-RTT packet
        packet = self._build_short_header_packet(dcid, self.client_app_pn, stream_frame)
        pn = self.client_app_pn
        self.client_app_pn += 1
        
        # Track the sent packet for loss detection
        self._track_sent_packet(
            PacketNumberSpace.APPLICATION,
            pn,
            len(packet),
            frames=[{
                "type": "STREAM",
                "stream_id": stream_id,
                "offset": 0,
                "data": stream_data,
                "fin": fin
            }]
        )
        
        self.send(packet)
        
        # Create event for waiting on response
        self.response_events[stream_id] = asyncio.Event()
        
        if self.debug:
            print(f"    → Sent HTTP/3 {method} request to {path}")
            print(f"      Stream ID: {stream_id}, PN: {pn}")
            print(f"      HEADERS frame: {len(headers_frame)} bytes")
            if body:
                print(f"      DATA frame: {len(body)} bytes")
            print(f"      Total packet: {len(packet)} bytes")
        
        return stream_id
    
    async def request(self, method: str = "GET", path: str = "/",
                      headers: dict = None, body: bytes = None,
                      timeout: float = 10.0) -> dict:
        """
        Send an HTTP/3 request and wait for the response.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path  
            headers: Additional headers dict
            body: Request body (for POST, PUT, etc.)
            timeout: Response timeout in seconds
            
        Returns:
            dict: Response with 'status', 'headers', and 'body'
        """
        stream_id = self.send_request(method, path, headers, body)
        
        try:
            await asyncio.wait_for(
                self.response_events[stream_id].wait(),
                timeout=timeout
            )
            
            response = self.pending_responses.get(stream_id, {})
            return response
            
        except asyncio.TimeoutError:
            if self.debug:
                print(f"    ⏱️ Request timeout for stream {stream_id}")
            return {
                "status": None,
                "headers": [],
                "body": b"",
                "error": "timeout"
            }
    
    def process_udp_packet(self, data: bytes):
        """Process a received UDP datagram."""
        recv_time = time.time()
        
        self.packets_received += 1
        self.bytes_received += len(data)
        
        offset = 0
        packet_in_datagram = 0
        
        initial_largest_before = self.initial_tracker.largest_pn
        handshake_largest_before = self.handshake_tracker.largest_pn
        app_largest_before = self.app_tracker.largest_pn
        client_finished_before = self.client_finished_sent
        
        while offset < len(data):
            remaining = data[offset:]
            if len(remaining) < 5:
                break
            
            packet_in_datagram += 1
            first_byte = remaining[0]
            
            # Short header (1-RTT) detection
            # Short Header format: 0_1_S_RR_PP (first bit = 0, second bit = 1, i.e. 0x40-0x7F)
            # If first_byte < 0x40, it's likely padding (0x00) or garbage data, not a real Short Header
            if not (first_byte & 0x80):
                # Validate Short Header format: Fixed Bit must be 1 (RFC 9000 Section 17.3)
                if not (first_byte & 0x40):
                    # Not a valid Short Header (could be padding or other data)
                    if self.debug and first_byte != 0x00:  # Don't spam for PADDING
                        print(f"      ⚠️ Invalid Short Header first byte: 0x{first_byte:02x}, skipping remaining {len(remaining)} bytes")
                    break
                
                # Check minimum packet size (DCID + PN + Auth Tag at minimum)
                dcid_len = len(self.our_scid) if self.our_scid else 8
                min_short_header_size = 1 + dcid_len + 1 + 16  # header + DCID + min PN + auth tag
                if len(remaining) < min_short_header_size:
                    if self.debug:
                        print(f"      ⚠️ Remaining data too short for Short Header: {len(remaining)} bytes")
                    break
                
                if self.debug:
                    print(f"    📦 [#{self.packets_received}.{packet_in_datagram}] Short Header (1-RTT)")
                self._process_1rtt_packet(remaining, recv_time)
                break
            
            # Parse Long header
            header_info = parse_long_header(remaining)
            if not header_info["success"]:
                if self.debug:
                    print(f"    ❌ Cannot parse header: {header_info.get('error')}")
                break
            
            packet_type_id = header_info["packet_type_id"]
            packet_len = header_info["pn_offset"] + header_info["length"]
            packet_data = remaining[:packet_len]
            
            if self.debug:
                type_name = header_info["packet_type"]
                print(f"    📦 [#{self.packets_received}.{packet_in_datagram}] {type_name} ({packet_len} bytes)")
            
            if packet_type_id == 0:  # Initial
                self._process_initial_packet(packet_data, recv_time)
            elif packet_type_id == 2:  # Handshake
                self._process_handshake_packet(packet_data, recv_time)
            else:
                if self.debug:
                    print(f"      ⚠️ Unhandled packet type: {header_info['packet_type']}")
            
            offset += packet_len
        
        # Send ACKs
        need_initial_ack = self.initial_tracker.largest_pn > initial_largest_before
        need_handshake_ack = self.handshake_tracker.largest_pn > handshake_largest_before
        need_app_ack = self.app_tracker.largest_pn > app_largest_before
        
        if self.client_finished_sent and not client_finished_before:
            need_handshake_ack = False
        
        if need_initial_ack or need_handshake_ack:
            self._send_combined_acks(need_initial_ack, need_handshake_ack)
        
        if need_app_ack:
            self._send_1rtt_ack()
    
    def _build_0rtt_packet(self, payload: bytes) -> bytes:
        """Build a 0-RTT packet with the given payload."""
        if not self.zero_rtt_secrets:
            raise RuntimeError("0-RTT secrets not available")
        
        dcid = self.original_dcid
        
        packet = build_0rtt_packet(
            self.zero_rtt_secrets["client"],
            dcid,
            self.our_scid,
            self.client_app_pn,  # 0-RTT and 1-RTT share packet number space (RFC 9000)
            payload,
            debug=self.debug
        )
        
        self.client_app_pn += 1
        return packet
    
    def send_0rtt_request(self, method: str = "GET", path: str = "/",
                          headers: dict = None, body: bytes = None) -> int:
        """
        Send an HTTP/3 request using 0-RTT early data.
        
        This should be called after initiating 0-RTT handshake but before
        it completes. The request will be sent in 0-RTT packets.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path
            headers: Additional headers dict
            body: Request body
            
        Returns:
            int: Stream ID used for this request
        """
        if not self.zero_rtt_secrets:
            raise RuntimeError("Cannot send 0-RTT request: 0-RTT not enabled")
        
        # Allocate stream ID (client-initiated bidirectional: 0, 4, 8, ...)
        stream_id = self.next_request_stream_id
        self.next_request_stream_id += 4
        
        # Build request headers
        extra_headers = headers or {}
        if "user-agent" not in extra_headers:
            extra_headers["user-agent"] = "http3-client/1.0 (0-RTT)"
        
        # Build QPACK encoded headers
        qpack_headers = build_qpack_request_headers(
            method=method,
            scheme="https",
            authority=self.hostname,
            path=path,
            extra_headers=extra_headers
        )
        
        # Build HTTP/3 HEADERS frame
        headers_frame = build_h3_headers_frame(qpack_headers)
        
        # Build stream data
        stream_data = headers_frame
        if body:
            data_frame = build_h3_data_frame(body)
            stream_data += data_frame
        
        # Build STREAM frame
        stream_frame = build_stream_frame(
            stream_id=stream_id,
            data=stream_data,
            offset=0,
            fin=True
        )
        
        # Build and send 0-RTT packet
        packet = self._build_0rtt_packet(stream_frame)
        self.send(packet)
        
        # Track the request
        self.response_events[stream_id] = asyncio.Event()
        self.pending_0rtt_requests.append((stream_id, {"method": method, "path": path}))
        
        if self.debug:
            print(f"    → Sent 0-RTT HTTP/3 {method} request to {path}")
            print(f"      Stream ID: {stream_id}, 0-RTT PN: {self.client_app_pn - 1}")
            print(f"      Packet size: {len(packet)} bytes")
        
        return stream_id
    
    def _try_load_session_ticket(self, force_0rtt: bool = False) -> Optional[SessionTicket]:
        """Try to load a valid session ticket for 0-RTT.
        
        Args:
            force_0rtt: If True, attempt 0-RTT even if max_early_data_size=0
                        (for testing servers that may support 0-RTT but don't 
                        set the early_data extension properly)
        """
        if not self.session_ticket_store:
            return None
        
        ticket = self.session_ticket_store.get_ticket(self.hostname)
        if ticket:
            if ticket.is_valid(time.time()):
                if ticket.max_early_data_size > 0:
                    if self.debug:
                        print(f"    📋 Found valid session ticket for 0-RTT")
                        print(f"      Ticket age: {int(time.time() - ticket.creation_time)}s")
                        print(f"      Max early data: {ticket.max_early_data_size} bytes")
                    return ticket
                elif force_0rtt:
                    if self.debug:
                        print(f"    📋 Found valid session ticket (forced 0-RTT mode)")
                        print(f"      Ticket age: {int(time.time() - ticket.creation_time)}s")
                        print(f"      ⚠️ max_early_data=0, but forcing 0-RTT attempt")
                    return ticket
                else:
                    if self.debug:
                        print(f"    ⚠️ Session ticket found but server doesn't support 0-RTT")
                        print(f"      (max_early_data_size=0, use --force-0rtt to try anyway)")
            else:
                if self.debug:
                    print(f"    ⚠️ Session ticket expired")
        return None
    
    async def do_handshake(self, timeout: float = 5.0, force_0rtt: bool = False) -> bool:
        """Perform QUIC handshake.
        
        Args:
            timeout: Handshake timeout in seconds
            force_0rtt: Force 0-RTT attempt even if max_early_data_size=0
        """
        self.start_time = time.time()
        
        # Try to load session ticket for 0-RTT
        session_ticket = self._try_load_session_ticket(force_0rtt=force_0rtt)
        
        if session_ticket:
            # 0-RTT path: use PSK-based ClientHello
            return await self._do_handshake_0rtt(session_ticket, timeout)
        else:
            # Normal 1-RTT path
            return await self._do_handshake_1rtt(timeout)
    
    async def _do_handshake_1rtt(self, timeout: float = 5.0) -> bool:
        """Perform normal 1-RTT QUIC handshake."""
        # Generate and send Initial packet
        packet, dcid, scid, private_key, client_hello, client_random = create_initial_packet(self.hostname, debug=self.debug)
        
        self.original_dcid = dcid
        self.our_scid = scid
        self.private_key = private_key
        self.client_hello = client_hello
        self.client_random = client_random
        
        # Derive initial keys
        self._derive_initial_keys()
        
        if self.debug:
            print(f"    DCID: {dcid.hex()}")
            print(f"    SCID: {scid.hex()}")
            print(f"    Initial packet size: {len(packet)} bytes")
        
        # Track the sent packet for loss detection
        self._track_sent_packet(
            PacketNumberSpace.INITIAL,
            0,  # PN=0
            len(packet),
            frames=[{"type": "CRYPTO", "offset": 0, "data": client_hello}]
        )
        
        # Send Initial packet
        self.send(packet)
        self.client_initial_pn += 1
        if self.debug:
            print(f"    → Sent Initial packet (PN=0)")
        
        # Start PTO timer for retransmission
        self._start_pto_timer()
        
        # Wait for handshake to complete
        try:
            await asyncio.wait_for(self.handshake_complete.wait(), timeout=timeout)
            elapsed = time.time() - self.start_time
            if self.debug:
                print(f"\n    ✅ Handshake complete! Time: {elapsed:.3f}s")
                print(f"    📊 Stats: received {self.packets_received} pkts / {self.bytes_received} bytes, sent {self.packets_sent} pkts")
            return True
        except asyncio.TimeoutError:
            elapsed = time.time() - self.start_time
            if self.debug:
                print(f"\n    ⏱️ Handshake timeout ({timeout}s)")
                print(f"    State: {self.state.value}")
                print(f"    ServerHello: {'✓' if self.server_hello_received else '✗'}")
                print(f"    Finished: {'✓' if self.finished_received else '✗'}")
            return False
    
    async def _do_handshake_0rtt(self, session_ticket: SessionTicket, timeout: float = 5.0) -> bool:
        """Perform 0-RTT QUIC handshake with session resumption."""
        if self.debug:
            print(f"    🚀 Attempting 0-RTT handshake with session resumption")
        
        self.zero_rtt_enabled = True
        
        # Generate Initial packet with PSK
        result = create_initial_packet_with_psk(self.hostname, session_ticket, debug=self.debug)
        packet, dcid, scid, private_key, client_hello, client_random, psk, early_secret = result
        
        self.original_dcid = dcid
        self.our_scid = scid
        self.private_key = private_key
        self.client_hello = client_hello
        self.client_random = client_random
        self.zero_rtt_psk = psk
        self.zero_rtt_early_secret = early_secret
        
        # Derive initial keys
        self._derive_initial_keys()
        
        # Derive 0-RTT secrets
        client_hello_hash = hashlib.sha256(client_hello).digest()
        self.zero_rtt_secrets = derive_0rtt_application_secrets(
            early_secret, client_hello_hash, debug=self.debug
        )
        
        # Write 0-RTT keys to keylog file
        if self.client_random and self.keylog_file:
            lines = write_keylog(
                self.keylog_file, self.client_random,
                client_early_secret=self.zero_rtt_secrets["client"]["traffic_secret"]
            )
            if self.debug:
                print(f"    📝 0-RTT keys written to {self.keylog_file}:")
                for line in lines:
                    print(f"       {line}")
        
        if self.debug:
            print(f"    DCID: {dcid.hex()}")
            print(f"    SCID: {scid.hex()}")
            print(f"    Initial packet size: {len(packet)} bytes")
            print(f"    ✓ 0-RTT keys derived, ready for early data")
        
        # Track the sent packet for loss detection
        self._track_sent_packet(
            PacketNumberSpace.INITIAL,
            0,  # PN=0
            len(packet),
            frames=[{"type": "CRYPTO", "offset": 0, "data": client_hello}]
        )
        
        # Send Initial packet
        self.send(packet)
        self.client_initial_pn += 1
        if self.debug:
            print(f"    → Sent Initial packet with PSK (PN=0)")
        
        # Start PTO timer for retransmission
        self._start_pto_timer()
        
        # Wait for handshake to complete
        try:
            await asyncio.wait_for(self.handshake_complete.wait(), timeout=timeout)
            elapsed = time.time() - self.start_time
            if self.debug:
                print(f"\n    ✅ 0-RTT Handshake complete! Time: {elapsed:.3f}s")
                if self.zero_rtt_accepted:
                    print(f"    🎉 Server accepted 0-RTT early data!")
                elif self.zero_rtt_rejected:
                    print(f"    ⚠️ Server rejected 0-RTT (fallback to 1-RTT)")
                print(f"    📊 Stats: received {self.packets_received} pkts / {self.bytes_received} bytes, sent {self.packets_sent} pkts")
            return True
        except asyncio.TimeoutError:
            elapsed = time.time() - self.start_time
            if self.debug:
                print(f"\n    ⏱️ 0-RTT Handshake timeout ({timeout}s)")
                print(f"    State: {self.state.value}")
                print(f"    ServerHello: {'✓' if self.server_hello_received else '✗'}")
                print(f"    Finished: {'✓' if self.finished_received else '✗'}")
            return False
    
    async def request_0rtt(self, method: str = "GET", path: str = "/",
                           headers: dict = None, body: bytes = None,
                           timeout: float = 10.0) -> dict:
        """
        Send a 0-RTT HTTP/3 request with session resumption.
        
        This method:
        1. Loads a valid session ticket
        2. Initiates 0-RTT handshake
        3. Sends the HTTP request in 0-RTT packets
        4. Completes the handshake
        5. Waits for the response
        
        Args:
            method: HTTP method
            path: Request path
            headers: Additional headers
            body: Request body
            timeout: Total timeout for the operation
            
        Returns:
            dict: Response with 'status', 'headers', 'body', and '0rtt' (whether 0-RTT was used)
        """
        session_ticket = self._try_load_session_ticket()
        if not session_ticket:
            # No valid session ticket, use normal request
            if self.debug:
                print(f"    ⚠️ No valid session ticket, using normal 1-RTT request")
            
            # Do normal handshake first
            success = await self._do_handshake_1rtt(timeout / 2)
            if not success:
                return {"status": None, "headers": [], "body": b"", "error": "handshake failed", "0rtt": False}
            
            # Send normal request
            response = await self.request(method, path, headers, body, timeout / 2)
            response["0rtt"] = False
            return response
        
        # Start 0-RTT handshake
        self.start_time = time.time()
        self.zero_rtt_enabled = True
        
        # Generate Initial packet with PSK
        result = create_initial_packet_with_psk(self.hostname, session_ticket, debug=self.debug)
        packet, dcid, scid, private_key, client_hello, client_random, psk, early_secret = result
        
        self.original_dcid = dcid
        self.our_scid = scid
        self.private_key = private_key
        self.client_hello = client_hello
        self.client_random = client_random
        self.zero_rtt_psk = psk
        self.zero_rtt_early_secret = early_secret
        
        # Derive initial keys
        self._derive_initial_keys()
        
        # Derive 0-RTT secrets
        client_hello_hash = hashlib.sha256(client_hello).digest()
        self.zero_rtt_secrets = derive_0rtt_application_secrets(
            early_secret, client_hello_hash, debug=self.debug
        )
        
        # Write 0-RTT keys to keylog file
        if self.client_random and self.keylog_file:
            lines = write_keylog(
                self.keylog_file, self.client_random,
                client_early_secret=self.zero_rtt_secrets["client"]["traffic_secret"]
            )
            if self.debug:
                print(f"    📝 0-RTT keys written to {self.keylog_file}")
        
        if self.debug:
            print(f"    🚀 Starting 0-RTT request to {path}")
            print(f"    DCID: {dcid.hex()}")
            print(f"    SCID: {scid.hex()}")
        
        # Send Initial packet
        self.send(packet)
        self.client_initial_pn += 1
        if self.debug:
            print(f"    → Sent Initial packet with PSK (PN=0)")
        
        # Send 0-RTT request immediately
        stream_id = self.send_0rtt_request(method, path, headers, body)
        
        # Wait for handshake to complete
        try:
            await asyncio.wait_for(self.handshake_complete.wait(), timeout=timeout / 2)
        except asyncio.TimeoutError:
            if self.debug:
                print(f"    ⏱️ 0-RTT handshake timeout")
            return {"status": None, "headers": [], "body": b"", "error": "handshake timeout", "0rtt": True}
        
        # Wait for response
        try:
            await asyncio.wait_for(
                self.response_events[stream_id].wait(),
                timeout=timeout / 2
            )
            
            response = self.pending_responses.get(stream_id, {})
            response["0rtt"] = True
            response["0rtt_accepted"] = self.zero_rtt_accepted
            return response
            
        except asyncio.TimeoutError:
            if self.debug:
                print(f"    ⏱️ 0-RTT response timeout for stream {stream_id}")
            return {
                "status": None,
                "headers": [],
                "body": b"",
                "error": "response timeout",
                "0rtt": True
            }

