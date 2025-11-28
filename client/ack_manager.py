"""
QUIC ACK Manager - ACK frame generation and sending

Handles:
- Tracking received packets per encryption level
- Generating ACK frames with proper ranges
- ACK coalescing and timing
"""

import time
from typing import Optional, List, Tuple, Callable, Set
from dataclasses import dataclass, field

from quic.frames import build_ack_frame


@dataclass
class PacketTracker:
    """
    Track received packet numbers for ACK generation.
    
    Maintains received packet numbers and computes ACK ranges.
    """
    received_pns: Set[int] = field(default_factory=set)
    largest_pn: int = -1
    largest_pn_recv_time: float = 0.0
    ack_delay_exponent: int = 3  # Default 2^3 = 8 microseconds
    
    # Track if we need to send an ACK
    ack_pending: bool = False
    
    def record(self, pn: int, recv_time: float = None) -> None:
        """
        Record a received packet number.
        
        Args:
            pn: Packet number
            recv_time: Time when packet was received
        """
        if pn in self.received_pns:
            return  # Duplicate
        
        self.received_pns.add(pn)
        self.ack_pending = True
        
        if pn > self.largest_pn:
            self.largest_pn = pn
            self.largest_pn_recv_time = recv_time if recv_time is not None else time.time()
    
    def is_duplicate(self, pn: int) -> bool:
        """Check if packet is a duplicate."""
        return pn in self.received_pns
    
    def get_ack_delay(self) -> int:
        """
        Calculate encoded ACK delay for the largest acknowledged packet.
        
        Returns:
            int: Encoded ACK delay value
        """
        if self.largest_pn_recv_time == 0.0:
            return 0
        delay_seconds = time.time() - self.largest_pn_recv_time
        delay_microseconds = int(delay_seconds * 1_000_000)
        return delay_microseconds >> self.ack_delay_exponent
    
    def get_ack_ranges(self) -> List[Tuple[int, int]]:
        """
        Get ACK ranges sorted by descending packet number.
        
        Returns:
            list: List of (largest, smallest) tuples
        """
        if not self.received_pns:
            return []
        
        sorted_pns = sorted(self.received_pns, reverse=True)
        ranges = []
        range_largest = sorted_pns[0]
        range_smallest = sorted_pns[0]
        
        for pn in sorted_pns[1:]:
            if pn == range_smallest - 1:
                range_smallest = pn
            else:
                ranges.append((range_largest, range_smallest))
                range_largest = pn
                range_smallest = pn
        
        ranges.append((range_largest, range_smallest))
        return ranges
    
    def get_first_ack_range(self) -> int:
        """Get the first ACK range value (largest - smallest in first range)."""
        ranges = self.get_ack_ranges()
        if not ranges:
            return 0
        largest, smallest = ranges[0]
        return largest - smallest
    
    def mark_ack_sent(self) -> None:
        """Mark that an ACK has been sent."""
        self.ack_pending = False


class AckManager:
    """
    Manages ACK generation and sending for all encryption levels.
    
    Responsibilities:
    - Track received packets per level (Initial, Handshake, Application)
    - Generate ACK frames with proper ranges
    - Coalesce ACKs when possible
    """
    
    def __init__(self, debug: bool = False):
        self.debug = debug
        
        # Trackers per encryption level
        self.initial_tracker = PacketTracker()
        self.handshake_tracker = PacketTracker()
        self.app_tracker = PacketTracker()
        
        # Callback for sending packets
        self.on_send_initial_ack: Optional[Callable[[bytes], None]] = None
        self.on_send_handshake_ack: Optional[Callable[[bytes], None]] = None
        self.on_send_app_ack: Optional[Callable[[bytes], None]] = None
    
    # =========================================================================
    # Packet tracking
    # =========================================================================
    
    def record_initial_packet(self, pn: int, recv_time: float = None,
                               ack_eliciting: bool = True) -> bool:
        """
        Record a received Initial packet.
        
        Args:
            pn: Packet number
            recv_time: Receive time
            ack_eliciting: Whether packet requires ACK
            
        Returns:
            bool: True if this is a new packet (not duplicate)
        """
        if self.initial_tracker.is_duplicate(pn):
            if self.debug:
                print(f"    ⚠️ Duplicate Initial packet PN={pn}")
            return False
        
        if ack_eliciting:
            self.initial_tracker.record(pn, recv_time)
        return True
    
    def record_handshake_packet(self, pn: int, recv_time: float = None,
                                 ack_eliciting: bool = True) -> bool:
        """Record a received Handshake packet."""
        if self.handshake_tracker.is_duplicate(pn):
            if self.debug:
                print(f"    ⚠️ Duplicate Handshake packet PN={pn}")
            return False
        
        if ack_eliciting:
            self.handshake_tracker.record(pn, recv_time)
        return True
    
    def record_app_packet(self, pn: int, recv_time: float = None,
                          ack_eliciting: bool = True) -> bool:
        """Record a received Application (1-RTT) packet."""
        if self.app_tracker.is_duplicate(pn):
            if self.debug:
                print(f"    ⚠️ Duplicate 1-RTT packet PN={pn}")
            return False
        
        if ack_eliciting:
            self.app_tracker.record(pn, recv_time)
        return True
    
    # =========================================================================
    # ACK frame building
    # =========================================================================
    
    def build_initial_ack_frame(self) -> Optional[bytes]:
        """Build ACK frame for Initial packets."""
        return self._build_ack_frame(self.initial_tracker)
    
    def build_handshake_ack_frame(self) -> Optional[bytes]:
        """Build ACK frame for Handshake packets."""
        return self._build_ack_frame(self.handshake_tracker)
    
    def build_app_ack_frame(self) -> Optional[bytes]:
        """Build ACK frame for Application packets."""
        return self._build_ack_frame(self.app_tracker)
    
    def _build_ack_frame(self, tracker: PacketTracker) -> Optional[bytes]:
        """Build ACK frame from a tracker."""
        if tracker.largest_pn < 0:
            return None
        
        ack_ranges = tracker.get_ack_ranges()
        return build_ack_frame(
            largest_ack=tracker.largest_pn,
            ack_delay=tracker.get_ack_delay(),
            first_ack_range=tracker.get_first_ack_range(),
            ack_ranges=ack_ranges
        )
    
    # =========================================================================
    # ACK sending decisions
    # =========================================================================
    
    def needs_initial_ack(self) -> bool:
        """Check if we need to send an Initial ACK."""
        return self.initial_tracker.ack_pending
    
    def needs_handshake_ack(self) -> bool:
        """Check if we need to send a Handshake ACK."""
        return self.handshake_tracker.ack_pending
    
    def needs_app_ack(self) -> bool:
        """Check if we need to send an Application ACK."""
        return self.app_tracker.ack_pending
    
    def mark_initial_ack_sent(self) -> None:
        """Mark Initial ACK as sent."""
        self.initial_tracker.mark_ack_sent()
    
    def mark_handshake_ack_sent(self) -> None:
        """Mark Handshake ACK as sent."""
        self.handshake_tracker.mark_ack_sent()
    
    def mark_app_ack_sent(self) -> None:
        """Mark Application ACK as sent."""
        self.app_tracker.mark_ack_sent()
    
    # =========================================================================
    # Stats and state access
    # =========================================================================
    
    @property
    def initial_largest_pn(self) -> int:
        return self.initial_tracker.largest_pn
    
    @property
    def handshake_largest_pn(self) -> int:
        return self.handshake_tracker.largest_pn
    
    @property
    def app_largest_pn(self) -> int:
        return self.app_tracker.largest_pn
    
    def get_tracker(self, level: str) -> PacketTracker:
        """
        Get tracker by level name.
        
        Args:
            level: "initial", "handshake", or "application"
        """
        if level == "initial":
            return self.initial_tracker
        elif level == "handshake":
            return self.handshake_tracker
        else:
            return self.app_tracker

