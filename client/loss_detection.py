"""
QUIC Loss Detection and Recovery (RFC 9002)

Implements:
- Packet tracking for sent packets
- ACK-based loss detection
- Probe Timeout (PTO) for detecting losses
- Retransmission of lost frames
"""

import time
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Callable, Any
from collections import OrderedDict


class PacketNumberSpace(Enum):
    """QUIC Packet Number Spaces"""
    INITIAL = "initial"
    HANDSHAKE = "handshake"
    APPLICATION = "application"


@dataclass
class SentPacketInfo:
    """
    Information about a sent packet for loss detection.
    
    Stores the frames contained in the packet so they can be
    retransmitted if the packet is determined to be lost.
    """
    packet_number: int
    sent_time: float
    sent_bytes: int
    ack_eliciting: bool
    in_flight: bool  # True if packet counts towards bytes in flight
    frames: List[Dict[str, Any]] = field(default_factory=list)
    
    # For tracking
    acknowledged: bool = False
    declared_lost: bool = False
    
    def __post_init__(self):
        if self.frames is None:
            self.frames = []


@dataclass
class RTTEstimate:
    """
    RTT (Round Trip Time) estimates for congestion control and loss detection.
    Based on RFC 9002 Section 5.
    """
    # Minimum RTT observed
    min_rtt: float = float('inf')
    # Smoothed RTT (exponentially weighted moving average)
    smoothed_rtt: float = 0.333  # Initial value: 333ms
    # RTT variance
    rttvar: float = 0.166  # Initial value: smoothed_rtt/2
    # Latest RTT sample
    latest_rtt: float = 0.0
    # First RTT sample (used for special handling)
    first_rtt_sample: Optional[float] = None
    
    def update(self, rtt_sample: float, ack_delay: float = 0.0, max_ack_delay: float = 0.025):
        """
        Update RTT estimates based on a new sample.
        
        Args:
            rtt_sample: The measured RTT
            ack_delay: ACK delay reported by peer (in seconds)
            max_ack_delay: Maximum ACK delay (from transport parameters)
        """
        self.latest_rtt = rtt_sample
        
        # Update min_rtt (RFC 9002 Section 5.2)
        if rtt_sample < self.min_rtt:
            self.min_rtt = rtt_sample
        
        # Adjust RTT sample with ACK delay (RFC 9002 Section 5.3)
        adjusted_rtt = rtt_sample
        if rtt_sample > self.min_rtt + ack_delay:
            # Only subtract ack_delay if it doesn't make adjusted_rtt < min_rtt
            adjusted_rtt = rtt_sample - min(ack_delay, max_ack_delay)
        
        if self.first_rtt_sample is None:
            # First sample (RFC 9002 Section 5.3)
            self.first_rtt_sample = rtt_sample
            self.smoothed_rtt = rtt_sample
            self.rttvar = rtt_sample / 2
        else:
            # Subsequent samples
            # rttvar = 3/4 * rttvar + 1/4 * |smoothed_rtt - adjusted_rtt|
            self.rttvar = 0.75 * self.rttvar + 0.25 * abs(self.smoothed_rtt - adjusted_rtt)
            # smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt
            self.smoothed_rtt = 0.875 * self.smoothed_rtt + 0.125 * adjusted_rtt
    
    def get_pto(self, max_ack_delay: float = 0.025) -> float:
        """
        Calculate Probe Timeout (PTO).
        
        PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay
        
        Args:
            max_ack_delay: Maximum ACK delay (from transport parameters)
            
        Returns:
            float: PTO in seconds
        """
        kGranularity = 0.001  # 1ms timer granularity
        return self.smoothed_rtt + max(4 * self.rttvar, kGranularity) + max_ack_delay


@dataclass 
class LossDetectionState:
    """State for loss detection per packet number space."""
    largest_acked_packet: int = -1
    loss_time: Optional[float] = None  # Time when packets were declared lost
    time_of_last_ack_eliciting_packet: Optional[float] = None
    
    # Sent packets (packet_number -> SentPacketInfo)
    sent_packets: Dict[int, SentPacketInfo] = field(default_factory=dict)
    
    # Statistics
    packets_sent: int = 0
    packets_acked: int = 0
    packets_lost: int = 0
    bytes_in_flight: int = 0


class LossDetector:
    """
    QUIC Loss Detection and Recovery.
    
    Implements loss detection based on RFC 9002:
    - Time threshold loss detection
    - Packet threshold loss detection  
    - Probe timeout (PTO)
    """
    
    # Constants from RFC 9002
    kPacketThreshold = 3  # Packets before oldest unacked is declared lost
    kTimeThreshold = 9/8  # Time before oldest unacked is declared lost
    kInitialRtt = 0.333   # 333ms initial RTT estimate
    kGranularity = 0.001  # 1ms timer granularity
    
    def __init__(self, debug: bool = False):
        self.debug = debug
        
        # RTT estimation
        self.rtt = RTTEstimate()
        
        # State per packet number space
        self.spaces: Dict[PacketNumberSpace, LossDetectionState] = {
            PacketNumberSpace.INITIAL: LossDetectionState(),
            PacketNumberSpace.HANDSHAKE: LossDetectionState(),
            PacketNumberSpace.APPLICATION: LossDetectionState(),
        }
        
        # PTO state
        self.pto_count: int = 0
        self.max_ack_delay: float = 0.025  # Default 25ms, can be updated from transport params
        
        # Callbacks for retransmission
        self.on_packets_lost: Optional[Callable[[PacketNumberSpace, List[SentPacketInfo]], None]] = None
        self.on_pto_timeout: Optional[Callable[[PacketNumberSpace], None]] = None
        
    def on_packet_sent(self, space: PacketNumberSpace, packet_number: int, 
                       sent_bytes: int, ack_eliciting: bool,
                       frames: List[Dict[str, Any]], in_flight: bool = True):
        """
        Called when a packet is sent.
        
        Args:
            space: Packet number space
            packet_number: The packet number
            sent_bytes: Size of the packet
            ack_eliciting: Whether the packet is ack-eliciting
            frames: List of frames in the packet
            in_flight: Whether packet counts towards congestion control
        """
        state = self.spaces[space]
        
        sent_info = SentPacketInfo(
            packet_number=packet_number,
            sent_time=time.time(),
            sent_bytes=sent_bytes,
            ack_eliciting=ack_eliciting,
            in_flight=in_flight,
            frames=frames.copy() if frames else []
        )
        
        state.sent_packets[packet_number] = sent_info
        state.packets_sent += 1
        
        if in_flight:
            state.bytes_in_flight += sent_bytes
        
        if ack_eliciting:
            state.time_of_last_ack_eliciting_packet = sent_info.sent_time
        
        if self.debug:
            print(f"    📤 Tracked sent packet: space={space.value}, PN={packet_number}, "
                  f"size={sent_bytes}, ack_eliciting={ack_eliciting}")
    
    def on_ack_received(self, space: PacketNumberSpace, ack_ranges: List[tuple],
                        ack_delay: float = 0.0) -> List[SentPacketInfo]:
        """
        Process received ACK frame.
        
        Args:
            space: Packet number space
            ack_ranges: List of (start, end) tuples of acknowledged packet numbers
            ack_delay: ACK delay reported by peer (in seconds)
            
        Returns:
            List of newly acknowledged packets
        """
        state = self.spaces[space]
        newly_acked = []
        now = time.time()
        
        if not ack_ranges:
            return newly_acked
        
        # Get largest acknowledged packet number
        largest_acked = max(end for start, end in ack_ranges)
        
        # Process acknowledged packets
        for ack_start, ack_end in ack_ranges:
            for pn in range(ack_end, ack_start - 1, -1):  # Iterate from largest to smallest
                if pn in state.sent_packets:
                    sent_info = state.sent_packets[pn]
                    if not sent_info.acknowledged:
                        sent_info.acknowledged = True
                        state.packets_acked += 1
                        newly_acked.append(sent_info)
                        
                        if sent_info.in_flight:
                            state.bytes_in_flight -= sent_info.sent_bytes
                        
                        if self.debug:
                            print(f"    ✓ Packet acknowledged: space={space.value}, PN={pn}")
        
        # Update RTT estimates using the largest newly acked packet
        if newly_acked:
            # Find the largest packet that was newly acknowledged
            largest_newly_acked = max(p.packet_number for p in newly_acked)
            largest_packet = state.sent_packets.get(largest_newly_acked)
            
            if largest_packet and largest_packet.ack_eliciting:
                rtt_sample = now - largest_packet.sent_time
                self.rtt.update(rtt_sample, ack_delay, self.max_ack_delay)
                
                if self.debug:
                    print(f"    📊 RTT updated: sample={rtt_sample*1000:.1f}ms, "
                          f"smoothed={self.rtt.smoothed_rtt*1000:.1f}ms, "
                          f"min={self.rtt.min_rtt*1000:.1f}ms")
        
        # Update largest acked
        if largest_acked > state.largest_acked_packet:
            state.largest_acked_packet = largest_acked
        
        # Detect lost packets
        lost_packets = self._detect_lost_packets(space, now)
        
        if lost_packets:
            state.packets_lost += len(lost_packets)
            if self.on_packets_lost:
                self.on_packets_lost(space, lost_packets)
        
        # Reset PTO count on receiving ACK
        self.pto_count = 0
        
        # Clean up old acknowledged packets
        self._cleanup_acked_packets(space)
        
        return newly_acked
    
    def _detect_lost_packets(self, space: PacketNumberSpace, now: float) -> List[SentPacketInfo]:
        """
        Detect lost packets using time and packet number thresholds.
        Based on RFC 9002 Section 6.
        
        Returns:
            List of packets determined to be lost
        """
        state = self.spaces[space]
        lost_packets = []
        
        if state.largest_acked_packet < 0:
            return lost_packets
        
        # Calculate loss delay threshold
        loss_delay = self.kTimeThreshold * max(self.rtt.latest_rtt, self.rtt.smoothed_rtt)
        loss_delay = max(loss_delay, self.kGranularity)
        
        # Packets sent before this time are potentially lost
        lost_send_time = now - loss_delay
        
        for pn, sent_info in list(state.sent_packets.items()):
            if sent_info.acknowledged or sent_info.declared_lost:
                continue
            
            if pn > state.largest_acked_packet:
                continue  # Can't be lost yet - not enough packets acknowledged after it
            
            # Check time threshold
            time_threshold_exceeded = sent_info.sent_time <= lost_send_time
            
            # Check packet threshold
            packet_threshold_exceeded = (state.largest_acked_packet - pn) >= self.kPacketThreshold
            
            if time_threshold_exceeded or packet_threshold_exceeded:
                sent_info.declared_lost = True
                lost_packets.append(sent_info)
                
                if sent_info.in_flight:
                    state.bytes_in_flight -= sent_info.sent_bytes
                
                if self.debug:
                    reason = "time" if time_threshold_exceeded else "packet"
                    print(f"    ❌ Packet lost: space={space.value}, PN={pn}, reason={reason}")
        
        return lost_packets
    
    def _cleanup_acked_packets(self, space: PacketNumberSpace):
        """Remove old acknowledged packets to prevent memory growth."""
        state = self.spaces[space]
        
        # Keep only unacknowledged packets and recently lost packets
        to_remove = []
        for pn, sent_info in state.sent_packets.items():
            if sent_info.acknowledged or (sent_info.declared_lost and 
                                           time.time() - sent_info.sent_time > 60):
                to_remove.append(pn)
        
        for pn in to_remove:
            del state.sent_packets[pn]
    
    def get_loss_time(self, space: PacketNumberSpace) -> Optional[float]:
        """
        Get the earliest time at which packets might be declared lost.
        
        Returns:
            Time when next loss detection should run, or None
        """
        state = self.spaces[space]
        
        if state.largest_acked_packet < 0:
            return None
        
        loss_delay = self.kTimeThreshold * max(self.rtt.latest_rtt, self.rtt.smoothed_rtt)
        loss_delay = max(loss_delay, self.kGranularity)
        
        earliest_loss_time = None
        
        for pn, sent_info in state.sent_packets.items():
            if sent_info.acknowledged or sent_info.declared_lost:
                continue
            if pn > state.largest_acked_packet:
                continue
            
            loss_time = sent_info.sent_time + loss_delay
            if earliest_loss_time is None or loss_time < earliest_loss_time:
                earliest_loss_time = loss_time
        
        return earliest_loss_time
    
    def get_pto_time_and_space(self, handshake_confirmed: bool = False) -> tuple:
        """
        Calculate time when PTO should fire and which space to probe.
        
        RFC 9002 Section 6.2.1: GetPtoTimeAndSpace()
        
        Args:
            handshake_confirmed: Whether the handshake is confirmed
            
        Returns:
            tuple: (pto_timeout, pto_space) - time and space to probe
        """
        # Base PTO duration (without max_ack_delay which is added for ApplicationData)
        base_pto = self.rtt.smoothed_rtt + max(4 * self.rtt.rttvar, self.kGranularity)
        duration = base_pto * (2 ** self.pto_count)
        
        # Check if any ack-eliciting packets are in flight
        any_in_flight = False
        for state in self.spaces.values():
            if any(not p.acknowledged and not p.declared_lost and p.ack_eliciting
                   for p in state.sent_packets.values()):
                any_in_flight = True
                break
        
        # If no ack-eliciting packets in flight, arm from now
        if not any_in_flight:
            # During handshake, prefer Handshake space if keys available
            return (time.time() + duration, PacketNumberSpace.INITIAL)
        
        # Find earliest PTO across spaces with in-flight packets
        pto_timeout = float('inf')
        pto_space = PacketNumberSpace.INITIAL
        
        # Order matters: Initial, Handshake, Application (per RFC 9002)
        space_order = [
            PacketNumberSpace.INITIAL,
            PacketNumberSpace.HANDSHAKE,
            PacketNumberSpace.APPLICATION
        ]
        
        for space in space_order:
            state = self.spaces[space]
            
            # Check if this space has ack-eliciting packets in flight
            has_in_flight = any(
                not p.acknowledged and not p.declared_lost and p.ack_eliciting
                for p in state.sent_packets.values()
            )
            if not has_in_flight:
                continue
            
            # Skip ApplicationData until handshake is confirmed
            if space == PacketNumberSpace.APPLICATION and not handshake_confirmed:
                continue
            
            # Calculate duration for this space
            space_duration = duration
            if space == PacketNumberSpace.APPLICATION:
                # ApplicationData includes max_ack_delay with backoff
                space_duration += self.max_ack_delay * (2 ** self.pto_count)
            
            # Calculate PTO time for this space
            if state.time_of_last_ack_eliciting_packet is not None:
                t = state.time_of_last_ack_eliciting_packet + space_duration
                if t < pto_timeout:
                    pto_timeout = t
                    pto_space = space
        
        # If no valid space found, use default
        if pto_timeout == float('inf'):
            pto_timeout = time.time() + duration
        
        return (pto_timeout, pto_space)
    
    def get_pto_time(self, handshake_confirmed: bool = False) -> float:
        """
        Calculate time when PTO should fire.
        
        Returns:
            float: Time when PTO timer should fire
        """
        pto_timeout, _ = self.get_pto_time_and_space(handshake_confirmed)
        return pto_timeout
    
    def on_pto_timeout(self, space: PacketNumberSpace):
        """
        Called when PTO timer fires.
        Triggers sending of probe packets.
        """
        self.pto_count += 1
        
        if self.debug:
            print(f"    ⏰ PTO timeout: space={space.value}, count={self.pto_count}")
        
        if self.on_pto_timeout:
            self.on_pto_timeout(space)
    
    def get_unacked_packets(self, space: PacketNumberSpace) -> List[SentPacketInfo]:
        """
        Get list of unacknowledged packets in a space.
        
        Returns:
            List of packets that haven't been acknowledged
        """
        state = self.spaces[space]
        return [
            info for info in state.sent_packets.values()
            if not info.acknowledged and not info.declared_lost
        ]
    
    def has_unacked_packets(self, space: PacketNumberSpace) -> bool:
        """Check if there are unacknowledged packets in the space."""
        return len(self.get_unacked_packets(space)) > 0
    
    def get_stats(self, space: PacketNumberSpace) -> Dict[str, Any]:
        """Get statistics for a packet number space."""
        state = self.spaces[space]
        return {
            "packets_sent": state.packets_sent,
            "packets_acked": state.packets_acked,
            "packets_lost": state.packets_lost,
            "bytes_in_flight": state.bytes_in_flight,
            "largest_acked": state.largest_acked_packet,
            "unacked_count": len(self.get_unacked_packets(space)),
        }

