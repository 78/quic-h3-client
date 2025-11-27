"""
QUIC Connection State Management
"""

import time
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Tuple, Set


class HandshakeState(Enum):
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
    received_ranges: List[Tuple[int, int]] = field(default_factory=list)  # [(start, end), ...]
    
    def add_fragment(self, offset: int, fragment: bytes) -> bool:
        """
        Add a CRYPTO fragment to the buffer.
        
        Args:
            offset: Byte offset of the fragment
            fragment: Fragment data
            
        Returns:
            bool: True if this is new data, False if duplicate
        """
        end = offset + len(fragment)
        
        # Check for duplicate
        for start_r, end_r in self.received_ranges:
            if offset >= start_r and end <= end_r:
                return False  # Duplicate
        
        # Expand buffer if needed
        if end > len(self.data):
            self.data.extend(b'\x00' * (end - len(self.data)))
        
        # Write fragment
        self.data[offset:end] = fragment
        
        # Update received ranges (simplified, doesn't merge)
        self.received_ranges.append((offset, end))
        return True
    
    def get_contiguous_data(self) -> bytes:
        """Get contiguous data starting from offset 0."""
        if not self.received_ranges:
            return b""
        
        # Sort ranges
        sorted_ranges = sorted(self.received_ranges, key=lambda x: x[0])
        
        # Find contiguous length from start
        contiguous_end = 0
        for start, end in sorted_ranges:
            if start <= contiguous_end:
                contiguous_end = max(contiguous_end, end)
            else:
                break  # Gap found
        
        return bytes(self.data[:contiguous_end])
    
    @property
    def total_received(self) -> int:
        """Total bytes received (may have gaps)."""
        if not self.received_ranges:
            return 0
        return max(end for _, end in self.received_ranges)


@dataclass 
class PacketTracker:
    """Track received packet numbers for ACK generation."""
    received_pns: Set[int] = field(default_factory=set)
    largest_pn: int = -1
    largest_pn_recv_time: float = 0.0  # Time when largest_pn was received
    ack_delay_exponent: int = 3        # Default exponent (2^3 = 8 microseconds)
    
    def record(self, pn: int, recv_time: float = None):
        """
        Record a received packet number with optional receive time.
        
        Args:
            pn: Packet number
            recv_time: Time when packet was received (default: now)
        """
        self.received_pns.add(pn)
        if pn > self.largest_pn:
            self.largest_pn = pn
            self.largest_pn_recv_time = recv_time if recv_time is not None else time.time()
    
    def get_ack_delay(self) -> int:
        """
        Calculate ACK delay for the largest acknowledged packet.
        
        Returns:
            int: Encoded ACK delay value (delay_us >> ack_delay_exponent)
        """
        if self.largest_pn_recv_time == 0.0:
            return 0
        delay_seconds = time.time() - self.largest_pn_recv_time
        delay_microseconds = int(delay_seconds * 1_000_000)
        # Encode: actual_delay = encoded_value << ack_delay_exponent
        # So: encoded_value = actual_delay >> ack_delay_exponent
        encoded_delay = delay_microseconds >> self.ack_delay_exponent
        return encoded_delay
    
    def get_ack_ranges(self) -> List[Tuple[int, int]]:
        """
        Get ACK ranges sorted by descending packet number.
        
        Each range is (largest_pn, smallest_pn) where largest_pn >= smallest_pn.
        The first range contains the largest acknowledged packet.
        
        Returns:
            list: List of (largest, smallest) tuples representing acknowledged ranges
        """
        if not self.received_pns:
            return []
        
        sorted_pns = sorted(self.received_pns, reverse=True)
        ranges = []
        range_largest = sorted_pns[0]
        range_smallest = sorted_pns[0]
        
        for pn in sorted_pns[1:]:
            if pn == range_smallest - 1:
                # Extend current range
                range_smallest = pn
            else:
                # Gap found, save current range and start new one
                ranges.append((range_largest, range_smallest))
                range_largest = pn
                range_smallest = pn
        
        # Don't forget the last range
        ranges.append((range_largest, range_smallest))
        return ranges
    
    def get_first_ack_range(self) -> int:
        """
        Get the first ACK range value for ACK frame.
        
        This is the number of packets acknowledged in the first (highest) range,
        calculated as: largest_pn - smallest_pn_in_first_range
        
        Returns:
            int: First ACK range value (0 if no packets received)
        """
        ranges = self.get_ack_ranges()
        if not ranges:
            return 0
        largest, smallest = ranges[0]
        return largest - smallest

