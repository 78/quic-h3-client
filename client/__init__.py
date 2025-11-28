"""
QUIC/HTTP3 Client Implementation

Provides:
- RealtimeQUICClient: Main client class
- Handshake state management
- Async protocol handlers
- Loss detection and recovery (RFC 9002)
- Congestion control with slow start and congestion avoidance
"""

from .state import HandshakeState, CryptoBuffer, PacketTracker
from .connection import RealtimeQUICClient
from .protocol import RealtimeQUICProtocol
from .loss_detection import (
    LossDetector, PacketNumberSpace, SentPacketInfo, RTTEstimate,
    CongestionController, CongestionState
)

