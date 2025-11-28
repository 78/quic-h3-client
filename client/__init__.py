"""
QUIC/HTTP3 Client Implementation

Architecture:
=============
The client uses a component-based architecture (similar to Google WebRTC):

Core Components:
- QuicConnection: Main orchestrator that composes all components
- CryptoManager: Key derivation, encryption/decryption, Key Update
- FlowController: Send/receive flow control (MAX_DATA, MAX_STREAM_DATA)
- AckManager: ACK frame generation and tracking
- H3Handler: HTTP/3 protocol layer (QPACK, request/response)
- LossDetector: Loss detection, PTO, congestion control

Usage:
======
    from client import QuicConnection
    
    client = QuicConnection("example.com", 443)
    await client.connect()
    await client.do_handshake()
    response = await client.request("GET", "/")
    client.close()
"""

# Loss detection and congestion control
from .loss_detection import (
    LossDetector, PacketNumberSpace, SentPacketInfo, RTTEstimate,
    CongestionController, CongestionState
)

# Component classes
from .crypto_manager import CryptoManager, CryptoState
from .flow_controller import FlowController, StreamFlowState
from .ack_manager import AckManager, PacketTracker
from .h3_handler import H3Handler, H3Settings, H3Response
from .frame_processor import FrameProcessor

# Main connection class and state (merged from state.py and protocol.py)
from .connection import (
    QuicConnection, 
    HandshakeState, 
    CryptoBuffer,
    QuicProtocol,
)

__all__ = [
    # Main client class
    "QuicConnection",
    
    # Component classes
    "CryptoManager",
    "CryptoState",
    "FlowController",
    "StreamFlowState",
    "AckManager",
    "H3Handler",
    "H3Settings",
    "H3Response",
    "FrameProcessor",
    
    # State management
    "HandshakeState",
    "CryptoBuffer",
    "PacketTracker",
    
    # Loss detection
    "LossDetector",
    "PacketNumberSpace",
    "SentPacketInfo",
    "RTTEstimate",
    "CongestionController",
    "CongestionState",
    
    # Protocol
    "QuicProtocol",
]
