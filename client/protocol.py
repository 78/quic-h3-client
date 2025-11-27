"""
Asyncio Protocol for QUIC Client
"""

import asyncio
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .connection import RealtimeQUICClient


class RealtimeQUICProtocol(asyncio.DatagramProtocol):
    """Protocol handler for real-time QUIC packet processing."""
    
    def __init__(self, client: 'RealtimeQUICClient'):
        self.client = client
        
    def connection_made(self, transport):
        """Called when connection is established."""
        pass
    
    def datagram_received(self, data: bytes, addr):
        """
        Process incoming UDP datagram immediately.
        
        Args:
            data: Received datagram
            addr: Source address
        """
        self.client.process_udp_packet(data)
    
    def error_received(self, exc):
        """Called when a send/receive operation fails."""
        if self.client.debug:
            print(f"    ❌ UDP Error: {exc}")
        
    def connection_lost(self, exc):
        """Called when connection is lost."""
        if exc and self.client.debug:
            print(f"    Connection closed: {exc}")

