#!/usr/bin/env python3
"""
Test script for QUIC packet loss detection and recovery.

This script tests the packet loss handling by:
1. Creating a client with simulated packet loss
2. Verifying that lost packets are retransmitted
3. Testing both handshake and data packet retransmission

Usage:
    python test_packet_loss.py [hostname] [--loss-rate 0.3]
"""

import argparse
import asyncio
import random
import time
from typing import Optional
from client import QuicConnection, QuicProtocol


class PacketLossProtocol(QuicProtocol):
    """
    Protocol wrapper that simulates packet loss for testing.
    Supports both outgoing (send) and incoming (receive) packet loss.
    """
    
    def __init__(self, client: 'PacketLossQUICClient', loss_rate: float = 0.0,
                 incoming_loss_rate: float = 0.0):
        super().__init__(client)
        self.loss_rate = loss_rate  # Outgoing loss rate
        self.incoming_loss_rate = incoming_loss_rate  # Incoming loss rate
        self.dropped_packets = 0  # Outgoing dropped
        self.dropped_incoming = 0  # Incoming dropped
        self.total_sent = 0
        self.total_received = 0
        self.initial_packets_sent = 0  # Track Initial packets specifically
        self.wrapped_transport = None
        
        # For controlled incoming drop
        self._incoming_packet_counter = 0
        self._incoming_packets_to_drop = set()
        self._drop_incoming_every_packet_once = False
        
    def connection_made(self, transport):
        """Wrap the transport to intercept sendto calls."""
        self.original_transport = transport
        # Create wrapper transport
        self.wrapped_transport = PacketLossTransport(
            transport, 
            self.loss_rate,
            self._on_packet_dropped,
            self._on_packet_sent,
            debug=self.client.debug
        )
        # IMPORTANT: Don't set client.transport here, it will be set by connect()
        # Instead, we'll intercept in the send method
        
    def _on_packet_dropped(self):
        self.dropped_packets += 1
    
    def _on_packet_sent(self, data: bytes):
        self.total_sent += 1
        # Check if it's an Initial packet (Long header, type 0)
        if len(data) > 0 and (data[0] & 0xF0) == 0xC0:
            self.initial_packets_sent += 1
    
    def datagram_received(self, data: bytes, addr):
        """
        Override to simulate incoming packet loss.
        Intercepts packets from the server and randomly drops them.
        """
        self._incoming_packet_counter += 1
        self.total_received += 1
        
        should_drop = False
        drop_reason = ""
        
        # Check drop-every-packet-once mode (alternating)
        if self._drop_incoming_every_packet_once:
            if self._incoming_packet_counter % 2 == 1:
                should_drop = True
                drop_reason = f"incoming-drop-alternating (#{self._incoming_packet_counter})"
            else:
                if self.client.debug:
                    print(f"    ✅ [SIMULATED] Allowing incoming packet #{self._incoming_packet_counter}")
        # Check scheduled drops
        elif self._incoming_packet_counter in self._incoming_packets_to_drop:
            should_drop = True
            drop_reason = "scheduled incoming drop"
        # Check random loss
        elif self.incoming_loss_rate > 0 and random.random() < self.incoming_loss_rate:
            should_drop = True
            drop_reason = "random incoming loss"
        
        if should_drop:
            self.dropped_incoming += 1
            if self.client.debug:
                # Try to identify packet type
                pkt_type = "Unknown"
                if len(data) > 0:
                    first_byte = data[0]
                    if (first_byte & 0x80) == 0:
                        pkt_type = "1-RTT"
                    elif (first_byte & 0xF0) == 0xC0:
                        pkt_type = "Initial"
                    elif (first_byte & 0xF0) == 0xE0:
                        pkt_type = "Handshake"
                print(f"    💥 [SIMULATED] Dropping INCOMING {pkt_type} packet #{self._incoming_packet_counter} ({drop_reason})")
            return  # Don't process this packet
        
        # Pass to actual handler
        super().datagram_received(data, addr)
    
    def drop_incoming_packet_n(self, n: int):
        """Schedule incoming packet number N to be dropped."""
        self._incoming_packets_to_drop.add(n)
    
    def enable_drop_incoming_every_packet_once(self):
        """Enable drop-every-packet-once mode for incoming packets."""
        self._drop_incoming_every_packet_once = True
        if self.client.debug:
            print(f"    ⚠️ [SIMULATED] Incoming drop-every-packet-once mode ENABLED")
    
    def disable_drop_incoming_every_packet_once(self):
        """Disable drop-every-packet-once mode for incoming packets."""
        self._drop_incoming_every_packet_once = False
        if self.client.debug:
            print(f"    ✓ [SIMULATED] Incoming drop-every-packet-once mode DISABLED")
    
    def get_incoming_stats(self) -> dict:
        """Get incoming packet loss statistics."""
        return {
            "total_received": self.total_received,
            "dropped_incoming": self.dropped_incoming,
            "processed": self.total_received - self.dropped_incoming,
        }


class PacketLossTransport:
    """
    Transport wrapper that simulates packet loss.
    """
    
    def __init__(self, transport, loss_rate: float, 
                 on_dropped=None, on_sent=None, debug=False):
        self._transport = transport
        self.loss_rate = loss_rate
        self.on_dropped = on_dropped
        self.on_sent = on_sent
        self.debug = debug
        self._packets_to_drop = set()  # Specific packet indices to drop
        self._packet_counter = 0
        
        # For "drop every packet once" mode - use alternating pattern
        self._drop_every_packet_once = False
        self._total_dropped = 0
        self._total_sent = 0
        
    def sendto(self, data, addr=None):
        """Send data, potentially dropping it to simulate loss."""
        self._packet_counter += 1
        
        # Check if this specific packet should be dropped
        should_drop = False
        drop_reason = ""
        
        # "Drop every packet once" mode - alternate between drop and send
        # This ensures every "logical" packet needs at least one retransmission
        if self._drop_every_packet_once:
            # Drop odd-numbered packets, send even-numbered packets
            # This simulates: send #1 (drop), send #2 (ok), send #3 (drop), send #4 (ok)...
            if self._packet_counter % 2 == 1:
                should_drop = True
                drop_reason = f"drop-alternating (#{self._packet_counter})"
            else:
                if self.debug:
                    print(f"    ✅ [SIMULATED] Allowing packet #{self._packet_counter} (even-numbered)")
        elif self._packet_counter in self._packets_to_drop:
            should_drop = True
            drop_reason = "scheduled drop"
        elif self.loss_rate > 0 and random.random() < self.loss_rate:
            should_drop = True
            drop_reason = "random loss"
        
        if should_drop:
            self._total_dropped += 1
            if self.debug:
                print(f"    💥 [SIMULATED] Dropping packet #{self._packet_counter} ({drop_reason})")
            if self.on_dropped:
                self.on_dropped()
            return  # Don't actually send
        
        # Actually send the packet
        self._total_sent += 1
        if addr:
            self._transport.sendto(data, addr)
        else:
            self._transport.sendto(data)
        
        if self.on_sent:
            self.on_sent(data)
    
    def close(self):
        self._transport.close()
    
    def drop_next_packet(self):
        """Schedule the next packet to be dropped."""
        self._packets_to_drop.add(self._packet_counter + 1)
    
    def drop_packet_n(self, n: int):
        """Schedule packet number N to be dropped."""
        self._packets_to_drop.add(n)
    
    def enable_drop_every_packet_once(self):
        """
        Enable mode where every packet is dropped once (alternating pattern).
        
        This simulates 50% packet loss in an alternating pattern, ensuring
        every "logical" packet (original send) is dropped and needs retransmission.
        """
        self._drop_every_packet_once = True
        self._total_dropped = 0
        self._total_sent = 0
        if self.debug:
            print(f"    ⚠️ [SIMULATED] Drop-every-packet-once mode ENABLED (alternating)")
    
    def disable_drop_every_packet_once(self):
        """Disable drop-every-packet-once mode."""
        self._drop_every_packet_once = False
        if self.debug:
            print(f"    ✓ [SIMULATED] Drop-every-packet-once mode DISABLED")
    
    def get_drop_once_stats(self) -> dict:
        """Get statistics for drop-every-packet-once mode."""
        return {
            "packets_attempted": self._packet_counter,
            "packets_dropped": self._total_dropped,
            "packets_sent": self._total_sent,
        }
    
    def get_remote_address(self):
        return self._transport.get_extra_info('peername')
    
    def get_extra_info(self, name, default=None):
        return self._transport.get_extra_info(name, default)


class PacketLossQUICClient(QuicConnection):
    """
    QUIC Client with simulated packet loss for testing.
    Supports both outgoing (client -> server) and incoming (server -> client) loss.
    """
    
    def __init__(self, hostname: str, port: int, loss_rate: float = 0.0,
                 incoming_loss_rate: float = 0.0,
                 debug: bool = True, keylog_file: str = None,
                 session_file: str = None):
        super().__init__(hostname, port, debug=debug, keylog_file=keylog_file,
                        session_file=session_file)
        self.loss_rate = loss_rate  # Outgoing loss
        self.incoming_loss_rate = incoming_loss_rate  # Incoming loss
        self.loss_protocol: Optional[PacketLossProtocol] = None
        self._wrapped_transport = None
        
    async def connect(self):
        """Connect with packet loss simulation."""
        self.target_ip = __import__('socket').gethostbyname(self.hostname)
        if self.debug:
            print(f"    Resolved: {self.target_ip}")
            if self.loss_rate > 0:
                print(f"    Simulated OUTGOING packet loss rate: {self.loss_rate * 100:.1f}%")
            if self.incoming_loss_rate > 0:
                print(f"    Simulated INCOMING packet loss rate: {self.incoming_loss_rate * 100:.1f}%")
        
        loop = asyncio.get_event_loop()
        
        # Create protocol with loss simulation
        self.loss_protocol = PacketLossProtocol(
            self, 
            self.loss_rate,
            incoming_loss_rate=self.incoming_loss_rate
        )
        
        self.transport, self.protocol = await loop.create_datagram_endpoint(
            lambda: self.loss_protocol,
            remote_addr=(self.target_ip, self.port)
        )
        
        # Store wrapped transport for packet loss simulation
        self._wrapped_transport = self.loss_protocol.wrapped_transport
    
    def send(self, data: bytes):
        """Send UDP packet through the loss simulation wrapper."""
        if self._wrapped_transport:
            self._wrapped_transport.sendto(data)
            self.packets_sent += 1
        elif self.transport:
            self.transport.sendto(data)
            self.packets_sent += 1


async def test_handshake_with_loss(hostname: str, port: int, loss_rate: float):
    """Test QUIC handshake with simulated packet loss."""
    print("=" * 70)
    print(f"Test: QUIC Handshake with {loss_rate*100:.0f}% Packet Loss")
    print("=" * 70)
    
    client = PacketLossQUICClient(
        hostname, port, 
        loss_rate=loss_rate,
        debug=True,
        keylog_file="test_keys.log"
    )
    
    try:
        await client.connect()
        
        print(f"\n[1] Starting QUIC handshake (loss rate: {loss_rate*100:.0f}%)...")
        start_time = time.time()
        
        # Use longer timeout since retransmission takes time
        success = await client.do_handshake(timeout=15.0)
        
        elapsed = time.time() - start_time
        
        if success:
            print(f"\n✅ Handshake SUCCEEDED in {elapsed:.2f}s")
            print(f"\n    === Loss Detection Stats ===")
            
            # Print loss detection statistics
            for space_name in ["INITIAL", "HANDSHAKE", "APPLICATION"]:
                from client.loss_detection import PacketNumberSpace
                space = PacketNumberSpace[space_name]
                stats = client.loss_detector.get_stats(space)
                if stats["packets_sent"] > 0:
                    print(f"    {space_name}:")
                    print(f"      Sent: {stats['packets_sent']}, Acked: {stats['packets_acked']}, Lost: {stats['packets_lost']}")
            
            # Print RTT stats
            rtt = client.loss_detector.rtt
            print(f"\n    === RTT Estimates ===")
            print(f"    Smoothed RTT: {rtt.smoothed_rtt*1000:.1f}ms")
            print(f"    Min RTT: {rtt.min_rtt*1000:.1f}ms" if rtt.min_rtt != float('inf') else "    Min RTT: N/A")
            print(f"    RTT Variance: {rtt.rttvar*1000:.1f}ms")
            
            if client.loss_protocol:
                print(f"\n    === Packet Loss Simulation ===")
                print(f"    Total sent: {client.loss_protocol.total_sent}")
                print(f"    Packets dropped: {client.loss_protocol.dropped_packets}")
                print(f"    Initial packets: {client.loss_protocol.initial_packets_sent}")
            
            # Try sending a request
            print(f"\n[2] Sending HTTP/3 request...")
            response = await client.request("GET", "/", timeout=10.0)
            
            if response.get("error"):
                print(f"    ❌ Request failed: {response['error']}")
            else:
                print(f"    ✅ Response status: {response.get('status')}")
                body = response.get("body", b"")
                print(f"    Body: {body[:100].decode('utf-8', errors='replace')}...")
            
            # Gracefully close
            client.send_connection_close()
            
        else:
            print(f"\n❌ Handshake FAILED after {elapsed:.2f}s")
            if client.loss_protocol:
                print(f"    Packets dropped: {client.loss_protocol.dropped_packets}")
        
        return success
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        client.close()


async def test_initial_packet_loss(hostname: str, port: int):
    """
    Test specific scenario: drop the first Initial packet.
    The client should retransmit and complete the handshake.
    """
    print("=" * 70)
    print("Test: Drop First Initial Packet (Force Retransmission)")
    print("=" * 70)
    
    client = PacketLossQUICClient(
        hostname, port, 
        loss_rate=0.0,  # We'll manually control which packets to drop
        debug=True,
        keylog_file="test_keys.log"
    )
    
    try:
        await client.connect()
        
        # Schedule the first packet to be dropped
        if client._wrapped_transport:
            client._wrapped_transport.drop_packet_n(1)  # Drop first packet
            print("\n    ⚠️ First packet scheduled to be DROPPED")
        
        print(f"\n[1] Starting QUIC handshake...")
        start_time = time.time()
        
        success = await client.do_handshake(timeout=15.0)
        
        elapsed = time.time() - start_time
        
        if success:
            print(f"\n✅ Handshake SUCCEEDED with retransmission in {elapsed:.2f}s")
            
            # Verify retransmission happened
            from client.loss_detection import PacketNumberSpace
            stats = client.loss_detector.get_stats(PacketNumberSpace.INITIAL)
            
            print(f"\n    === Initial Space Stats ===")
            print(f"    Packets sent: {stats['packets_sent']}")
            print(f"    Packets acked: {stats['packets_acked']}")
            
            if stats['packets_sent'] > 1:
                print(f"    ✅ Retransmission detected (sent {stats['packets_sent']} Initial packets)")
            
            # Send a request to verify connection works
            print(f"\n[2] Verifying connection with HTTP/3 request...")
            response = await client.request("GET", "/", timeout=10.0)
            
            if not response.get("error"):
                print(f"    ✅ Request succeeded, status: {response.get('status')}")
            
            client.send_connection_close()
            
        else:
            print(f"\n❌ Handshake FAILED")
        
        return success
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        client.close()


async def test_request_with_loss(hostname: str, port: int, loss_rate: float):
    """Test HTTP/3 request with simulated packet loss."""
    print("=" * 70)
    print(f"Test: HTTP/3 Request with {loss_rate*100:.0f}% Packet Loss")
    print("=" * 70)
    
    # First establish connection without loss
    client = PacketLossQUICClient(
        hostname, port, 
        loss_rate=0.0,  # No loss during handshake
        debug=True,
        keylog_file="test_keys.log"
    )
    
    try:
        await client.connect()
        
        print(f"\n[1] Establishing connection (no loss)...")
        success = await client.do_handshake(timeout=10.0)
        
        if not success:
            print("    ❌ Handshake failed")
            return False
        
        print(f"    ✅ Handshake complete")
        
        # Now enable packet loss for data transmission
        if client._wrapped_transport:
            client._wrapped_transport.loss_rate = loss_rate
            print(f"\n[2] Enabling {loss_rate*100:.0f}% packet loss for data...")
        
        print(f"\n[3] Sending HTTP/3 request with packet loss...")
        start_time = time.time()
        
        response = await client.request("GET", "/", timeout=15.0)
        
        elapsed = time.time() - start_time
        
        if response.get("error"):
            print(f"\n    ❌ Request failed: {response['error']}")
            print(f"    Time: {elapsed:.2f}s")
        else:
            print(f"\n    ✅ Request succeeded in {elapsed:.2f}s")
            print(f"    Status: {response.get('status')}")
            
            from client.loss_detection import PacketNumberSpace
            stats = client.loss_detector.get_stats(PacketNumberSpace.APPLICATION)
            print(f"\n    === Application Space Stats ===")
            print(f"    Packets sent: {stats['packets_sent']}")
            print(f"    Packets acked: {stats['packets_acked']}")
            print(f"    Packets lost: {stats['packets_lost']}")
        
        client.send_connection_close()
        return not response.get("error")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        client.close()


async def test_drop_every_packet_once(hostname: str, port: int):
    """
    Test scenario: Every packet is dropped on first send, requiring retransmission.
    This is an extreme test to verify the retransmission logic handles all cases.
    """
    print("=" * 70)
    print("Test: Drop Every Packet Once (Force Retransmission for All)")
    print("=" * 70)
    
    client = PacketLossQUICClient(
        hostname, port, 
        loss_rate=0.0,  # We'll use drop_every_packet_once mode
        debug=True,
        keylog_file="test_keys.log"
    )
    
    try:
        await client.connect()
        
        # Enable "drop every packet once" mode
        if client._wrapped_transport:
            client._wrapped_transport.enable_drop_every_packet_once()
        else:
            print("    ❌ Error: wrapped transport not available")
            return False
        
        print(f"\n[1] Starting QUIC handshake (every packet will be dropped once)...")
        start_time = time.time()
        
        # Use longer timeout since every packet needs retransmission
        success = await client.do_handshake(timeout=60.0)
        
        elapsed = time.time() - start_time
        
        if success:
            print(f"\n✅ Handshake SUCCEEDED in {elapsed:.2f}s")
            
            # Print drop-once statistics
            if client._wrapped_transport:
                stats = client._wrapped_transport.get_drop_once_stats()
                print(f"\n    === Drop-Every-Packet-Once Stats (Handshake) ===")
                print(f"    Packets attempted: {stats['packets_attempted']}")
                print(f"    Packets dropped: {stats['packets_dropped']}")
                print(f"    Packets actually sent: {stats['packets_sent']}")
            
            # Print loss detection statistics
            print(f"\n    === Loss Detection Stats ===")
            for space_name in ["INITIAL", "HANDSHAKE", "APPLICATION"]:
                from client.loss_detection import PacketNumberSpace
                space = PacketNumberSpace[space_name]
                stats = client.loss_detector.get_stats(space)
                if stats["packets_sent"] > 0:
                    print(f"    {space_name}:")
                    print(f"      Sent: {stats['packets_sent']}, Acked: {stats['packets_acked']}, Lost: {stats['packets_lost']}")
            
            # Print RTT stats
            rtt = client.loss_detector.rtt
            print(f"\n    === RTT Estimates ===")
            print(f"    Smoothed RTT: {rtt.smoothed_rtt*1000:.1f}ms")
            print(f"    Min RTT: {rtt.min_rtt*1000:.1f}ms" if rtt.min_rtt != float('inf') else "    Min RTT: N/A")
            
            # Now test with HTTP/3 request - also with drop-once
            print(f"\n[2] Sending HTTP/3 request (with drop-once)...")
            
            request_start = time.time()
            response = await client.request("GET", "/", timeout=60.0)
            request_elapsed = time.time() - request_start
            
            if response.get("error"):
                print(f"    ❌ Request failed: {response['error']}")
            else:
                print(f"    ✅ Response status: {response.get('status')} in {request_elapsed:.2f}s")
                body = response.get("body", b"")
                if body:
                    print(f"    Body preview: {body[:100].decode('utf-8', errors='replace')}...")
            
            # Print final statistics
            if client._wrapped_transport:
                stats = client._wrapped_transport.get_drop_once_stats()
                print(f"\n    === Final Drop-Once Stats ===")
                print(f"    Total packets attempted: {stats['packets_attempted']}")
                print(f"    Total packets dropped: {stats['packets_dropped']}")
                print(f"    Total packets sent: {stats['packets_sent']}")
            
            # Gracefully close
            client.send_connection_close()
            
        else:
            print(f"\n❌ Handshake FAILED after {elapsed:.2f}s")
            if client._wrapped_transport:
                stats = client._wrapped_transport.get_drop_once_stats()
                print(f"    Packets attempted: {stats['packets_attempted']}")
                print(f"    Packets dropped: {stats['packets_dropped']}")
                print(f"    Packets sent: {stats['packets_sent']}")
        
        return success
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        client.close()


async def test_drop_every_packet_once_handshake_only(hostname: str, port: int):
    """
    Test: Drop every packet once during handshake ONLY.
    After handshake, disable drop-once mode for normal request.
    """
    print("=" * 70)
    print("Test: Drop Every Packet Once (Handshake Only)")
    print("=" * 70)
    
    client = PacketLossQUICClient(
        hostname, port, 
        loss_rate=0.0,
        debug=True,
        keylog_file="test_keys.log"
    )
    
    try:
        await client.connect()
        
        # Enable "drop every packet once" mode for handshake
        if client._wrapped_transport:
            client._wrapped_transport.enable_drop_every_packet_once()
        else:
            print("    ❌ Error: wrapped transport not available")
            return False
        
        print(f"\n[1] Starting QUIC handshake (drop-once mode)...")
        start_time = time.time()
        
        success = await client.do_handshake(timeout=60.0)
        
        elapsed = time.time() - start_time
        
        if success:
            print(f"\n✅ Handshake SUCCEEDED in {elapsed:.2f}s")
            
            # Print drop-once statistics
            if client._wrapped_transport:
                stats = client._wrapped_transport.get_drop_once_stats()
                print(f"\n    === Handshake Drop Stats ===")
                print(f"    Packets attempted: {stats['packets_attempted']}")
                print(f"    Packets dropped: {stats['packets_dropped']}")
                print(f"    Packets sent: {stats['packets_sent']}")
                
                # Disable drop-once for request
                client._wrapped_transport.disable_drop_every_packet_once()
            
            # Send normal request
            print(f"\n[2] Sending HTTP/3 request (normal mode)...")
            
            request_start = time.time()
            response = await client.request("GET", "/", timeout=10.0)
            request_elapsed = time.time() - request_start
            
            if response.get("error"):
                print(f"    ❌ Request failed: {response['error']}")
            else:
                print(f"    ✅ Response status: {response.get('status')} in {request_elapsed:.2f}s")
                body = response.get("body", b"")
                if body:
                    print(f"    Body: {body[:200].decode('utf-8', errors='replace')}...")
            
            client.send_connection_close()
            
        else:
            print(f"\n❌ Handshake FAILED after {elapsed:.2f}s")
        
        return success
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        client.close()


async def test_incoming_packet_loss(hostname: str, port: int, incoming_loss_rate: float):
    """
    Test: Server -> Client packet loss (incoming).
    
    This tests the ACK ranges with gaps functionality.
    When server packets are lost, the client should:
    1. Report gaps in ACK frames
    2. Server should retransmit missing packets
    3. Client should reassemble data correctly
    """
    print("=" * 70)
    print(f"Test: INCOMING Packet Loss (Server -> Client) at {incoming_loss_rate*100:.0f}%")
    print("=" * 70)
    
    client = PacketLossQUICClient(
        hostname, port, 
        loss_rate=0.0,  # No outgoing loss
        incoming_loss_rate=incoming_loss_rate,  # Incoming loss
        debug=True,
        keylog_file="test_keys.log"
    )
    
    try:
        await client.connect()
        
        print(f"\n[1] Starting QUIC handshake (incoming loss: {incoming_loss_rate*100:.0f}%)...")
        start_time = time.time()
        
        success = await client.do_handshake(timeout=20.0)
        
        elapsed = time.time() - start_time
        
        if success:
            print(f"\n✅ Handshake SUCCEEDED in {elapsed:.2f}s")
            
            # Print incoming packet statistics
            if client.loss_protocol:
                stats = client.loss_protocol.get_incoming_stats()
                print(f"\n    === Incoming Packet Stats (Handshake) ===")
                print(f"    Total received from server: {stats['total_received']}")
                print(f"    Dropped (simulated loss): {stats['dropped_incoming']}")
                print(f"    Actually processed: {stats['processed']}")
            
            # Check ACK ranges to see if gaps were reported
            print(f"\n    === ACK Ranges (showing gaps) ===")
            for tracker_name, tracker in [
                ("Initial", client.initial_tracker),
                ("Handshake", client.handshake_tracker),
                ("Application", client.app_tracker)
            ]:
                ranges = tracker.get_ack_ranges()
                if ranges:
                    print(f"    {tracker_name}: {ranges}")
                    if len(ranges) > 1:
                        print(f"      ⚠️  {len(ranges)} ranges = {len(ranges)-1} gap(s) detected!")
            
            # Send HTTP/3 request
            print(f"\n[2] Sending HTTP/3 request...")
            response = await client.request("GET", "/", timeout=15.0)
            
            if response.get("error"):
                print(f"    ❌ Request failed: {response['error']}")
            else:
                print(f"    ✅ Response status: {response.get('status')}")
                body = response.get("body", b"")
                if body:
                    print(f"    Body: {body[:100].decode('utf-8', errors='replace')}...")
            
            # Final stats
            if client.loss_protocol:
                stats = client.loss_protocol.get_incoming_stats()
                print(f"\n    === Final Incoming Stats ===")
                print(f"    Total from server: {stats['total_received']}")
                print(f"    Dropped: {stats['dropped_incoming']}")
                print(f"    Processed: {stats['processed']}")
            
            client.send_connection_close()
            
        else:
            print(f"\n❌ Handshake FAILED after {elapsed:.2f}s")
            if client.loss_protocol:
                stats = client.loss_protocol.get_incoming_stats()
                print(f"    Incoming dropped: {stats['dropped_incoming']}")
        
        return success
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        client.close()


async def test_drop_incoming_every_packet_once(hostname: str, port: int):
    """
    Test: Drop every incoming packet once (alternating pattern).
    
    This is an extreme test where every server packet is dropped the first time,
    forcing the server to retransmit everything.
    """
    print("=" * 70)
    print("Test: Drop Every INCOMING Packet Once (Force Server Retransmission)")
    print("=" * 70)
    
    client = PacketLossQUICClient(
        hostname, port, 
        loss_rate=0.0,
        incoming_loss_rate=0.0,
        debug=True,
        keylog_file="test_keys.log"
    )
    
    try:
        await client.connect()
        
        # Enable drop-every-packet-once for incoming
        if client.loss_protocol:
            client.loss_protocol.enable_drop_incoming_every_packet_once()
        
        print(f"\n[1] Starting QUIC handshake (every incoming packet dropped once)...")
        start_time = time.time()
        
        success = await client.do_handshake(timeout=60.0)
        
        elapsed = time.time() - start_time
        
        if success:
            print(f"\n✅ Handshake SUCCEEDED in {elapsed:.2f}s")
            
            if client.loss_protocol:
                stats = client.loss_protocol.get_incoming_stats()
                print(f"\n    === Incoming Drop Stats ===")
                print(f"    Total from server: {stats['total_received']}")
                print(f"    Dropped: {stats['dropped_incoming']}")
                print(f"    Processed: {stats['processed']}")
            
            # Show ACK ranges
            print(f"\n    === ACK Ranges ===")
            for tracker_name, tracker in [
                ("Initial", client.initial_tracker),
                ("Handshake", client.handshake_tracker),
                ("Application", client.app_tracker)
            ]:
                ranges = tracker.get_ack_ranges()
                if ranges:
                    print(f"    {tracker_name}: {ranges}")
            
            # Disable drop-once for request
            if client.loss_protocol:
                client.loss_protocol.disable_drop_incoming_every_packet_once()
            
            # Send request
            print(f"\n[2] Sending HTTP/3 request (normal mode)...")
            response = await client.request("GET", "/", timeout=10.0)
            
            if response.get("error"):
                print(f"    ❌ Request failed: {response['error']}")
            else:
                print(f"    ✅ Response status: {response.get('status')}")
            
            client.send_connection_close()
            
        else:
            print(f"\n❌ Handshake FAILED after {elapsed:.2f}s")
        
        return success
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        client.close()


async def test_bidirectional_loss(hostname: str, port: int, loss_rate: float):
    """
    Test: Both outgoing AND incoming packet loss.
    
    This is the most realistic scenario simulating a lossy network.
    """
    print("=" * 70)
    print(f"Test: Bidirectional Packet Loss ({loss_rate*100:.0f}% each direction)")
    print("=" * 70)
    
    client = PacketLossQUICClient(
        hostname, port, 
        loss_rate=loss_rate,  # Outgoing
        incoming_loss_rate=loss_rate,  # Incoming
        debug=True,
        keylog_file="test_keys.log"
    )
    
    try:
        await client.connect()
        
        print(f"\n[1] Starting QUIC handshake (bidirectional {loss_rate*100:.0f}% loss)...")
        start_time = time.time()
        
        success = await client.do_handshake(timeout=30.0)
        
        elapsed = time.time() - start_time
        
        if success:
            print(f"\n✅ Handshake SUCCEEDED in {elapsed:.2f}s")
            
            if client.loss_protocol:
                print(f"\n    === Packet Loss Stats ===")
                print(f"    Outgoing dropped: {client.loss_protocol.dropped_packets}")
                print(f"    Incoming dropped: {client.loss_protocol.dropped_incoming}")
            
            # Send request
            print(f"\n[2] Sending HTTP/3 request...")
            response = await client.request("GET", "/", timeout=20.0)
            
            if response.get("error"):
                print(f"    ❌ Request failed: {response['error']}")
            else:
                print(f"    ✅ Response status: {response.get('status')}")
            
            client.send_connection_close()
            
        else:
            print(f"\n❌ Handshake FAILED after {elapsed:.2f}s")
        
        return success
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        client.close()


async def run_all_tests(hostname: str, port: int):
    """Run all packet loss tests."""
    results = []
    
    # Test 1: Handshake with 20% outgoing loss
    result = await test_handshake_with_loss(hostname, port, loss_rate=0.2)
    results.append(("Handshake with 20% outgoing loss", result))
    
    print("\n" + "=" * 70 + "\n")
    await asyncio.sleep(1)
    
    # Test 2: Drop first Initial packet
    result = await test_initial_packet_loss(hostname, port)
    results.append(("Drop first Initial packet", result))
    
    print("\n" + "=" * 70 + "\n")
    await asyncio.sleep(1)
    
    # Test 3: Request with 30% outgoing loss
    result = await test_request_with_loss(hostname, port, loss_rate=0.3)
    results.append(("Request with 30% outgoing loss", result))
    
    print("\n" + "=" * 70 + "\n")
    await asyncio.sleep(1)
    
    # Test 4: Incoming packet loss (server -> client)
    result = await test_incoming_packet_loss(hostname, port, incoming_loss_rate=0.3)
    results.append(("Incoming packet loss 30%", result))
    
    print("\n" + "=" * 70 + "\n")
    await asyncio.sleep(1)
    
    # Test 5: Bidirectional loss
    result = await test_bidirectional_loss(hostname, port, loss_rate=0.2)
    results.append(("Bidirectional 20% loss", result))
    
    print("\n" + "=" * 70 + "\n")
    await asyncio.sleep(1)
    
    # Test 6: Drop every outgoing packet once (handshake only)
    result = await test_drop_every_packet_once_handshake_only(hostname, port)
    results.append(("Drop every outgoing packet once (handshake)", result))
    
    print("\n" + "=" * 70 + "\n")
    await asyncio.sleep(1)
    
    # Test 7: Drop every incoming packet once
    result = await test_drop_incoming_every_packet_once(hostname, port)
    results.append(("Drop every incoming packet once", result))
    
    # Print summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"  {status}: {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    return passed == total


def main():
    parser = argparse.ArgumentParser(
        description="Test QUIC packet loss detection and recovery"
    )
    parser.add_argument(
        "hostname",
        nargs="?",
        default="api.tenclass.net",
        help="Target hostname (default: api.tenclass.net)"
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=443,
        help="Target port (default: 443)"
    )
    parser.add_argument(
        "--loss-rate",
        type=float,
        default=0.2,
        help="Simulated packet loss rate (default: 0.2 = 20%%)"
    )
    parser.add_argument(
        "--test",
        choices=[
            "all", "handshake", "initial", "request", 
            "drop-once", "drop-once-handshake",
            "incoming", "incoming-drop-once", "bidirectional"
        ],
        default="all",
        help="Which test to run (default: all)"
    )
    parser.add_argument(
        "--incoming-loss-rate",
        type=float,
        default=0.3,
        help="Simulated incoming packet loss rate (default: 0.3 = 30%%)"
    )
    
    args = parser.parse_args()
    
    print(f"QUIC Packet Loss Test")
    print(f"Target: {args.hostname}:{args.port}")
    if args.test not in ["drop-once", "drop-once-handshake", "incoming-drop-once"]:
        print(f"Outgoing Loss Rate: {args.loss_rate * 100:.0f}%")
        if args.test in ["incoming", "bidirectional"]:
            print(f"Incoming Loss Rate: {args.incoming_loss_rate * 100:.0f}%")
    print()
    
    try:
        if args.test == "all":
            asyncio.run(run_all_tests(args.hostname, args.port))
        elif args.test == "handshake":
            asyncio.run(test_handshake_with_loss(args.hostname, args.port, args.loss_rate))
        elif args.test == "initial":
            asyncio.run(test_initial_packet_loss(args.hostname, args.port))
        elif args.test == "request":
            asyncio.run(test_request_with_loss(args.hostname, args.port, args.loss_rate))
        elif args.test == "drop-once":
            asyncio.run(test_drop_every_packet_once(args.hostname, args.port))
        elif args.test == "drop-once-handshake":
            asyncio.run(test_drop_every_packet_once_handshake_only(args.hostname, args.port))
        elif args.test == "incoming":
            asyncio.run(test_incoming_packet_loss(args.hostname, args.port, args.incoming_loss_rate))
        elif args.test == "incoming-drop-once":
            asyncio.run(test_drop_incoming_every_packet_once(args.hostname, args.port))
        elif args.test == "bidirectional":
            asyncio.run(test_bidirectional_loss(args.hostname, args.port, args.loss_rate))
    except KeyboardInterrupt:
        print("\nTest interrupted")


if __name__ == "__main__":
    main()

