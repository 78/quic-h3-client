#!/usr/bin/env python3
"""
QUIC DATAGRAM Test Script (RFC 9221)

This script demonstrates the DATAGRAM functionality:
1. Connect to a QUIC server with DATAGRAM enabled
2. Check if the server supports DATAGRAM
3. Send and receive DATAGRAM frames

Note: Not all servers support DATAGRAM. You need a server that:
- Advertises max_datagram_frame_size > 0 in transport parameters
- Actually handles DATAGRAM frames

Known servers that support DATAGRAM:
- Cloudflare (limited support)
- Custom servers with DATAGRAM enabled

Usage:
    python test_datagram.py [hostname] [port]
"""

import asyncio
import sys

# Add project root to path
sys.path.insert(0, '.')

from client import QuicConnection


async def test_datagram_connection(hostname: str, port: int):
    """
    Test DATAGRAM functionality with a QUIC server.
    """
    print(f"\n{'='*60}")
    print(f"QUIC DATAGRAM Test")
    print(f"{'='*60}")
    print(f"Target: {hostname}:{port}")
    print(f"{'='*60}\n")
    
    # Create connection with DATAGRAM enabled
    client = QuicConnection(
        hostname, port,
        debug=True,
        keylog_file="datagram_test.log",
        enable_datagram=True,  # Enable DATAGRAM support
        max_datagram_frame_size=65535  # Advertise max size
    )
    
    try:
        # Connect
        print("📡 Connecting...")
        await client.connect()
        
        # Handshake
        print("🤝 Performing handshake...")
        success = await client.do_handshake(timeout=10.0)
        
        if not success:
            print("❌ Handshake failed!")
            return False
        
        print("✅ Handshake complete!\n")
        
        # Check DATAGRAM support
        print(f"{'='*60}")
        print("DATAGRAM Support Status")
        print(f"{'='*60}")
        print(f"  Local enabled:     {client.datagram_enabled}")
        print(f"  Local max size:    {client.local_max_datagram_frame_size}")
        print(f"  Peer max size:     {client.peer_max_datagram_frame_size}")
        print(f"  DATAGRAM available: {client.datagram_available}")
        print(f"  Max sendable size: {client.max_datagram_size}")
        print()
        
        if not client.datagram_available:
            print("⚠️  Server does not support DATAGRAM!")
            print("    (max_datagram_frame_size not advertised by peer)")
            print()
            
            # Still try a normal HTTP/3 request to verify connection
            print("📤 Testing normal HTTP/3 request...")
            response = await client.request("GET", "/", timeout=5.0)
            if response.get("status"):
                print(f"✅ HTTP/3 request successful: {response['status']}")
            else:
                print(f"❌ HTTP/3 request failed: {response.get('error')}")
            
            return False
        
        # DATAGRAM is available - try to send one
        print("📦 DATAGRAM is supported! Sending test datagram...")
        
        test_data = b"Hello, DATAGRAM! This is a test message."
        
        if client.send_datagram(test_data):
            print(f"✅ Sent DATAGRAM: {len(test_data)} bytes")
            print(f"   Data: {test_data[:50]!r}...")
        else:
            print("❌ Failed to send DATAGRAM")
        
        # Try to receive a DATAGRAM (unlikely without a specific echo server)
        print("\n⏳ Waiting for DATAGRAM response (2 seconds)...")
        received = await client.recv_datagram(timeout=2.0)
        
        if received:
            print(f"📨 Received DATAGRAM: {len(received)} bytes")
            print(f"   Data: {received[:50]!r}...")
        else:
            print("   No DATAGRAM received (expected if server doesn't echo)")
        
        # Also test HTTP/3
        print("\n📤 Testing HTTP/3 request alongside DATAGRAM...")
        response = await client.request("GET", "/", timeout=5.0)
        if response.get("status"):
            print(f"✅ HTTP/3 request successful: {response['status']}")
            body_preview = response.get("body", b"")[:100]
            print(f"   Body preview: {body_preview}...")
        else:
            print(f"❌ HTTP/3 request failed: {response.get('error')}")
        
        print("\n✅ Test completed!")
        return True
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        # Graceful close
        print("\n🔌 Closing connection...")
        client.send_connection_close(0, "test complete")
        await asyncio.sleep(0.1)
        client.close()


async def test_datagram_api():
    """
    Test DATAGRAM API without connecting to a server.
    """
    print(f"\n{'='*60}")
    print("DATAGRAM API Unit Tests")
    print(f"{'='*60}\n")
    
    # Test 1: Create client with DATAGRAM disabled (default)
    client1 = QuicConnection("test.local", 443, debug=False)
    assert not client1.datagram_enabled, "DATAGRAM should be disabled by default"
    assert client1.local_max_datagram_frame_size == 0, "Max size should be 0 when disabled"
    print("✅ Test 1: DATAGRAM disabled by default")
    
    # Test 2: Create client with DATAGRAM enabled
    client2 = QuicConnection("test.local", 443, debug=False, enable_datagram=True)
    assert client2.datagram_enabled, "DATAGRAM should be enabled"
    assert client2.local_max_datagram_frame_size == 65535, "Default max size should be 65535"
    print("✅ Test 2: DATAGRAM enabled with default max size")
    
    # Test 3: Create client with custom max size
    client3 = QuicConnection("test.local", 443, debug=False, 
                             enable_datagram=True, max_datagram_frame_size=1200)
    assert client3.local_max_datagram_frame_size == 1200, "Custom max size should be 1200"
    print("✅ Test 3: DATAGRAM enabled with custom max size")
    
    # Test 4: can_send_datagram without peer support
    assert not client2.can_send_datagram(), "Should not be able to send without peer support"
    print("✅ Test 4: can_send_datagram returns False without peer support")
    
    # Test 5: datagram_available property
    assert not client2.datagram_available, "datagram_available should be False without peer"
    print("✅ Test 5: datagram_available property")
    
    print("\n✅ All API tests passed!")


async def main():
    # Run API tests first
    await test_datagram_api()
    
    # Get hostname and port from arguments
    hostname = sys.argv[1] if len(sys.argv) > 1 else "cloudflare-quic.com"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    
    # Run connection test
    await test_datagram_connection(hostname, port)


if __name__ == "__main__":
    asyncio.run(main())

