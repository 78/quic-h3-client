#!/usr/bin/env python3
"""
HTTP/3 Client - Main Entry Point

A QUIC/HTTP3 client implementation from scratch.
Supports:
- QUIC handshake with TLS 1.3
- HTTP/3 protocol initialization
- HTTP/3 request/response
- Concurrent HTTP/3 requests on a single connection
- Key logging for Wireshark (SSLKEYLOGFILE format)
- 0-RTT session resumption for faster subsequent connections

Usage:
    python main.py [options] [hostname]

Examples:
    # Single request (default)
    python main.py api.tenclass.net
    python main.py cloudflare-quic.com -p 443 --path /
    
    # Concurrent requests
    python main.py -c api.tenclass.net --paths /health /api/status
    
    # With custom keylog file
    python main.py api.tenclass.net -k my_keys.log
    
    # 0-RTT mode with session file
    python main.py --0rtt api.tenclass.net -s session.json
    
    # First connection (saves session ticket)
    python main.py api.tenclass.net -s session.json
    # Second connection (uses 0-RTT if possible)
    python main.py api.tenclass.net -s session.json
"""

import argparse
import asyncio
from client import RealtimeQUICClient


def print_response(path: str, response: dict):
    """Print HTTP/3 response in a formatted way."""
    print(f"\n    === Response for {path} ===")
    
    if response.get("error"):
        print(f"    ❌ Error: {response['error']}")
    else:
        print(f"    Status: {response.get('status')}")
        print(f"\n    Headers:")
        for name, value in response.get("headers", []):
            print(f"      {name}: {value}")
        
        body = response.get("body", b"")
        print(f"\n    Body ({len(body)} bytes):")
        try:
            body_text = body.decode('utf-8')
            # Pretty print if it looks like JSON
            if body_text.strip().startswith('{') or body_text.strip().startswith('['):
                import json
                try:
                    parsed = json.loads(body_text)
                    print(f"      {json.dumps(parsed, indent=6, ensure_ascii=False)}")
                except:
                    print(f"      {body_text[:500]}")
            else:
                print(f"      {body_text[:500]}")
            if len(body_text) > 500:
                print(f"      ... ({len(body_text) - 500} more bytes)")
        except:
            print(f"      (binary) {body[:100].hex()}")


async def http3_concurrent_requests(hostname: str, port: int, paths: list,
                                    debug: bool = True, keylog_file: str = None,
                                    session_file: str = None):
    """
    Perform QUIC handshake and send multiple concurrent HTTP/3 requests.
    
    Args:
        hostname: Target hostname
        port: Target port
        paths: List of request paths (e.g., ["/health", "/api/status"])
        debug: Enable debug output
        keylog_file: Path to write keys in SSLKEYLOGFILE format for Wireshark
        session_file: Path to session file for 0-RTT
    """
    print("=" * 60)
    print("HTTP/3 Concurrent Requests Test")
    print("=" * 60)
    
    if keylog_file:
        print(f"    Key log file: {keylog_file}")
    if session_file:
        print(f"    Session file: {session_file}")
    
    print(f"\n[1] Connecting to {hostname}:{port}...")
    client = RealtimeQUICClient(hostname, port, debug=debug, keylog_file=keylog_file,
                                 session_file=session_file)
    
    try:
        await client.connect()
        
        print(f"\n[2] Starting QUIC handshake...")
        success = await client.do_handshake(timeout=5.0)
        
        if success:
            print(f"\n[3] Handshake result: SUCCESS ✅")
            
            # Print handshake summary
            print(f"\n    === Handshake Summary ===")
            print(f"    Initial packets received: {len(client.initial_tracker.received_pns)}")
            print(f"    Handshake packets received: {len(client.handshake_tracker.received_pns)}")
            print(f"    Initial CRYPTO: {client.initial_crypto_buffer.total_received} bytes")
            print(f"    Handshake CRYPTO: {client.handshake_crypto_buffer.total_received} bytes")
            
            # Send concurrent HTTP/3 requests
            print(f"\n[4] Sending {len(paths)} concurrent HTTP/3 GET requests...")
            print("-" * 40)
            for path in paths:
                print(f"    - {path}")
            print("-" * 40)
            
            import time
            start_time = time.time()
            
            # Create concurrent request tasks
            async def make_request(path: str):
                return path, await client.request(
                    method="GET",
                    path=path,
                    headers={"accept": "*/*"},
                    timeout=10.0
                )
            
            # Execute all requests concurrently
            tasks = [make_request(path) for path in paths]
            results = await asyncio.gather(*tasks)
            
            elapsed = time.time() - start_time
            
            # Print all responses
            print(f"\n[5] HTTP/3 Responses (completed in {elapsed:.3f}s):")
            print("-" * 40)
            
            for path, response in results:
                print_response(path, response)
            
            # Send CONNECTION_CLOSE to gracefully close the connection
            print(f"\n[6] Closing connection...")
            print("-" * 40)
            client.send_connection_close()
            
        else:
            print(f"\n[3] Handshake result: FAILED ❌")
            
    except KeyboardInterrupt:
        print(f"\n\n[!] Ctrl+C received, exiting...")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Print final statistics
        print(f"\n    === Final Statistics ===")
        print(f"    UDP packets received: {client.packets_received}")
        print(f"    Bytes received: {client.bytes_received}")
        print(f"    Packets sent: {client.packets_sent}")
        print(f"    Initial packets: {len(client.initial_tracker.received_pns)}")
        print(f"    Handshake packets: {len(client.handshake_tracker.received_pns)}")
        print(f"    1-RTT packets: {len(client.app_tracker.received_pns)}")
        client.close()
    
    print("\n" + "=" * 60)
    return client


async def http3_request(hostname: str, port: int, path: str = "/", 
                        debug: bool = True, keylog_file: str = None,
                        session_file: str = None, force_0rtt: bool = False):
    """
    Perform QUIC handshake and send an HTTP/3 request.
    
    Args:
        hostname: Target hostname
        port: Target port
        path: Request path (e.g., "/health", "/api/status")
        debug: Enable debug output
        keylog_file: Path to write keys in SSLKEYLOGFILE format for Wireshark
        session_file: Path to session file for 0-RTT
    """
    print("=" * 60)
    print("HTTP/3 Client")
    print("=" * 60)
    
    if keylog_file:
        print(f"    Key log file: {keylog_file}")
    if session_file:
        print(f"    Session file: {session_file}")
    
    print(f"\n[1] Connecting to {hostname}:{port}...")
    client = RealtimeQUICClient(hostname, port, debug=debug, keylog_file=keylog_file,
                                 session_file=session_file)
    
    try:
        await client.connect()
        
        print(f"\n[2] Starting QUIC handshake...")
        success = await client.do_handshake(timeout=5.0, force_0rtt=force_0rtt)
        
        if success:
            print(f"\n[3] Handshake result: SUCCESS ✅")
            
            # Print handshake summary
            print(f"\n    === Handshake Summary ===")
            print(f"    Initial packets received: {len(client.initial_tracker.received_pns)}")
            print(f"    Handshake packets received: {len(client.handshake_tracker.received_pns)}")
            print(f"    Initial CRYPTO: {client.initial_crypto_buffer.total_received} bytes")
            print(f"    Handshake CRYPTO: {client.handshake_crypto_buffer.total_received} bytes")
            if client.zero_rtt_enabled:
                if client.zero_rtt_accepted:
                    print(f"    0-RTT: ✅ ACCEPTED by server")
                elif client.zero_rtt_rejected:
                    print(f"    0-RTT: ❌ REJECTED by server (fallback to 1-RTT)")
                else:
                    print(f"    0-RTT: ⏳ pending")
            
            # Send HTTP/3 request
            print(f"\n[4] Sending HTTP/3 GET request to {path}...")
            print("-" * 40)
            
            response = await client.request(
                method="GET",
                path=path,
                headers={
                    "accept": "*/*",
                },
                timeout=10.0
            )
            
            # Print response
            print(f"\n[5] HTTP/3 Response:")
            print("-" * 40)
            print_response(path, response)
            
            # Wait a bit for NewSessionTicket before closing
            if session_file:
                print(f"\n[6] Waiting for session ticket...")
                print("-" * 40)
                await asyncio.sleep(0.5)  # Give server time to send NewSessionTicket
                if client.session_tickets:
                    print(f"    ✅ Received {len(client.session_tickets)} session ticket(s)")
                    for i, ticket in enumerate(client.session_tickets):
                        print(f"       [{i+1}] lifetime={ticket.ticket_lifetime}s, max_early_data={ticket.max_early_data_size}")
                else:
                    print(f"    ⚠️ No session tickets received (server may not support 0-RTT)")
            
            # Send CONNECTION_CLOSE to gracefully close the connection
            print(f"\n[7] Closing connection...")
            print("-" * 40)
            client.send_connection_close()
            
        else:
            print(f"\n[3] Handshake result: FAILED ❌")
            
    except KeyboardInterrupt:
        print(f"\n\n[!] Ctrl+C received, exiting...")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Print final statistics
        print(f"\n    === Final Statistics ===")
        print(f"    UDP packets received: {client.packets_received}")
        print(f"    Bytes received: {client.bytes_received}")
        print(f"    Packets sent: {client.packets_sent}")
        print(f"    Initial packets: {len(client.initial_tracker.received_pns)}")
        print(f"    Handshake packets: {len(client.handshake_tracker.received_pns)}")
        print(f"    1-RTT packets: {len(client.app_tracker.received_pns)}")
        if session_file and client.session_tickets:
            print(f"    Session tickets: {len(client.session_tickets)}")
        client.close()
    
    print("\n" + "=" * 60)
    return client


async def http3_0rtt_request(hostname: str, port: int, path: str = "/",
                             debug: bool = True, keylog_file: str = None,
                             session_file: str = None):
    """
    Perform 0-RTT HTTP/3 request with session resumption.
    
    This function:
    1. Loads a valid session ticket (if available)
    2. Sends the request in 0-RTT early data
    3. Completes the handshake in parallel
    
    Args:
        hostname: Target hostname
        port: Target port
        path: Request path
        debug: Enable debug output
        keylog_file: Path to write keys
        session_file: Path to session file (required for 0-RTT)
    """
    print("=" * 60)
    print("HTTP/3 0-RTT Client")
    print("=" * 60)
    
    if not session_file:
        print("    ❌ Error: Session file is required for 0-RTT mode")
        print("    Use -s/--session to specify a session file")
        return None
    
    if keylog_file:
        print(f"    Key log file: {keylog_file}")
    print(f"    Session file: {session_file}")
    
    print(f"\n[1] Connecting to {hostname}:{port} with 0-RTT...")
    client = RealtimeQUICClient(hostname, port, debug=debug, keylog_file=keylog_file,
                                 session_file=session_file)
    
    try:
        await client.connect()
        
        print(f"\n[2] Sending 0-RTT HTTP/3 GET request to {path}...")
        print("-" * 40)
        
        import time
        start_time = time.time()
        
        response = await client.request_0rtt(
            method="GET",
            path=path,
            headers={"accept": "*/*"},
            timeout=10.0
        )
        
        elapsed = time.time() - start_time
        
        # Print response
        print(f"\n[3] HTTP/3 Response (completed in {elapsed:.3f}s):")
        print("-" * 40)
        
        if response.get("0rtt"):
            if response.get("0rtt_accepted"):
                print(f"    🎉 0-RTT was ACCEPTED by server!")
            else:
                print(f"    ⚠️ 0-RTT was REJECTED (fallback to 1-RTT)")
        else:
            print(f"    ℹ️ Used normal 1-RTT (no valid session ticket)")
        
        print_response(path, response)
        
        # Send CONNECTION_CLOSE
        print(f"\n[4] Closing connection...")
        print("-" * 40)
        client.send_connection_close()
        
    except KeyboardInterrupt:
        print(f"\n\n[!] Ctrl+C received, exiting...")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Print final statistics
        print(f"\n    === Final Statistics ===")
        print(f"    UDP packets received: {client.packets_received}")
        print(f"    Bytes received: {client.bytes_received}")
        print(f"    Packets sent: {client.packets_sent}")
        print(f"    0-RTT enabled: {client.zero_rtt_enabled}")
        if client.zero_rtt_enabled:
            print(f"    0-RTT accepted: {client.zero_rtt_accepted}")
        client.close()
    
    print("\n" + "=" * 60)
    return client


async def realtime_quic_handshake(hostname: str, port: int, debug: bool = True, keylog_file: str = None):
    """
    Perform QUIC handshake with real-time packet processing.
    After handshake, continues to receive and process messages until Ctrl+C.
    (Legacy mode - for debugging only)
    
    Args:
        hostname: Target hostname
        port: Target port
        debug: Enable debug output
        keylog_file: Path to write keys in SSLKEYLOGFILE format for Wireshark
    """
    print("=" * 60)
    print("QUIC Realtime Client (Legacy Mode)")
    print("=" * 60)
    
    if keylog_file:
        print(f"    Key log file: {keylog_file}")
    
    print(f"\n[1] Connecting to {hostname}:{port}...")
    client = RealtimeQUICClient(hostname, port, debug=debug, keylog_file=keylog_file)
    
    try:
        await client.connect()
        
        print(f"\n[2] Starting handshake...")
        success = await client.do_handshake(timeout=5.0)
        
        if success:
            print(f"\n[3] Handshake result: SUCCESS ✅")
            
            # Print summary
            print(f"\n    === Handshake Summary ===")
            print(f"    Initial packets received: {len(client.initial_tracker.received_pns)}")
            print(f"    Handshake packets received: {len(client.handshake_tracker.received_pns)}")
            print(f"    Initial CRYPTO: {client.initial_crypto_buffer.total_received} bytes")
            print(f"    Handshake CRYPTO: {client.handshake_crypto_buffer.total_received} bytes")
            
            # Continue receiving messages until Ctrl+C
            print(f"\n[4] Receiving messages (press Ctrl+C to exit)...")
            print("-" * 40)
            
            try:
                while True:
                    await asyncio.sleep(0.1)
            except asyncio.CancelledError:
                pass
            
        else:
            print(f"\n[3] Handshake result: FAILED ❌")
            
    except KeyboardInterrupt:
        print(f"\n\n[!] Ctrl+C received, exiting...")
    finally:
        # Print final statistics
        print(f"\n    === Final Statistics ===")
        print(f"    UDP packets received: {client.packets_received}")
        print(f"    Bytes received: {client.bytes_received}")
        print(f"    Packets sent: {client.packets_sent}")
        print(f"    Initial packets: {len(client.initial_tracker.received_pns)}")
        print(f"    Handshake packets: {len(client.handshake_tracker.received_pns)}")
        print(f"    1-RTT packets: {len(client.app_tracker.received_pns)}")
        client.close()
    
    print("\n" + "=" * 60)
    return client


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="HTTP/3 Client - A QUIC/HTTP3 client implementation with 0-RTT support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single request
  python main.py api.tenclass.net
  python main.py cloudflare-quic.com -p 443 --path /
  
  # Concurrent requests
  python main.py -c api.tenclass.net --paths /health /api/status
  
  # With custom keylog file
  python main.py api.tenclass.net -k my_keys.log
  
  # With session file (enables session resumption)
  python main.py api.tenclass.net -s session.json
  
  # 0-RTT mode (requires session file)
  # First run: saves session ticket
  python main.py api.tenclass.net -s session.json
  # Second run: uses 0-RTT
  python main.py --0rtt api.tenclass.net -s session.json
  
  # Quiet mode (less output)
  python main.py api.tenclass.net -q
"""
    )
    
    # Positional argument
    parser.add_argument(
        "hostname",
        nargs="?",
        default="api.tenclass.net",
        help="Target hostname (default: api.tenclass.net)"
    )
    
    # Optional arguments
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=443,
        help="Target port (default: 443)"
    )
    
    parser.add_argument(
        "--path",
        default="/health",
        help="Request path for single request mode (default: /health)"
    )
    
    parser.add_argument(
        "-c", "--concurrent",
        action="store_true",
        help="Enable concurrent requests mode"
    )
    
    parser.add_argument(
        "--paths",
        nargs="+",
        default=["/health", "/"],
        help="Request paths for concurrent mode (default: /health /)"
    )
    
    parser.add_argument(
        "-k", "--keylog",
        default="quic_keys.log",
        help="Key log file path for Wireshark (default: quic_keys.log)"
    )
    
    parser.add_argument(
        "-s", "--session",
        default=None,
        help="Session file path for session resumption and 0-RTT (default: None)"
    )
    
    parser.add_argument(
        "--0rtt",
        dest="zero_rtt",
        action="store_true",
        help="Enable 0-RTT mode (requires --session)"
    )
    
    parser.add_argument(
        "--force-0rtt",
        dest="force_zero_rtt",
        action="store_true",
        help="Force 0-RTT even if server's max_early_data=0 (for testing)"
    )
    
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Disable debug output"
    )
    
    args = parser.parse_args()
    
    # Extract values
    hostname = args.hostname
    port = args.port
    path = args.path
    keylog_file = args.keylog
    session_file = args.session
    concurrent_mode = args.concurrent
    zero_rtt_mode = args.zero_rtt
    force_zero_rtt = args.force_zero_rtt
    paths = args.paths
    debug = not args.quiet
    
    print(f"HTTP/3 Client - Keys will be written to {keylog_file} (Wireshark SSLKEYLOGFILE format)")
    
    if zero_rtt_mode:
        print(f"Mode: 0-RTT REQUEST")
        if not session_file:
            print("⚠️ Warning: 0-RTT mode requires --session option")
    elif force_zero_rtt:
        print(f"Mode: FORCE 0-RTT (testing mode)")
        if not session_file:
            print("⚠️ Warning: --force-0rtt requires --session option")
    elif concurrent_mode:
        print(f"Mode: CONCURRENT REQUESTS")
        print(f"Target: https://{hostname}:{port}")
        print(f"Paths: {', '.join(paths)}")
    else:
        print(f"Mode: SINGLE REQUEST")
        print(f"Target: https://{hostname}:{port}{path}")
    
    if session_file:
        print(f"Session file: {session_file}")
    
    print(f"Press Ctrl+C to exit\n")
    
    try:
        if zero_rtt_mode:
            asyncio.run(http3_0rtt_request(hostname, port, path, debug=debug, 
                                           keylog_file=keylog_file, session_file=session_file))
        elif concurrent_mode:
            asyncio.run(http3_concurrent_requests(hostname, port, paths, debug=debug, 
                                                   keylog_file=keylog_file, session_file=session_file))
        else:
            asyncio.run(http3_request(hostname, port, path, debug=debug, 
                                       keylog_file=keylog_file, session_file=session_file,
                                       force_0rtt=force_zero_rtt))
    except KeyboardInterrupt:
        print("\nProgram exited")


if __name__ == "__main__":
    main()

