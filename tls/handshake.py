"""
TLS 1.3 Handshake Message Building and Parsing (RFC 8446)
"""

import os
import struct
import hashlib
from .constants import (
    TLS_AES_128_GCM_SHA256, HANDSHAKE_TYPE_NAMES, CIPHER_SUITE_NAMES,
    SIGNATURE_ALGORITHM_NAMES
)
from .extensions import (
    build_key_share_extension, build_supported_versions_extension,
    build_signature_algorithms_extension, build_supported_groups_extension,
    build_server_name_extension, build_alpn_extension, build_quic_transport_params,
    build_psk_key_exchange_modes_extension, build_early_data_extension,
    build_pre_shared_key_extension, compute_psk_binder,
    parse_tls_extensions
)
from .session import parse_new_session_ticket, SessionTicket


def build_client_hello(hostname: str, scid: bytes, x25519_public_key: bytes,
                       max_datagram_frame_size: int = 0) -> tuple:
    """
    Build complete TLS 1.3 ClientHello.
    
    Args:
        hostname: Server hostname for SNI
        scid: Source Connection ID for transport params
        x25519_public_key: Client's X25519 public key
        max_datagram_frame_size: Max DATAGRAM frame size to advertise (0 = disabled)
    
    Returns:
        tuple: (handshake_message, client_random)
    """
    # Build extensions
    extensions = b""
    extensions += build_key_share_extension(x25519_public_key)
    extensions += build_supported_versions_extension()
    extensions += build_signature_algorithms_extension()
    extensions += build_supported_groups_extension()
    extensions += build_server_name_extension(hostname)
    extensions += build_alpn_extension()
    extensions += build_quic_transport_params(scid, max_datagram_frame_size)
    # Add psk_key_exchange_modes to indicate we support session resumption
    extensions += build_psk_key_exchange_modes_extension()
    
    # Build ClientHello body
    client_random = os.urandom(32)  # Save for key logging
    client_hello = b""
    client_hello += struct.pack(">H", 0x0303)  # legacy_version: TLS 1.2
    client_hello += client_random              # random (32 bytes)
    client_hello += struct.pack("B", 0)         # session_id_length: 0
    
    # Cipher suites (just TLS_AES_128_GCM_SHA256)
    cipher_suites = struct.pack(">H", TLS_AES_128_GCM_SHA256)
    client_hello += struct.pack(">H", len(cipher_suites)) + cipher_suites
    
    # Compression methods (null only)
    client_hello += struct.pack("BB", 1, 0)  # length=1, method=null
    
    # Extensions
    client_hello += struct.pack(">H", len(extensions)) + extensions
    
    # Wrap in Handshake message
    handshake = struct.pack("B", 1)  # HandshakeType: ClientHello
    handshake += struct.pack(">I", len(client_hello))[1:]  # 3-byte length
    handshake += client_hello
    
    return handshake, client_random


def build_client_hello_with_psk(hostname: str, scid: bytes, x25519_public_key: bytes,
                                 session_ticket: SessionTicket, include_early_data: bool = True,
                                 max_datagram_frame_size: int = 0) -> tuple:
    """
    Build TLS 1.3 ClientHello with PSK extension for 0-RTT resumption.
    
    This is used when we have a valid session ticket and want to attempt 0-RTT.
    The pre_shared_key extension MUST be the last extension in ClientHello.
    
    Args:
        hostname: Server hostname for SNI
        scid: Source Connection ID for transport params
        x25519_public_key: Client's X25519 public key
        session_ticket: Session ticket for resumption
        include_early_data: Whether to include early_data extension for 0-RTT
        max_datagram_frame_size: Max DATAGRAM frame size to advertise (0 = disabled)
    
    Returns:
        tuple: (handshake_message, client_random, psk)
    """
    import time
    
    # Compute PSK from session ticket
    psk = session_ticket.compute_psk()
    
    # Calculate obfuscated ticket age
    current_time = time.time()
    obfuscated_age = session_ticket.get_obfuscated_ticket_age(current_time)
    
    # Build extensions (order matters!)
    # All extensions EXCEPT pre_shared_key first
    extensions = b""
    extensions += build_server_name_extension(hostname)
    extensions += build_supported_groups_extension()
    extensions += build_signature_algorithms_extension()
    extensions += build_key_share_extension(x25519_public_key)
    extensions += build_supported_versions_extension()
    extensions += build_alpn_extension()
    extensions += build_quic_transport_params(scid, max_datagram_frame_size)
    extensions += build_psk_key_exchange_modes_extension()
    
    # Include early_data extension if requested
    # In QUIC, we should include this when attempting 0-RTT, even if max_early_data_size=0
    # (some servers may support 0-RTT but not properly set the early_data extension in NewSessionTicket)
    if include_early_data:
        extensions += build_early_data_extension()
    
    # Build ClientHello body (without PSK extension and binder)
    client_random = os.urandom(32)
    client_hello_body = b""
    client_hello_body += struct.pack(">H", 0x0303)  # legacy_version: TLS 1.2
    client_hello_body += client_random
    client_hello_body += struct.pack("B", 0)  # session_id_length: 0
    
    # Cipher suites
    cipher_suites = struct.pack(">H", TLS_AES_128_GCM_SHA256)
    client_hello_body += struct.pack(">H", len(cipher_suites)) + cipher_suites
    
    # Compression methods
    client_hello_body += struct.pack("BB", 1, 0)  # length=1, method=null
    
    # Build PSK extension with placeholder binder
    psk_ext, binder_offset_in_ext = build_pre_shared_key_extension(
        session_ticket.ticket, obfuscated_age, binder_placeholder=True
    )
    
    # Calculate total extensions length
    total_ext_len = len(extensions) + len(psk_ext)
    
    # Build partial ClientHello for binder calculation
    # According to RFC 8446 Section 4.2.11.2:
    # "the binder is computed over the ClientHello[0..client_hello.length-len(binders)]"
    # This means we use the FINAL ClientHello length in the handshake header,
    # but the content is truncated to just before the binders field.
    
    # First, build the final ClientHello to get its length
    final_client_hello = client_hello_body + struct.pack(">H", total_ext_len) + extensions + psk_ext
    final_client_hello_length = len(final_client_hello)
    
    # PSK extension structure:
    # - type (2 bytes)
    # - ext_length (2 bytes)
    # - identities_len (2 bytes)
    # - identity (variable) = ticket_len(2) + ticket + age(4)
    # - binders_len (2 bytes)  <-- NOT included in transcript for binder
    # - binder_len (1 byte)    <-- NOT included in transcript for binder
    # - binder (32 bytes)      <-- NOT included in transcript for binder
    # Total binders section = 2 + 1 + 32 = 35 bytes
    binders_section_len = 35
    
    # Build partial ClientHello content (without binders)
    partial_client_hello = client_hello_body + struct.pack(">H", total_ext_len) + extensions
    psk_ext_up_to_identities = psk_ext[:-binders_section_len]
    partial_client_hello += psk_ext_up_to_identities
    
    # Build partial handshake message for transcript hash
    # IMPORTANT: Use the FINAL ClientHello length in the header
    partial_handshake = struct.pack("B", 1)  # ClientHello type
    partial_handshake += struct.pack(">I", final_client_hello_length)[1:]  # 3-byte length (FINAL length)
    partial_handshake += partial_client_hello  # But content is truncated
    
    # Compute transcript hash for binder
    transcript_hash = hashlib.sha256(partial_handshake).digest()
    
    # Compute binder
    binder = compute_psk_binder(psk, transcript_hash)
    
    # Replace placeholder binder with actual binder
    psk_ext_with_binder = psk_ext[:-32] + binder
    
    # Build final ClientHello
    final_client_hello = client_hello_body + struct.pack(">H", total_ext_len) + extensions + psk_ext_with_binder
    
    # Wrap in Handshake message
    handshake = struct.pack("B", 1)  # HandshakeType: ClientHello
    handshake += struct.pack(">I", len(final_client_hello))[1:]  # 3-byte length
    handshake += final_client_hello
    
    return handshake, client_random, psk


def parse_tls_handshake(data: bytes, debug: bool = False) -> list:
    """
    Parse TLS handshake messages.
    
    Args:
        data: Raw handshake data
        debug: Enable debug output
        
    Returns:
        list: List of parsed message dicts
    """
    messages = []
    offset = 0
    
    while offset < len(data):
        if offset + 4 > len(data):
            break
            
        msg_type = data[offset]
        length = struct.unpack(">I", b'\x00' + data[offset+1:offset+4])[0]
        
        # Check if we have the complete message
        # If not, stop parsing and wait for more data
        if offset + 4 + length > len(data):
            break
        
        msg_name = HANDSHAKE_TYPE_NAMES.get(msg_type, f"Unknown({msg_type})")
        msg_data = data[offset+4:offset+4+length]
        
        message = {
            "type": msg_name,
            "type_id": msg_type,
            "length": length,
        }
        
        # Parse ServerHello
        if msg_type == 2 and len(msg_data) >= 34:
            legacy_version = struct.unpack(">H", msg_data[0:2])[0]
            random = msg_data[2:34]
            message["legacy_version"] = f"0x{legacy_version:04x}"
            message["random"] = random.hex()
            
            session_id_len = msg_data[34]
            message["session_id_length"] = session_id_len
            if session_id_len > 0:
                message["session_id"] = msg_data[35:35+session_id_len].hex()
            
            idx = 35 + session_id_len
            if idx + 2 <= len(msg_data):
                cipher_suite = struct.unpack(">H", msg_data[idx:idx+2])[0]
                message["cipher_suite"] = CIPHER_SUITE_NAMES.get(cipher_suite, f"0x{cipher_suite:04x}")
                message["cipher_suite_raw"] = f"0x{cipher_suite:04x}"
                idx += 2
            
            # Compression method
            if idx < len(msg_data):
                message["compression_method"] = msg_data[idx]
                idx += 1
            
            # Extensions
            if idx + 2 <= len(msg_data):
                ext_len = struct.unpack(">H", msg_data[idx:idx+2])[0]
                message["extensions_length"] = ext_len
                idx += 2
                
                if idx + ext_len <= len(msg_data):
                    ext_data = msg_data[idx:idx+ext_len]
                    message["extensions"] = parse_tls_extensions(ext_data, is_server_hello=True)
        
        # Parse NewSessionTicket (type 4)
        elif msg_type == 4:
            ticket_info = parse_new_session_ticket(msg_data, debug)
            message["ticket_lifetime"] = ticket_info["ticket_lifetime"]
            message["ticket_age_add"] = ticket_info["ticket_age_add"]
            message["ticket_nonce"] = ticket_info["ticket_nonce"].hex()
            message["ticket_length"] = len(ticket_info["ticket"])
            message["ticket_preview"] = ticket_info["ticket"][:32].hex() + "..." if len(ticket_info["ticket"]) > 32 else ticket_info["ticket"].hex()
            message["max_early_data_size"] = ticket_info["max_early_data_size"]
            message["extensions"] = ticket_info["extensions"]
            message["session_ticket"] = ticket_info["session_ticket"]
        
        # Parse EncryptedExtensions (type 8)
        elif msg_type == 8 and len(msg_data) >= 2:
            ext_len = struct.unpack(">H", msg_data[0:2])[0]
            message["extensions_length"] = ext_len
            
            if 2 + ext_len <= len(msg_data):
                ext_data = msg_data[2:2+ext_len]
                message["extensions"] = parse_tls_extensions(ext_data, is_server_hello=False)
        
        # Parse Certificate (type 11)
        elif msg_type == 11 and len(msg_data) >= 4:
            # Certificate request context length (1 byte)
            context_len = msg_data[0]
            idx = 1 + context_len
            
            if idx + 3 <= len(msg_data):
                # Certificate list length (3 bytes)
                cert_list_len = struct.unpack(">I", b'\x00' + msg_data[idx:idx+3])[0]
                message["certificate_list_length"] = cert_list_len
                idx += 3
                
                # Parse certificates
                certs = []
                cert_idx = 0
                while idx < len(msg_data) and cert_idx < cert_list_len:
                    if idx + 3 > len(msg_data):
                        break
                    cert_len = struct.unpack(">I", b'\x00' + msg_data[idx:idx+3])[0]
                    idx += 3
                    cert_idx += 3
                    
                    if idx + cert_len <= len(msg_data):
                        cert_data = msg_data[idx:idx+cert_len]
                        certs.append({
                            "length": cert_len,
                            "data_preview": cert_data[:50].hex() + "..." if len(cert_data) > 50 else cert_data.hex()
                        })
                        idx += cert_len
                        cert_idx += cert_len
                        
                        # Certificate extensions length (2 bytes)
                        if idx + 2 <= len(msg_data):
                            cert_ext_len = struct.unpack(">H", msg_data[idx:idx+2])[0]
                            idx += 2 + cert_ext_len
                            cert_idx += 2 + cert_ext_len
                
                message["certificates"] = certs
                message["certificate_count"] = len(certs)
        
        # Parse CertificateVerify (type 15)
        elif msg_type == 15 and len(msg_data) >= 4:
            sig_algorithm = struct.unpack(">H", msg_data[0:2])[0]
            sig_len = struct.unpack(">H", msg_data[2:4])[0]
            
            message["signature_algorithm"] = SIGNATURE_ALGORITHM_NAMES.get(sig_algorithm, f"0x{sig_algorithm:04x}")
            message["signature_length"] = sig_len
            if 4 + sig_len <= len(msg_data):
                message["signature_preview"] = msg_data[4:4+min(32, sig_len)].hex() + "..."
        
        # Parse Finished (type 20)
        elif msg_type == 20:
            message["verify_data"] = msg_data.hex()
            message["verify_data_length"] = len(msg_data)
        
        messages.append(message)
        offset += 4 + length
    
    return messages

