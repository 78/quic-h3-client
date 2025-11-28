"""
QUIC Packet Builders (RFC 9000)
"""

import os
import struct
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

from ..constants import QUIC_VERSION
from ..varint import encode_varint
from ..crypto.keys import derive_initial_secrets
from ..crypto.aead import encrypt_payload, apply_header_protection
from ..frames.builders import build_crypto_frame, build_padding_frame


def build_initial_packet(dcid: bytes, scid: bytes, packet_number: int, 
                         payload: bytes, token: bytes = b"", 
                         debug: bool = False) -> bytes:
    """
    Build complete QUIC Initial packet with automatic key derivation.
    
    Args:
        dcid: Destination Connection ID
        scid: Source Connection ID
        packet_number: Packet number
        payload: Plaintext payload (frames)
        token: Optional Retry Token from server (for address validation)
        debug: Enable debug output
        
    Returns:
        bytes: Complete encrypted Initial packet
    """
    # Derive secrets
    secrets = derive_initial_secrets(dcid)
    
    if debug:
        print(f"  [DEBUG] Client key: {secrets['key'].hex()}")
        print(f"  [DEBUG] Client iv: {secrets['iv'].hex()}")
        print(f"  [DEBUG] Client hp: {secrets['hp'].hex()}")
    
    # Determine packet number length (use 2 bytes)
    pn_length = 2
    
    # Build unprotected header
    # First byte: 1100 0001 (Long header, Initial, PN length = 2)
    first_byte = 0xc0 | (0 << 4) | (pn_length - 1)  # Initial packet type = 0
    
    header = struct.pack("B", first_byte)
    header += struct.pack(">I", QUIC_VERSION)
    header += struct.pack("B", len(dcid)) + dcid
    header += struct.pack("B", len(scid)) + scid
    header += encode_varint(len(token))  # Token length
    if token:
        header += token  # Include Retry Token
    
    # Calculate length field (packet number + payload + auth tag)
    encrypted_length = pn_length + len(payload) + 16
    header += encode_varint(encrypted_length)
    
    # Packet number
    pn_offset = len(header)
    header += struct.pack(">H", packet_number)  # 2-byte packet number
    
    if debug:
        print(f"  [DEBUG] Header before encryption ({len(header)} bytes): {header.hex()}")
        print(f"  [DEBUG] Payload length: {len(payload)} bytes")
        print(f"  [DEBUG] PN offset: {pn_offset}")
        if token:
            print(f"  [DEBUG] Retry Token ({len(token)} bytes): {token.hex()}")
    
    # Encrypt payload
    encrypted_payload = encrypt_payload(secrets, packet_number, header, payload)
    
    if debug:
        print(f"  [DEBUG] Encrypted payload length: {len(encrypted_payload)} bytes")
    
    # Apply header protection
    protected_header = apply_header_protection(
        secrets, header, encrypted_payload, pn_offset, pn_length
    )
    
    if debug:
        print(f"  [DEBUG] Protected header: {protected_header.hex()}")
    
    return protected_header + encrypted_payload


def build_initial_packet_with_secrets(secrets: dict, dcid: bytes, scid: bytes,
                                      packet_number: int, payload: bytes,
                                      debug: bool = False) -> bytes:
    """
    Build complete QUIC Initial packet using provided secrets.
    
    Args:
        secrets: Pre-derived secrets {key, iv, hp}
        dcid: Destination Connection ID
        scid: Source Connection ID
        packet_number: Packet number
        payload: Plaintext payload
        debug: Enable debug output
        
    Returns:
        bytes: Complete encrypted Initial packet
    """
    if debug:
        print(f"  [DEBUG] Client key: {secrets['key'].hex()}")
        print(f"  [DEBUG] Client iv: {secrets['iv'].hex()}")
        print(f"  [DEBUG] Client hp: {secrets['hp'].hex()}")
    
    # Determine packet number length (use 1 byte for ACK packets)
    pn_length = 1
    
    # Build unprotected header
    first_byte = 0xc0 | (0 << 4) | (pn_length - 1)  # Initial packet type = 0
    
    header = struct.pack("B", first_byte)
    header += struct.pack(">I", QUIC_VERSION)
    header += struct.pack("B", len(dcid)) + dcid
    header += struct.pack("B", len(scid)) + scid
    header += encode_varint(0)  # Token length = 0
    
    # Calculate length field
    encrypted_length = pn_length + len(payload) + 16
    header += encode_varint(encrypted_length)
    
    # Packet number
    pn_offset = len(header)
    header += struct.pack("B", packet_number & 0xFF)  # 1-byte packet number
    
    # Encrypt payload
    encrypted_payload = encrypt_payload(secrets, packet_number, header, payload)
    
    # Apply header protection
    protected_header = apply_header_protection(
        secrets, header, encrypted_payload, pn_offset, pn_length
    )
    
    return protected_header + encrypted_payload


def build_handshake_packet(secrets: dict, dcid: bytes, scid: bytes,
                           packet_number: int, payload: bytes,
                           debug: bool = False) -> bytes:
    """
    Build complete QUIC Handshake packet.
    
    Args:
        secrets: Handshake encryption secrets {key, iv, hp}
        dcid: Destination Connection ID
        scid: Source Connection ID
        packet_number: Packet number
        payload: Plaintext payload
        debug: Enable debug output
        
    Returns:
        bytes: Complete encrypted Handshake packet
    """
    if debug:
        print(f"  [DEBUG] Client HS key: {secrets['key'].hex()}")
        print(f"  [DEBUG] Client HS iv: {secrets['iv'].hex()}")
        print(f"  [DEBUG] Client HS hp: {secrets['hp'].hex()}")
    
    # Determine packet number length (use 1 byte for ACK packets)
    pn_length = 1
    
    # Build unprotected header
    # First byte: 1110 0000 (Long header, Handshake, PN length = 1)
    first_byte = 0xc0 | (2 << 4) | (pn_length - 1)  # Handshake packet type = 2
    
    header = struct.pack("B", first_byte)
    header += struct.pack(">I", QUIC_VERSION)
    header += struct.pack("B", len(dcid)) + dcid
    header += struct.pack("B", len(scid)) + scid
    
    # No token field for Handshake packets
    
    # Calculate length field
    encrypted_length = pn_length + len(payload) + 16
    header += encode_varint(encrypted_length)
    
    # Packet number
    pn_offset = len(header)
    header += struct.pack("B", packet_number & 0xFF)  # 1-byte packet number
    
    if debug:
        print(f"  [DEBUG] HS Header before encryption ({len(header)} bytes): {header.hex()}")
    
    # Encrypt payload
    encrypted_payload = encrypt_payload(secrets, packet_number, header, payload)
    
    # Apply header protection
    protected_header = apply_header_protection(
        secrets, header, encrypted_payload, pn_offset, pn_length
    )
    
    return protected_header + encrypted_payload


def create_initial_packet(hostname: str, debug: bool = False,
                          max_datagram_frame_size: int = 0) -> tuple:
    """
    Create complete QUIC Initial packet with ClientHello.
    
    This is the entry point for starting a QUIC connection.
    
    Args:
        hostname: Target hostname for SNI
        debug: Enable debug output
        max_datagram_frame_size: Max DATAGRAM frame size to advertise (0 = disabled)
        
    Returns:
        tuple: (packet, dcid, scid, private_key, client_hello, client_random)
    """
    # Import here to avoid circular dependency
    from tls.handshake import build_client_hello
    
    # Generate random connection IDs
    dcid = os.urandom(8)  # Destination Connection ID
    scid = os.urandom(8)  # Source Connection ID
    
    # Generate X25519 key pair
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    # Build ClientHello
    client_hello, client_random = build_client_hello(
        hostname, scid, public_key, max_datagram_frame_size
    )
    
    if debug:
        print(f"  [DEBUG] ClientHello length: {len(client_hello)} bytes")
    
    # Build CRYPTO frame
    crypto_frame = build_crypto_frame(0, client_hello)
    
    if debug:
        print(f"  [DEBUG] CRYPTO frame length: {len(crypto_frame)} bytes")
    
    # Calculate exact header size for padding
    header_base_size = 1 + 4 + 1 + len(dcid) + 1 + len(scid) + 1  # token len=0 is 1 byte
    auth_tag_size = 16
    pn_length = 2
    min_packet_size = 1200
    length_field_size = 2
    
    # Available space for payload
    available_for_payload = min_packet_size - header_base_size - length_field_size - pn_length - auth_tag_size
    
    padding_needed = available_for_payload - len(crypto_frame)
    if padding_needed > 0:
        crypto_frame += build_padding_frame(padding_needed)
    
    if debug:
        print(f"  [DEBUG] Total payload (with padding): {len(crypto_frame)} bytes")
    
    # Build Initial packet
    packet = build_initial_packet(dcid, scid, 0, crypto_frame, debug=debug)

    if debug:
        print(f"  [DEBUG] Initial packet length: {len(packet)} bytes")
    
    # Ensure packet is at least 1200 bytes
    if len(packet) < 1200:
        extra_padding = 1200 - len(packet)
        if debug:
            print(f"  [DEBUG] Adding extra padding: {extra_padding} bytes")
        crypto_frame += build_padding_frame(extra_padding)
        packet = build_initial_packet(dcid, scid, 0, crypto_frame, debug=debug)
    
    return packet, dcid, scid, private_key, client_hello, client_random


def build_0rtt_packet(secrets: dict, dcid: bytes, scid: bytes,
                      packet_number: int, payload: bytes,
                      debug: bool = False) -> bytes:
    """
    Build complete QUIC 0-RTT packet.
    
    0-RTT packets are Long Header packets with packet type = 1 (0x01).
    They carry early data encrypted with 0-RTT keys.
    
    Args:
        secrets: 0-RTT encryption secrets {key, iv, hp}
        dcid: Destination Connection ID
        scid: Source Connection ID
        packet_number: Packet number
        payload: Plaintext payload
        debug: Enable debug output
        
    Returns:
        bytes: Complete encrypted 0-RTT packet
    """
    if debug:
        print(f"  [DEBUG] Client 0-RTT key: {secrets['key'].hex()}")
        print(f"  [DEBUG] Client 0-RTT iv: {secrets['iv'].hex()}")
        print(f"  [DEBUG] Client 0-RTT hp: {secrets['hp'].hex()}")
    
    # Determine packet number length (use 1 byte for short packet numbers)
    if packet_number < 0x100:
        pn_length = 1
    elif packet_number < 0x10000:
        pn_length = 2
    else:
        pn_length = 4
    
    # Build unprotected header
    # First byte: 1101 XXXX (Long header, 0-RTT type = 1)
    # Bits: Form(1) + Fixed(1) + Type(2) + Reserved(2) + PN Length(2)
    first_byte = 0xc0 | (1 << 4) | (pn_length - 1)  # 0-RTT packet type = 1
    
    header = struct.pack("B", first_byte)
    header += struct.pack(">I", QUIC_VERSION)
    header += struct.pack("B", len(dcid)) + dcid
    header += struct.pack("B", len(scid)) + scid
    
    # Calculate length field
    encrypted_length = pn_length + len(payload) + 16  # +16 for auth tag
    header += encode_varint(encrypted_length)
    
    # Packet number
    pn_offset = len(header)
    if pn_length == 1:
        header += struct.pack("B", packet_number & 0xFF)
    elif pn_length == 2:
        header += struct.pack(">H", packet_number)
    else:
        header += struct.pack(">I", packet_number)
    
    if debug:
        print(f"  [DEBUG] 0-RTT Header before encryption ({len(header)} bytes): {header.hex()}")
        print(f"  [DEBUG] 0-RTT Payload length: {len(payload)} bytes")
    
    # Encrypt payload
    encrypted_payload = encrypt_payload(secrets, packet_number, header, payload)
    
    # Apply header protection
    protected_header = apply_header_protection(
        secrets, header, encrypted_payload, pn_offset, pn_length
    )
    
    return protected_header + encrypted_payload


def create_initial_packet_with_retry_token(
    hostname: str, 
    dcid: bytes,
    scid: bytes,
    retry_token: bytes,
    private_key: X25519PrivateKey,
    client_hello: bytes,
    debug: bool = False
) -> bytes:
    """
    Create a new QUIC Initial packet with a Retry Token.
    
    This is sent in response to a server's Retry packet for address validation.
    The packet uses the same keys (SCID from client), same ClientHello,
    but with a new DCID (from Retry packet's SCID) and includes the Retry Token.
    
    Args:
        hostname: Target hostname
        dcid: New Destination Connection ID (from Retry packet's SCID)
        scid: Our Source Connection ID (same as before)
        retry_token: The Retry Token from the server's Retry packet
        private_key: Our X25519 private key (same as before)
        client_hello: Original ClientHello message
        debug: Enable debug output
        
    Returns:
        bytes: Complete encrypted Initial packet with Retry Token
    """
    # Build CRYPTO frame with original ClientHello
    crypto_frame = build_crypto_frame(0, client_hello)
    
    if debug:
        print(f"  [DEBUG] CRYPTO frame length: {len(crypto_frame)} bytes")
        print(f"  [DEBUG] Retry Token length: {len(retry_token)} bytes")
    
    # Calculate exact header size for padding
    # Token field now includes the retry token length
    token_len_size = len(encode_varint(len(retry_token)))
    header_base_size = 1 + 4 + 1 + len(dcid) + 1 + len(scid) + token_len_size + len(retry_token)
    auth_tag_size = 16
    pn_length = 2
    min_packet_size = 1200
    length_field_size = 2
    
    # Available space for payload
    available_for_payload = min_packet_size - header_base_size - length_field_size - pn_length - auth_tag_size
    
    padding_needed = available_for_payload - len(crypto_frame)
    if padding_needed > 0:
        crypto_frame += build_padding_frame(padding_needed)
    
    if debug:
        print(f"  [DEBUG] Total payload (with padding): {len(crypto_frame)} bytes")
    
    # Build Initial packet with Retry Token, starting with packet number 0
    packet = build_initial_packet(dcid, scid, 0, crypto_frame, token=retry_token, debug=debug)

    if debug:
        print(f"  [DEBUG] Initial packet with Retry Token length: {len(packet)} bytes")
    
    # Ensure packet is at least 1200 bytes
    if len(packet) < 1200:
        extra_padding = 1200 - len(packet)
        if debug:
            print(f"  [DEBUG] Adding extra padding: {extra_padding} bytes")
        crypto_frame += build_padding_frame(extra_padding)
        packet = build_initial_packet(dcid, scid, 0, crypto_frame, token=retry_token, debug=debug)
    
    return packet


def create_initial_packet_with_psk(hostname: str, session_ticket, debug: bool = False,
                                    max_datagram_frame_size: int = 0) -> tuple:
    """
    Create complete QUIC Initial packet with PSK-based ClientHello for 0-RTT.
    
    This is used for session resumption with 0-RTT early data.
    
    Args:
        hostname: Target hostname for SNI
        session_ticket: SessionTicket object for resumption
        debug: Enable debug output
        max_datagram_frame_size: Max DATAGRAM frame size to advertise (0 = disabled)
        
    Returns:
        tuple: (packet, dcid, scid, private_key, client_hello, client_random, psk, early_secret)
    """
    from tls.handshake import build_client_hello_with_psk
    import hashlib
    from ..crypto.keys import derive_0rtt_secrets
    
    # Generate random connection IDs
    dcid = os.urandom(8)  # Destination Connection ID
    scid = os.urandom(8)  # Source Connection ID
    
    # Generate X25519 key pair
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    # Build ClientHello with PSK
    client_hello, client_random, psk = build_client_hello_with_psk(
        hostname, scid, public_key, session_ticket, include_early_data=True,
        max_datagram_frame_size=max_datagram_frame_size
    )
    
    if debug:
        print(f"  [DEBUG] ClientHello with PSK length: {len(client_hello)} bytes")
    
    # Derive 0-RTT secrets from PSK
    early_secrets = derive_0rtt_secrets(psk, debug=debug)
    early_secret = early_secrets["early_secret"]
    
    # Build CRYPTO frame
    crypto_frame = build_crypto_frame(0, client_hello)
    
    if debug:
        print(f"  [DEBUG] CRYPTO frame length: {len(crypto_frame)} bytes")
    
    # Calculate exact header size for padding
    header_base_size = 1 + 4 + 1 + len(dcid) + 1 + len(scid) + 1  # token len=0 is 1 byte
    auth_tag_size = 16
    pn_length = 2
    min_packet_size = 1200
    length_field_size = 2
    
    # Available space for payload
    available_for_payload = min_packet_size - header_base_size - length_field_size - pn_length - auth_tag_size
    
    padding_needed = available_for_payload - len(crypto_frame)
    if padding_needed > 0:
        crypto_frame += build_padding_frame(padding_needed)
    
    if debug:
        print(f"  [DEBUG] Total payload (with padding): {len(crypto_frame)} bytes")
    
    # Build Initial packet
    packet = build_initial_packet(dcid, scid, 0, crypto_frame, debug=debug)

    if debug:
        print(f"  [DEBUG] Initial packet length: {len(packet)} bytes")
    
    # Ensure packet is at least 1200 bytes
    if len(packet) < 1200:
        extra_padding = 1200 - len(packet)
        if debug:
            print(f"  [DEBUG] Adding extra padding: {extra_padding} bytes")
        crypto_frame += build_padding_frame(extra_padding)
        packet = build_initial_packet(dcid, scid, 0, crypto_frame, debug=debug)
    
    return packet, dcid, scid, private_key, client_hello, client_random, psk, early_secret

