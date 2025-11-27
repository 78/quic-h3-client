"""
QUIC/TLS 1.3 Key Derivation (RFC 9001, RFC 8446)
"""

import hmac
import hashlib
import struct
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .hkdf import hkdf_extract, hkdf_expand_label
from ..constants import QUIC_V1_INITIAL_SALT, TLS13_EARLY_SECRET, TLS13_DERIVED_SECRET


def derive_initial_secrets(dcid: bytes) -> dict:
    """
    Derive QUIC Initial secrets from Destination Connection ID.
    
    Args:
        dcid: Destination Connection ID (original DCID for client)
        
    Returns:
        dict: Client Initial secrets {key, iv, hp}
    """
    # Step 1: Extract initial secret
    initial_secret = hkdf_extract(QUIC_V1_INITIAL_SALT, dcid)
    
    # Step 2: Derive client initial secret
    client_initial_secret = hkdf_expand_label(
        initial_secret, b"client in", b"", 32
    )
    
    # Step 3: Derive keys and IVs
    client_key = hkdf_expand_label(client_initial_secret, b"quic key", b"", 16)
    client_iv = hkdf_expand_label(client_initial_secret, b"quic iv", b"", 12)
    client_hp = hkdf_expand_label(client_initial_secret, b"quic hp", b"", 16)
    
    return {
        "key": client_key,
        "iv": client_iv,
        "hp": client_hp,
    }


def derive_server_initial_secrets(dcid: bytes) -> dict:
    """
    Derive Server Initial secrets from Destination Connection ID.
    
    Args:
        dcid: Original Destination Connection ID sent by client
        
    Returns:
        dict: Server Initial secrets {key, iv, hp}
    """
    # Step 1: Extract initial secret
    initial_secret = hkdf_extract(QUIC_V1_INITIAL_SALT, dcid)
    
    # Step 2: Derive server initial secret
    server_initial_secret = hkdf_expand_label(
        initial_secret, b"server in", b"", 32
    )
    
    # Step 3: Derive keys and IVs
    server_key = hkdf_expand_label(server_initial_secret, b"quic key", b"", 16)
    server_iv = hkdf_expand_label(server_initial_secret, b"quic iv", b"", 12)
    server_hp = hkdf_expand_label(server_initial_secret, b"quic hp", b"", 16)
    
    return {
        "key": server_key,
        "iv": server_iv,
        "hp": server_hp,
    }


def derive_handshake_secrets(shared_secret: bytes, transcript_hash: bytes, debug: bool = False) -> dict:
    """
    Derive TLS 1.3 Handshake Traffic Secrets from ECDH shared secret.
    
    TLS 1.3 Key Schedule:
    1. early_secret = HKDF-Extract(salt=0, IKM=PSK or 0) [FIXED CONSTANT]
    2. derived_secret = HKDF-Expand-Label(early_secret, "derived", "", 32) [FIXED CONSTANT]
    3. handshake_secret = HKDF-Extract(salt=derived_secret, IKM=shared_secret)
    4. client_hs_traffic_secret = HKDF-Expand-Label(handshake_secret, "c hs traffic", transcript_hash, 32)
    5. server_hs_traffic_secret = HKDF-Expand-Label(handshake_secret, "s hs traffic", transcript_hash, 32)
    
    Args:
        shared_secret: ECDH shared secret
        transcript_hash: SHA-256 hash of ClientHello + ServerHello
        debug: Enable debug output
        
    Returns:
        dict: {client: {key, iv, hp, traffic_secret}, server: {...}, handshake_secret}
    """
    # Step 1-2: Use precomputed constants
    early_secret = TLS13_EARLY_SECRET
    derived_secret = TLS13_DERIVED_SECRET
    
    if debug:
        print(f"    Early Secret: {early_secret.hex()}")
        print(f"    Derived Secret: {derived_secret.hex()}")
    
    # Step 3: Handshake secret
    handshake_secret = hkdf_extract(derived_secret, shared_secret)
    
    if debug:
        print(f"    Handshake Secret: {handshake_secret.hex()}")
    
    # Step 4: Client handshake traffic secret
    client_hs_traffic_secret = hkdf_expand_label(
        handshake_secret, b"c hs traffic", transcript_hash, 32
    )
    
    # Step 5: Server handshake traffic secret
    server_hs_traffic_secret = hkdf_expand_label(
        handshake_secret, b"s hs traffic", transcript_hash, 32
    )
    
    if debug:
        print(f"    Client HS Traffic Secret: {client_hs_traffic_secret.hex()}")
        print(f"    Server HS Traffic Secret: {server_hs_traffic_secret.hex()}")
    
    # Derive QUIC keys from traffic secrets
    client_secrets = {
        "key": hkdf_expand_label(client_hs_traffic_secret, b"quic key", b"", 16),
        "iv": hkdf_expand_label(client_hs_traffic_secret, b"quic iv", b"", 12),
        "hp": hkdf_expand_label(client_hs_traffic_secret, b"quic hp", b"", 16),
        "traffic_secret": client_hs_traffic_secret,
    }
    
    server_secrets = {
        "key": hkdf_expand_label(server_hs_traffic_secret, b"quic key", b"", 16),
        "iv": hkdf_expand_label(server_hs_traffic_secret, b"quic iv", b"", 12),
        "hp": hkdf_expand_label(server_hs_traffic_secret, b"quic hp", b"", 16),
        "traffic_secret": server_hs_traffic_secret,
    }
    
    if debug:
        print(f"    Server HS Key: {server_secrets['key'].hex()}")
        print(f"    Server HS IV: {server_secrets['iv'].hex()}")
        print(f"    Server HS HP: {server_secrets['hp'].hex()}")
    
    return {
        "client": client_secrets,
        "server": server_secrets,
        "handshake_secret": handshake_secret,
    }


def derive_application_secrets(handshake_secret: bytes, transcript_hash: bytes, debug: bool = False) -> dict:
    """
    Derive TLS 1.3 Application Traffic Secrets from Handshake Secret.
    
    Per RFC 8446 Section 7.1, the transcript_hash should be computed over:
    ClientHello + ServerHello + EncryptedExtensions + Certificate + 
    CertificateVerify + ServerFinished
    
    NOTE: Client Finished is NOT included in the transcript for application secrets!
    
    TLS 1.3 Key Schedule continuation:
    1. derived_secret_for_master = HKDF-Expand-Label(handshake_secret, "derived", empty_hash, 32)
    2. master_secret = HKDF-Extract(salt=derived_secret_for_master, IKM=0)
    3. client_app_traffic_secret = HKDF-Expand-Label(master_secret, "c ap traffic", transcript_hash, 32)
    4. server_app_traffic_secret = HKDF-Expand-Label(master_secret, "s ap traffic", transcript_hash, 32)
    
    Args:
        handshake_secret: The handshake secret from derive_handshake_secrets
        transcript_hash: SHA-256 hash up to and including Server Finished
        debug: Enable debug output
        
    Returns:
        dict: {client: {key, iv, hp, traffic_secret}, server: {...}, master_secret}
    """
    # Step 1: Derive secret for master
    empty_hash = hashlib.sha256(b"").digest()
    derived_secret_for_master = hkdf_expand_label(handshake_secret, b"derived", empty_hash, 32)
    
    if debug:
        print(f"    Derived Secret (for master): {derived_secret_for_master.hex()}")
    
    # Step 2: Master secret
    master_secret = hkdf_extract(derived_secret_for_master, b"\x00" * 32)
    
    if debug:
        print(f"    Master Secret: {master_secret.hex()}")
    
    # Step 3: Client application traffic secret
    client_app_traffic_secret = hkdf_expand_label(
        master_secret, b"c ap traffic", transcript_hash, 32
    )
    
    # Step 4: Server application traffic secret
    server_app_traffic_secret = hkdf_expand_label(
        master_secret, b"s ap traffic", transcript_hash, 32
    )
    
    if debug:
        print(f"    Client App Traffic Secret: {client_app_traffic_secret.hex()}")
        print(f"    Server App Traffic Secret: {server_app_traffic_secret.hex()}")
    
    # Derive QUIC keys from traffic secrets
    client_secrets = {
        "key": hkdf_expand_label(client_app_traffic_secret, b"quic key", b"", 16),
        "iv": hkdf_expand_label(client_app_traffic_secret, b"quic iv", b"", 12),
        "hp": hkdf_expand_label(client_app_traffic_secret, b"quic hp", b"", 16),
        "traffic_secret": client_app_traffic_secret,
    }
    
    server_secrets = {
        "key": hkdf_expand_label(server_app_traffic_secret, b"quic key", b"", 16),
        "iv": hkdf_expand_label(server_app_traffic_secret, b"quic iv", b"", 12),
        "hp": hkdf_expand_label(server_app_traffic_secret, b"quic hp", b"", 16),
        "traffic_secret": server_app_traffic_secret,
    }
    
    if debug:
        print(f"    Server 1-RTT Key: {server_secrets['key'].hex()}")
        print(f"    Server 1-RTT IV: {server_secrets['iv'].hex()}")
        print(f"    Server 1-RTT HP: {server_secrets['hp'].hex()}")
    
    return {
        "client": client_secrets,
        "server": server_secrets,
        "master_secret": master_secret,
    }


def compute_finished_verify_data(traffic_secret: bytes, transcript_hash: bytes) -> bytes:
    """
    Compute the verify_data for TLS 1.3 Finished message.
    
    verify_data = HMAC(finished_key, transcript_hash)
    finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", 32)
    
    Args:
        traffic_secret: Handshake traffic secret
        transcript_hash: Transcript hash up to this point
        
    Returns:
        bytes: 32-byte verify_data
    """
    # Derive finished_key from traffic secret
    finished_key = hkdf_expand_label(traffic_secret, b"finished", b"", 32)
    
    # Compute verify_data using HMAC-SHA256
    verify_data = hmac.new(finished_key, transcript_hash, hashlib.sha256).digest()
    
    return verify_data


def build_client_finished_message(client_hs_traffic_secret: bytes, transcript_hash: bytes) -> bytes:
    """
    Build TLS 1.3 Client Finished handshake message.
    
    Structure:
    - Handshake type: 20 (Finished)
    - Length: 32 (SHA-256 hash size)
    - verify_data: 32 bytes
    
    Args:
        client_hs_traffic_secret: Client handshake traffic secret
        transcript_hash: Transcript hash up to this point
        
    Returns:
        bytes: Complete Finished handshake message
    """
    verify_data = compute_finished_verify_data(client_hs_traffic_secret, transcript_hash)
    
    # TLS Handshake header: type (1 byte) + length (3 bytes) + data
    msg_type = 20  # Finished
    length = len(verify_data)  # 32 for SHA-256
    
    header = struct.pack(">B", msg_type) + struct.pack(">I", length)[1:]  # 3-byte length
    
    return header + verify_data


def perform_ecdh(private_key: X25519PrivateKey, server_public_key_bytes: bytes) -> bytes:
    """
    Perform X25519 ECDH key exchange.
    
    Args:
        private_key: Client's X25519 private key
        server_public_key_bytes: Server's public key (32 bytes)
        
    Returns:
        bytes: 32-byte shared secret
    """
    server_public_key = X25519PublicKey.from_public_bytes(server_public_key_bytes)
    shared_secret = private_key.exchange(server_public_key)
    return shared_secret


def derive_resumption_master_secret(master_secret: bytes, transcript_hash: bytes, debug: bool = False) -> bytes:
    """
    Derive TLS 1.3 Resumption Master Secret.
    
    This is used to derive PSK for session resumption.
    
    resumption_master_secret = HKDF-Expand-Label(master_secret, "res master", 
                                                   transcript_hash_with_client_finished, 32)
    
    Args:
        master_secret: The master secret from application secrets derivation
        transcript_hash: SHA-256 hash up to and including Client Finished
        debug: Enable debug output
        
    Returns:
        bytes: 32-byte resumption master secret
    """
    resumption_master_secret = hkdf_expand_label(
        master_secret, b"res master", transcript_hash, 32
    )
    
    if debug:
        print(f"    Resumption Master Secret: {resumption_master_secret.hex()}")
    
    return resumption_master_secret


def derive_0rtt_secrets(psk: bytes, debug: bool = False) -> dict:
    """
    Derive 0-RTT (Early Data) secrets from PSK.
    
    TLS 1.3 0-RTT Key Schedule:
    1. early_secret = HKDF-Extract(salt=0, IKM=PSK)
    2. client_early_traffic_secret = HKDF-Expand-Label(early_secret, "c e traffic", ClientHello_hash, 32)
    
    Args:
        psk: Pre-Shared Key computed from session ticket
        debug: Enable debug output
        
    Returns:
        dict: {client: {key, iv, hp, traffic_secret}, early_secret}
    """
    # Step 1: Derive early_secret from PSK
    early_secret = hkdf_extract(b"\x00" * 32, psk)
    
    if debug:
        print(f"    Early Secret (from PSK): {early_secret.hex()}")
    
    return {
        "early_secret": early_secret,
    }


def derive_0rtt_application_secrets(early_secret: bytes, client_hello_hash: bytes, debug: bool = False) -> dict:
    """
    Derive 0-RTT application secrets from early secret and ClientHello hash.
    
    client_early_traffic_secret = HKDF-Expand-Label(early_secret, "c e traffic", ClientHello_hash, 32)
    
    Args:
        early_secret: The early secret derived from PSK
        client_hello_hash: SHA-256 hash of ClientHello
        debug: Enable debug output
        
    Returns:
        dict: {client: {key, iv, hp, traffic_secret}}
    """
    # Derive client early traffic secret
    client_early_traffic_secret = hkdf_expand_label(
        early_secret, b"c e traffic", client_hello_hash, 32
    )
    
    if debug:
        print(f"    Client Early Traffic Secret: {client_early_traffic_secret.hex()}")
    
    # Derive QUIC keys from traffic secret
    client_secrets = {
        "key": hkdf_expand_label(client_early_traffic_secret, b"quic key", b"", 16),
        "iv": hkdf_expand_label(client_early_traffic_secret, b"quic iv", b"", 12),
        "hp": hkdf_expand_label(client_early_traffic_secret, b"quic hp", b"", 16),
        "traffic_secret": client_early_traffic_secret,
    }
    
    if debug:
        print(f"    Client 0-RTT Key: {client_secrets['key'].hex()}")
        print(f"    Client 0-RTT IV: {client_secrets['iv'].hex()}")
        print(f"    Client 0-RTT HP: {client_secrets['hp'].hex()}")
    
    return {
        "client": client_secrets,
    }


def derive_handshake_secrets_with_psk(shared_secret: bytes, transcript_hash: bytes, 
                                       psk: bytes = None, debug: bool = False) -> dict:
    """
    Derive TLS 1.3 Handshake Traffic Secrets with PSK support.
    
    When PSK is provided:
    1. early_secret = HKDF-Extract(salt=0, IKM=PSK)
    2. derived_secret = HKDF-Expand-Label(early_secret, "derived", empty_hash, 32)
    3. handshake_secret = HKDF-Extract(salt=derived_secret, IKM=shared_secret)
    
    Args:
        shared_secret: ECDH shared secret
        transcript_hash: SHA-256 hash of ClientHello + ServerHello
        psk: Pre-Shared Key (None for initial connection)
        debug: Enable debug output
        
    Returns:
        dict: {client: {key, iv, hp, traffic_secret}, server: {...}, handshake_secret}
    """
    empty_hash = hashlib.sha256(b"").digest()
    
    if psk:
        # With PSK: derive early_secret from PSK
        early_secret = hkdf_extract(b"\x00" * 32, psk)
        derived_secret = hkdf_expand_label(early_secret, b"derived", empty_hash, 32)
    else:
        # Without PSK: use precomputed constants
        early_secret = TLS13_EARLY_SECRET
        derived_secret = TLS13_DERIVED_SECRET
    
    if debug:
        print(f"    Early Secret: {early_secret.hex()}")
        print(f"    Derived Secret: {derived_secret.hex()}")
    
    # Step 3: Handshake secret
    handshake_secret = hkdf_extract(derived_secret, shared_secret)
    
    if debug:
        print(f"    Handshake Secret: {handshake_secret.hex()}")
    
    # Step 4: Client handshake traffic secret
    client_hs_traffic_secret = hkdf_expand_label(
        handshake_secret, b"c hs traffic", transcript_hash, 32
    )
    
    # Step 5: Server handshake traffic secret
    server_hs_traffic_secret = hkdf_expand_label(
        handshake_secret, b"s hs traffic", transcript_hash, 32
    )
    
    if debug:
        print(f"    Client HS Traffic Secret: {client_hs_traffic_secret.hex()}")
        print(f"    Server HS Traffic Secret: {server_hs_traffic_secret.hex()}")
    
    # Derive QUIC keys from traffic secrets
    client_secrets = {
        "key": hkdf_expand_label(client_hs_traffic_secret, b"quic key", b"", 16),
        "iv": hkdf_expand_label(client_hs_traffic_secret, b"quic iv", b"", 12),
        "hp": hkdf_expand_label(client_hs_traffic_secret, b"quic hp", b"", 16),
        "traffic_secret": client_hs_traffic_secret,
    }
    
    server_secrets = {
        "key": hkdf_expand_label(server_hs_traffic_secret, b"quic key", b"", 16),
        "iv": hkdf_expand_label(server_hs_traffic_secret, b"quic iv", b"", 12),
        "hp": hkdf_expand_label(server_hs_traffic_secret, b"quic hp", b"", 16),
        "traffic_secret": server_hs_traffic_secret,
    }
    
    if debug:
        print(f"    Server HS Key: {server_secrets['key'].hex()}")
        print(f"    Server HS IV: {server_secrets['iv'].hex()}")
        print(f"    Server HS HP: {server_secrets['hp'].hex()}")
    
    return {
        "client": client_secrets,
        "server": server_secrets,
        "handshake_secret": handshake_secret,
        "early_secret": early_secret if psk else None,
    }

