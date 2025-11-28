"""
TLS 1.3 Extension Building and Parsing (RFC 8446)
"""

import struct
import hmac
import hashlib
from quic.varint import encode_varint, decode_varint
from quic.frames.parsers import parse_quic_transport_params
from .constants import (
    EXT_SERVER_NAME, EXT_SUPPORTED_GROUPS, EXT_SIGNATURE_ALGORITHMS,
    EXT_ALPN, EXT_SUPPORTED_VERSIONS, EXT_KEY_SHARE, EXT_QUIC_TRANSPORT_PARAMS,
    EXT_PSK_KEY_EXCHANGE_MODES, EXT_PRE_SHARED_KEY, EXT_EARLY_DATA,
    GROUP_X25519, SIG_ECDSA_SECP256R1_SHA256, SIG_RSA_PSS_RSAE_SHA256, SIG_RSA_PKCS1_SHA256,
    EXTENSION_NAMES, GROUP_NAMES
)


def build_extension(ext_type: int, data: bytes) -> bytes:
    """
    Build a TLS extension.
    
    Args:
        ext_type: Extension type
        data: Extension data
        
    Returns:
        bytes: Complete extension
    """
    return struct.pack(">HH", ext_type, len(data)) + data


def build_server_name_extension(hostname: str) -> bytes:
    """Build SNI extension."""
    name_bytes = hostname.encode('ascii')
    # Server Name list: type (1 byte) + length (2 bytes) + name
    name_entry = struct.pack(">BH", 0, len(name_bytes)) + name_bytes
    # List length (2 bytes)
    data = struct.pack(">H", len(name_entry)) + name_entry
    return build_extension(EXT_SERVER_NAME, data)


def build_supported_groups_extension() -> bytes:
    """Build supported_groups extension (x25519 only)."""
    groups = struct.pack(">H", GROUP_X25519)
    data = struct.pack(">H", len(groups)) + groups
    return build_extension(EXT_SUPPORTED_GROUPS, data)


def build_signature_algorithms_extension() -> bytes:
    """Build signature_algorithms extension."""
    algorithms = struct.pack(
        ">HHH",
        SIG_ECDSA_SECP256R1_SHA256,
        SIG_RSA_PSS_RSAE_SHA256,
        SIG_RSA_PKCS1_SHA256,
    )
    data = struct.pack(">H", len(algorithms)) + algorithms
    return build_extension(EXT_SIGNATURE_ALGORITHMS, data)


def build_supported_versions_extension() -> bytes:
    """Build supported_versions extension (TLS 1.3 only)."""
    # Client sends list of versions
    versions = struct.pack(">H", 0x0304)  # TLS 1.3
    data = struct.pack("B", len(versions)) + versions
    return build_extension(EXT_SUPPORTED_VERSIONS, data)


def build_key_share_extension(public_key: bytes) -> bytes:
    """Build key_share extension with x25519 public key."""
    # Key Share Entry: group (2) + length (2) + key
    key_entry = struct.pack(">HH", GROUP_X25519, len(public_key)) + public_key
    # Client Key Share Length
    data = struct.pack(">H", len(key_entry)) + key_entry
    return build_extension(EXT_KEY_SHARE, data)


def build_alpn_extension(protocols: list = None) -> bytes:
    """
    Build ALPN extension.
    
    Args:
        protocols: List of protocol strings (default: ["h3"])
        
    Returns:
        bytes: ALPN extension
    """
    if protocols is None:
        protocols = ["h3"]
    
    protocol_list = b""
    for protocol in protocols:
        proto_bytes = protocol.encode('ascii')
        protocol_list += struct.pack("B", len(proto_bytes)) + proto_bytes
    
    data = struct.pack(">H", len(protocol_list)) + protocol_list
    return build_extension(EXT_ALPN, data)


def build_quic_transport_params(scid: bytes) -> bytes:
    """
    Build QUIC transport parameters extension.
    
    Args:
        scid: Source Connection ID
        
    Returns:
        bytes: Transport parameters extension
    """
    params = b""
    
    # max_idle_timeout (0x01): 60000 ms
    params += encode_varint(0x01)  # type
    params += encode_varint(4)      # length
    params += encode_varint(60000)  # value
    
    # initial_max_data (0x04): 65536 (64KB - for 2Mbps embedded devices)
    # Formula: 2 × BDP, where BDP = bandwidth × RTT
    # 2Mbps × 200ms = 50KB, so 64KB provides good headroom
    params += encode_varint(0x04)
    params += encode_varint(4)
    params += encode_varint(65536)
    
    # initial_max_stream_data_bidi_local (0x05): 65536 (64KB)
    params += encode_varint(0x05)
    params += encode_varint(4)
    params += encode_varint(65536)
    
    # initial_max_stream_data_bidi_remote (0x06): 65536 (64KB)
    params += encode_varint(0x06)
    params += encode_varint(4)
    params += encode_varint(65536)
    
    # initial_max_stream_data_uni (0x07): 65536 (64KB)
    params += encode_varint(0x07)
    params += encode_varint(4)
    params += encode_varint(65536)
    
    # initial_max_streams_bidi (0x08): 8 (reduced for embedded devices)
    # Each stream needs state tracking, fewer streams = less memory
    params += encode_varint(0x08)
    params += encode_varint(1)
    params += encode_varint(8)
    
    # initial_max_streams_uni (0x09): 8 (reduced for embedded devices)
    # HTTP/3 needs 3 uni streams (control, QPACK encoder/decoder)
    params += encode_varint(0x09)
    params += encode_varint(1)
    params += encode_varint(8)
    
    # ack_delay_exponent (0x0a): 3
    params += encode_varint(0x0a)
    params += encode_varint(1)
    params += encode_varint(3)
    
    # max_ack_delay (0x0b): 25ms
    params += encode_varint(0x0b)
    params += encode_varint(1)
    params += encode_varint(25)
    
    # active_connection_id_limit (0x0e): 2 (minimal for embedded devices)
    # Fewer CIDs = less memory for tracking
    params += encode_varint(0x0e)
    params += encode_varint(1)
    params += encode_varint(2)
    
    # initial_source_connection_id (0x0f)
    params += encode_varint(0x0f)
    params += encode_varint(len(scid))
    params += scid
    
    return build_extension(EXT_QUIC_TRANSPORT_PARAMS, params)


def parse_tls_extensions(data: bytes, is_server_hello: bool = False) -> list:
    """
    Parse TLS extensions.
    
    Args:
        data: Raw extensions data
        is_server_hello: True if parsing ServerHello extensions
        
    Returns:
        list: List of parsed extension dicts
    """
    extensions = []
    offset = 0
    
    while offset + 4 <= len(data):
        ext_type = struct.unpack(">H", data[offset:offset+2])[0]
        ext_len = struct.unpack(">H", data[offset+2:offset+4])[0]
        ext_data = data[offset+4:offset+4+ext_len]
        
        ext_name = EXTENSION_NAMES.get(ext_type, f"unknown(0x{ext_type:04x})")
        
        ext_info = {
            "type": ext_type,
            "name": ext_name,
            "length": ext_len,
        }
        
        # Parse specific extensions
        if ext_type == 43:  # supported_versions
            if is_server_hello and len(ext_data) >= 2:
                version = struct.unpack(">H", ext_data[0:2])[0]
                version_names = {0x0304: "TLS 1.3", 0x0303: "TLS 1.2"}
                ext_info["version"] = version_names.get(version, f"0x{version:04x}")
            elif not is_server_hello and len(ext_data) >= 1:
                ver_len = ext_data[0]
                versions = []
                for i in range(1, 1 + ver_len, 2):
                    if i + 1 < len(ext_data):
                        v = struct.unpack(">H", ext_data[i:i+2])[0]
                        versions.append(f"0x{v:04x}")
                ext_info["versions"] = versions
        
        elif ext_type == 51:  # key_share
            if is_server_hello and len(ext_data) >= 4:
                # Server Key Share: Group (2) + Key Length (2) + Key
                group = struct.unpack(">H", ext_data[0:2])[0]
                key_len = struct.unpack(">H", ext_data[2:4])[0]
                key_exchange = ext_data[4:4+key_len]
                
                ext_info["group"] = GROUP_NAMES.get(group, f"0x{group:04x}")
                ext_info["key_exchange_length"] = key_len
                ext_info["key_exchange"] = key_exchange.hex()
                ext_info["key_exchange_bytes"] = key_exchange  # Keep raw bytes for ECDH
        
        elif ext_type == 16:  # ALPN
            if len(ext_data) >= 2:
                alpn_len = struct.unpack(">H", ext_data[0:2])[0]
                protocols = []
                idx = 2
                while idx < 2 + alpn_len:
                    proto_len = ext_data[idx]
                    proto = ext_data[idx+1:idx+1+proto_len].decode('ascii', errors='replace')
                    protocols.append(proto)
                    idx += 1 + proto_len
                ext_info["protocols"] = protocols
        
        elif ext_type == 10:  # supported_groups
            if len(ext_data) >= 2:
                groups_len = struct.unpack(">H", ext_data[0:2])[0]
                groups = []
                idx = 2
                while idx + 2 <= 2 + groups_len:
                    group_id = struct.unpack(">H", ext_data[idx:idx+2])[0]
                    groups.append(GROUP_NAMES.get(group_id, f"0x{group_id:04x}"))
                    idx += 2
                ext_info["groups"] = groups
        
        elif ext_type == 57:  # quic_transport_params
            ext_info["params"] = parse_quic_transport_params(ext_data)
        
        extensions.append(ext_info)
        offset += 4 + ext_len
    
    return extensions


def build_psk_key_exchange_modes_extension() -> bytes:
    """
    Build psk_key_exchange_modes extension (RFC 8446 Section 4.2.9).
    
    This extension indicates the PSK key exchange modes the client supports.
    For 0-RTT, we need PSK with (EC)DHE key establishment (psk_dhe_ke).
    
    Returns:
        bytes: psk_key_exchange_modes extension
    """
    # Only support psk_dhe_ke (PSK with ECDH)
    modes = struct.pack("B", 1)  # psk_dhe_ke = 1
    data = struct.pack("B", len(modes)) + modes
    return build_extension(EXT_PSK_KEY_EXCHANGE_MODES, data)


def build_early_data_extension() -> bytes:
    """
    Build early_data extension for ClientHello (RFC 8446 Section 4.2.10).
    
    In ClientHello, this extension has empty data (length = 0).
    It indicates the client wants to send 0-RTT early data.
    
    Returns:
        bytes: early_data extension
    """
    return build_extension(EXT_EARLY_DATA, b"")


def build_pre_shared_key_extension(psk_identity: bytes, obfuscated_ticket_age: int,
                                   binder_placeholder: bool = True) -> tuple:
    """
    Build pre_shared_key extension for ClientHello (RFC 8446 Section 4.2.11).
    
    This extension MUST be the last extension in ClientHello.
    
    Structure:
        struct {
            PskIdentity identities<7..2^16-1>;
            PskBinderEntry binders<33..2^16-1>;
        } OfferedPsks;
        
        struct {
            opaque identity<1..2^16-1>;
            uint32 obfuscated_ticket_age;
        } PskIdentity;
    
    Args:
        psk_identity: The PSK identity (ticket from NewSessionTicket)
        obfuscated_ticket_age: Obfuscated ticket age in milliseconds
        binder_placeholder: If True, use placeholder zeros for binder (32 bytes)
        
    Returns:
        tuple: (extension_bytes, binder_offset) where binder_offset is position of binder
    """
    # Build PskIdentity
    psk_identity_entry = struct.pack(">H", len(psk_identity)) + psk_identity
    psk_identity_entry += struct.pack(">I", obfuscated_ticket_age)
    
    # Identities list
    identities = struct.pack(">H", len(psk_identity_entry)) + psk_identity_entry
    
    # Binder (SHA-256 HMAC = 32 bytes)
    binder_len = 32
    if binder_placeholder:
        binder = b"\x00" * binder_len
    else:
        binder = b"\x00" * binder_len  # Will be filled in later
    
    # Binders list: length (2 bytes) + binder length (1 byte) + binder
    binders = struct.pack(">H", 1 + binder_len) + struct.pack("B", binder_len) + binder
    
    # Complete extension data
    ext_data = identities + binders
    
    # Build extension
    ext_type_bytes = struct.pack(">H", EXT_PRE_SHARED_KEY)
    ext_len_bytes = struct.pack(">H", len(ext_data))
    extension = ext_type_bytes + ext_len_bytes + ext_data
    
    # Calculate binder offset within extension
    # Extension: type(2) + len(2) + identities_len(2) + identity + binders_len(2) + binder_len(1)
    binder_offset = 2 + 2 + len(identities) + 2 + 1
    
    return extension, binder_offset


def compute_psk_binder(psk: bytes, transcript_hash: bytes) -> bytes:
    """
    Compute the PSK binder value for the pre_shared_key extension.
    
    According to RFC 8446 Section 4.2.11.2 and Section 7.1:
    - binder_key = Derive-Secret(Early Secret, "res binder", "")
    - finished_key = HKDF-Expand-Label(binder_key, "finished", "", 32)
    - binder = HMAC(finished_key, transcript_hash_without_binders)
    
    Note: Derive-Secret uses Transcript-Hash(Messages), so for empty messages
    we need to use SHA-256("") = e3b0c442... as the context.
    
    Args:
        psk: The Pre-Shared Key
        transcript_hash: Hash of ClientHello up to (but not including) binders
        
    Returns:
        bytes: 32-byte binder value
    """
    from quic.crypto.hkdf import hkdf_extract, hkdf_expand_label
    
    # Derive early_secret from PSK
    # early_secret = HKDF-Extract(salt=0, IKM=PSK)
    early_secret = hkdf_extract(b"\x00" * 32, psk)
    
    # Derive binder_key using Derive-Secret
    # binder_key = Derive-Secret(early_secret, "res binder", "")
    # Derive-Secret uses Transcript-Hash("") as context
    empty_hash = hashlib.sha256(b"").digest()
    binder_key = hkdf_expand_label(early_secret, b"res binder", empty_hash, 32)
    
    # Derive finished_key from binder_key
    # finished_key = HKDF-Expand-Label(binder_key, "finished", "", 32)
    # Note: This uses empty context, NOT the empty hash
    finished_key = hkdf_expand_label(binder_key, b"finished", b"", 32)
    
    # Compute binder = HMAC-SHA256(finished_key, transcript_hash)
    binder = hmac.new(finished_key, transcript_hash, hashlib.sha256).digest()
    
    return binder

