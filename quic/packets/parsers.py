"""
QUIC Packet Parsers (RFC 9000)
"""

import struct
from ..varint import decode_varint
from ..constants import PACKET_TYPE_NAMES, QUIC_VERSION
from ..crypto.keys import derive_server_initial_secrets
from ..crypto.aead import remove_header_protection, decrypt_payload, verify_retry_integrity_tag
from ..frames.parsers import parse_quic_frames


def parse_long_header(packet: bytes) -> dict:
    """
    Parse QUIC Long Header and return header info.
    
    Long Header format:
    - First byte: Header Form (1) | Fixed Bit (1) | Long Packet Type (2) | Type-Specific Bits (4)
    - Version (4 bytes)
    - DCID Length (1 byte) + DCID
    - SCID Length (1 byte) + SCID
    - [Type-specific fields]
    
    Args:
        packet: Raw packet bytes
        
    Returns:
        dict: Parsed header info
    """
    result = {
        "success": False,
        "packet_type": None,
        "packet_type_id": None,
        "version": None,
        "dcid": None,
        "dcid_bytes": None,
        "scid": None,
        "scid_bytes": None,
        "pn_offset": 0,
        "length": 0,
        "total_header_len": 0,
        "error": None
    }
    
    if len(packet) < 7:
        result["error"] = "Packet too short"
        return result
    
    first_byte = packet[0]
    if not (first_byte & 0x80):
        result["error"] = "Not a Long Header packet"
        return result
    
    packet_type = (first_byte & 0x30) >> 4
    result["packet_type"] = PACKET_TYPE_NAMES.get(packet_type, f"Unknown({packet_type})")
    result["packet_type_id"] = packet_type
    
    version = struct.unpack(">I", packet[1:5])[0]
    result["version"] = f"0x{version:08x}"
    
    dcid_len = packet[5]
    dcid = packet[6:6 + dcid_len]
    result["dcid"] = dcid.hex()
    result["dcid_bytes"] = dcid
    
    scid_len = packet[6 + dcid_len]
    scid = packet[7 + dcid_len:7 + dcid_len + scid_len]
    result["scid"] = scid.hex()
    result["scid_bytes"] = scid
    
    offset = 7 + dcid_len + scid_len
    
    # For Initial packets, parse token
    if packet_type == 0:  # Initial
        token_len, consumed = decode_varint(packet, offset)
        offset += consumed
        offset += token_len  # Skip token
    
    # Parse Length field
    length, consumed = decode_varint(packet, offset)
    offset += consumed
    
    result["pn_offset"] = offset
    result["length"] = length
    result["success"] = True
    
    return result


def decrypt_quic_packet(packet: bytes, secrets: dict, header_info: dict, 
                        debug: bool = True) -> dict:
    """
    Generic QUIC packet decryption using provided secrets.
    
    Args:
        packet: Raw packet bytes
        secrets: Decryption secrets {key, iv, hp}
        header_info: Parsed header info from parse_long_header
        debug: Enable debug output
        
    Returns:
        dict: {success, packet_number, plaintext, frames, error}
    """
    result = {
        "success": False,
        "packet_number": None,
        "plaintext": None,
        "frames": [],
        "error": None
    }
    
    pn_offset = header_info["pn_offset"]
    length = header_info["length"]
    
    # Remove header protection
    header, packet_number, pn_length = remove_header_protection(
        secrets, packet, pn_offset
    )
    result["packet_number"] = packet_number
    
    if debug:
        print(f"    Packet Number: {packet_number}")
        print(f"    PN Length: {pn_length}")
    
    # Extract encrypted payload
    encrypted_payload = packet[pn_offset + pn_length:pn_offset + length]
    
    if debug:
        print(f"    Encrypted payload length: {len(encrypted_payload)}")
    
    # Decrypt payload
    plaintext = decrypt_payload(secrets, packet_number, header, encrypted_payload)
    
    if plaintext is None:
        result["error"] = "Decryption failed"
        return result
    
    result["success"] = True
    result["plaintext"] = plaintext
    
    if debug:
        print(f"    Decryption successful! Plaintext length: {len(plaintext)}")
    
    # Parse frames
    frames = parse_quic_frames(plaintext, debug)
    result["frames"] = frames
    
    return result


def decrypt_server_initial(packet: bytes, original_dcid: bytes, 
                           debug: bool = True) -> dict:
    """
    Decrypt a server Initial packet.
    
    Args:
        packet: Raw packet bytes
        original_dcid: Original DCID sent by client (for key derivation)
        debug: Enable debug output
        
    Returns:
        dict: Decryption result with frames
    """
    header_info = parse_long_header(packet)
    
    result = {
        "success": False,
        "packet_type": header_info["packet_type"],
        "version": header_info["version"],
        "dcid": header_info["dcid"],
        "scid": header_info["scid"],
        "packet_number": None,
        "frames": [],
        "error": header_info.get("error"),
        "total_length": header_info["pn_offset"] + header_info["length"] if header_info["success"] else 0
    }
    
    if not header_info["success"]:
        return result
    
    if debug:
        print(f"    Packet type: {result['packet_type']}")
        print(f"    QUIC Version: {result['version']}")
        print(f"    DCID: {result['dcid']}")
        print(f"    SCID: {result['scid']}")
        print(f"    Encrypted data length: {header_info['length']}")
        print(f"    PN offset: {header_info['pn_offset']}")
    
    # Only decrypt Initial packets here
    if header_info["packet_type_id"] != 0:
        result["error"] = f"Not an Initial packet (got {result['packet_type']})"
        return result
    
    # Derive server secrets using original DCID
    secrets = derive_server_initial_secrets(original_dcid)
    
    if debug:
        print(f"    Server Key: {secrets['key'].hex()}")
        print(f"    Server IV: {secrets['iv'].hex()}")
        print(f"    Server HP: {secrets['hp'].hex()}")
    
    # Decrypt
    decrypt_result = decrypt_quic_packet(packet, secrets, header_info, debug)
    
    result["packet_number"] = decrypt_result["packet_number"]
    result["frames"] = decrypt_result["frames"]
    result["success"] = decrypt_result["success"]
    result["error"] = decrypt_result.get("error")
    
    return result


def decrypt_server_handshake(packet: bytes, handshake_secrets: dict, 
                             debug: bool = True) -> dict:
    """
    Decrypt a server Handshake packet.
    
    Args:
        packet: Raw packet bytes
        handshake_secrets: Server handshake secrets {key, iv, hp}
        debug: Enable debug output
        
    Returns:
        dict: Decryption result with frames
    """
    header_info = parse_long_header(packet)
    
    result = {
        "success": False,
        "packet_type": header_info["packet_type"],
        "version": header_info["version"],
        "dcid": header_info["dcid"],
        "scid": header_info["scid"],
        "packet_number": None,
        "frames": [],
        "error": header_info.get("error"),
        "total_length": header_info["pn_offset"] + header_info["length"] if header_info["success"] else 0
    }
    
    if not header_info["success"]:
        return result
    
    if debug:
        print(f"    Packet type: {result['packet_type']}")
        print(f"    QUIC Version: {result['version']}")
        print(f"    DCID: {result['dcid']}")
        print(f"    SCID: {result['scid']}")
        print(f"    Encrypted data length: {header_info['length']}")
        print(f"    PN offset: {header_info['pn_offset']}")
    
    # Only decrypt Handshake packets here
    if header_info["packet_type_id"] != 2:
        result["error"] = f"Not a Handshake packet (got {result['packet_type']})"
        return result
    
    if debug:
        print(f"    Server HS Key: {handshake_secrets['key'].hex()}")
        print(f"    Server HS IV: {handshake_secrets['iv'].hex()}")
        print(f"    Server HS HP: {handshake_secrets['hp'].hex()}")
    
    # Decrypt
    decrypt_result = decrypt_quic_packet(packet, handshake_secrets, header_info, debug)
    
    result["packet_number"] = decrypt_result["packet_number"]
    result["frames"] = decrypt_result["frames"]
    result["success"] = decrypt_result["success"]
    result["error"] = decrypt_result.get("error")
    
    return result


def parse_retry_packet(packet: bytes, original_dcid: bytes, debug: bool = True) -> dict:
    """
    Parse and validate a QUIC Retry packet (RFC 9000 Section 17.2.5).
    
    Retry Packet format:
    - Header Form (1) = 1
    - Fixed Bit (1) = 1  
    - Long Packet Type (2) = 3
    - Unused (4)
    - Version (32)
    - Destination Connection ID Length (8)
    - Destination Connection ID (0..160)
    - Source Connection ID Length (8)
    - Source Connection ID (0..160)
    - Retry Token (..)
    - Retry Integrity Tag (128) - last 16 bytes
    
    Args:
        packet: Raw Retry packet bytes
        original_dcid: Original DCID sent by client (for integrity validation)
        debug: Enable debug output
        
    Returns:
        dict: {
            success: bool,
            dcid: str (hex),
            dcid_bytes: bytes,
            scid: str (hex),
            scid_bytes: bytes,
            retry_token: bytes,
            error: str or None
        }
    """
    result = {
        "success": False,
        "dcid": None,
        "dcid_bytes": None,
        "scid": None,
        "scid_bytes": None,
        "retry_token": None,
        "error": None
    }
    
    # Minimum Retry packet size: 1 (header) + 4 (version) + 1 (dcid_len) + 1 (scid_len) + 16 (tag) = 23
    if len(packet) < 23:
        result["error"] = "Packet too short for Retry"
        return result
    
    first_byte = packet[0]
    
    # Validate header form and fixed bit
    if not (first_byte & 0x80):
        result["error"] = "Not a Long Header packet"
        return result
    
    if not (first_byte & 0x40):
        result["error"] = "Fixed Bit not set"
        return result
    
    # Validate packet type (should be 3 for Retry)
    packet_type = (first_byte & 0x30) >> 4
    if packet_type != 3:
        result["error"] = f"Not a Retry packet (type={packet_type})"
        return result
    
    # Parse version
    version = struct.unpack(">I", packet[1:5])[0]
    if version != QUIC_VERSION:
        result["error"] = f"Version mismatch: expected 0x{QUIC_VERSION:08x}, got 0x{version:08x}"
        return result
    
    # Parse DCID
    dcid_len = packet[5]
    if len(packet) < 7 + dcid_len:
        result["error"] = "Packet too short for DCID"
        return result
    
    dcid = packet[6:6 + dcid_len]
    result["dcid"] = dcid.hex()
    result["dcid_bytes"] = dcid
    
    # Parse SCID
    scid_len_offset = 6 + dcid_len
    scid_len = packet[scid_len_offset]
    scid_start = scid_len_offset + 1
    
    if len(packet) < scid_start + scid_len + 16:  # +16 for integrity tag
        result["error"] = "Packet too short for SCID and integrity tag"
        return result
    
    scid = packet[scid_start:scid_start + scid_len]
    result["scid"] = scid.hex()
    result["scid_bytes"] = scid
    
    # Extract Retry Token (everything between SCID and integrity tag)
    token_start = scid_start + scid_len
    token_end = len(packet) - 16  # Last 16 bytes are integrity tag
    
    if token_end <= token_start:
        result["error"] = "No Retry Token in packet"
        return result
    
    retry_token = packet[token_start:token_end]
    integrity_tag = packet[token_end:]
    
    if debug:
        print(f"    Retry packet parsed:")
        print(f"      DCID: {result['dcid']}")
        print(f"      SCID: {result['scid']}")
        print(f"      Retry Token length: {len(retry_token)} bytes")
        print(f"      Integrity Tag: {integrity_tag.hex()}")
    
    # Verify integrity tag (RFC 9001 Section 5.8)
    if not verify_retry_integrity_tag(packet, original_dcid):
        result["error"] = "Retry Integrity Tag validation failed"
        if debug:
            print(f"      ❌ Integrity tag validation FAILED")
        return result
    
    if debug:
        print(f"      ✓ Integrity tag validation passed")
    
    result["retry_token"] = retry_token
    result["success"] = True
    
    return result

