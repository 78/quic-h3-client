"""
QUIC AEAD Encryption/Decryption and Header Protection (RFC 9001)
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt_payload(secrets: dict, packet_number: int, header: bytes, payload: bytes) -> bytes:
    """
    Encrypt QUIC packet payload using AES-128-GCM.
    
    Args:
        secrets: Dict with 'key' and 'iv'
        packet_number: Packet number (used with IV to create nonce)
        header: Unprotected header (used as additional data)
        payload: Plaintext payload to encrypt
        
    Returns:
        bytes: Ciphertext with authentication tag
    """
    # Build nonce: IV XOR packet_number (padded to 12 bytes)
    nonce = bytearray(secrets["iv"])
    pn_bytes = packet_number.to_bytes(12, byteorder='big')
    for i in range(12):
        nonce[i] ^= pn_bytes[i]
    
    # Encrypt with AEAD
    aesgcm = AESGCM(secrets["key"])
    ciphertext = aesgcm.encrypt(bytes(nonce), payload, header)
    
    return ciphertext


def decrypt_payload(secrets: dict, packet_number: int, header: bytes, encrypted_payload: bytes) -> bytes:
    """
    Decrypt QUIC packet payload using AES-128-GCM.
    
    Args:
        secrets: Dict with 'key' and 'iv'
        packet_number: Packet number
        header: Unprotected header (used as additional data)
        encrypted_payload: Ciphertext with authentication tag
        
    Returns:
        bytes: Decrypted plaintext, or None if decryption fails
    """
    # Build nonce: IV XOR packet_number (padded to 12 bytes)
    nonce = bytearray(secrets["iv"])
    pn_bytes = packet_number.to_bytes(12, byteorder='big')
    for i in range(12):
        nonce[i] ^= pn_bytes[i]
    
    # Decrypt with AEAD
    aesgcm = AESGCM(secrets["key"])
    try:
        plaintext = aesgcm.decrypt(bytes(nonce), encrypted_payload, header)
        return plaintext
    except Exception as e:
        print(f"    Decryption failed: {e}")
        return None


def apply_header_protection(secrets: dict, header: bytes, encrypted_payload: bytes, 
                           pn_offset: int, pn_length: int) -> bytes:
    """
    Apply QUIC header protection.
    
    Args:
        secrets: Dict with 'hp' key
        header: Unprotected header
        encrypted_payload: Encrypted payload (for sample)
        pn_offset: Offset of packet number in header
        pn_length: Length of packet number
        
    Returns:
        bytes: Protected header
    """
    # Sample starts 4 bytes after the start of the Packet Number field
    sample_start = 4 - pn_length
    sample = encrypted_payload[sample_start:sample_start + 16]
    
    # Generate mask using AES-ECB
    cipher = Cipher(algorithms.AES(secrets["hp"]), modes.ECB())
    encryptor = cipher.encryptor()
    mask = encryptor.update(sample) + encryptor.finalize()
    
    # Apply mask to header
    protected_header = bytearray(header)
    
    # Protect first byte (lower 4 bits for long header, lower 5 bits for short header)
    if protected_header[0] & 0x80:  # Long header
        protected_header[0] ^= mask[0] & 0x0f
    else:  # Short header
        protected_header[0] ^= mask[0] & 0x1f
    
    # Protect packet number bytes
    for i in range(pn_length):
        protected_header[pn_offset + i] ^= mask[1 + i]
    
    return bytes(protected_header)


def remove_header_protection(secrets: dict, packet: bytes, pn_offset: int) -> tuple:
    """
    Remove header protection and return unprotected header info.
    
    Args:
        secrets: Dict with 'hp' key
        packet: Complete packet with protected header
        pn_offset: Offset where packet number starts
        
    Returns:
        tuple: (unprotected_header, packet_number, pn_length)
    """
    # Sample is taken from the encrypted payload, 4 bytes after packet number offset
    sample_offset = pn_offset + 4
    sample = packet[sample_offset:sample_offset + 16]
    
    # Generate mask using AES-ECB
    cipher = Cipher(algorithms.AES(secrets["hp"]), modes.ECB())
    encryptor = cipher.encryptor()
    mask = encryptor.update(sample) + encryptor.finalize()
    
    # Unmask first byte to get packet number length
    first_byte = packet[0]
    if first_byte & 0x80:  # Long header
        unmasked_first = first_byte ^ (mask[0] & 0x0f)
    else:  # Short header
        unmasked_first = first_byte ^ (mask[0] & 0x1f)
    
    pn_length = (unmasked_first & 0x03) + 1
    
    # Unmask packet number
    pn_bytes = bytearray(packet[pn_offset:pn_offset + pn_length])
    for i in range(pn_length):
        pn_bytes[i] ^= mask[1 + i]
    
    # Reconstruct packet number
    packet_number = 0
    for b in pn_bytes:
        packet_number = (packet_number << 8) | b
    
    # Build unprotected header
    unprotected_header = bytes([unmasked_first]) + packet[1:pn_offset] + bytes(pn_bytes)
    
    return unprotected_header, packet_number, pn_length

