"""
HKDF Functions for TLS 1.3 / QUIC Key Derivation (RFC 5869, RFC 8446)
"""

import hmac
import hashlib
import struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.backends import default_backend


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """
    HKDF-Extract using SHA-256.
    
    Args:
        salt: Salt value (optional, can be zero-length)
        ikm: Input keying material
        
    Returns:
        bytes: Pseudorandom key (32 bytes for SHA-256)
    """
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand_label(secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
    """
    HKDF-Expand-Label as defined in TLS 1.3 (RFC 8446 Section 7.1).
    
    HkdfLabel structure:
        uint16 length
        opaque label<7..255> = "tls13 " + Label
        opaque context<0..255>
    
    Args:
        secret: The secret to expand
        label: The label (without "tls13 " prefix)
        context: Context (usually transcript hash or empty)
        length: Desired output length
        
    Returns:
        bytes: Derived key material
    """
    # Build HkdfLabel structure
    hkdf_label = struct.pack(">H", length)  # length (2 bytes)
    full_label = b"tls13 " + label
    hkdf_label += struct.pack("B", len(full_label)) + full_label  # label
    hkdf_label += struct.pack("B", len(context)) + context  # context
    
    hkdf = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=length,
        info=hkdf_label,
        backend=default_backend()
    )
    return hkdf.derive(secret)

