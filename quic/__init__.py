"""
QUIC Protocol Implementation

This package provides low-level QUIC protocol functionality:
- Variable-length integer encoding/decoding
- Cryptographic operations (HKDF, AEAD)
- Frame building and parsing
- Packet building and parsing
"""

from .constants import *
from .varint import encode_varint, decode_varint

