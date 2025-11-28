"""
QUIC Cryptographic Operations

Provides:
- HKDF key derivation functions
- AEAD encryption/decryption
- Initial/Handshake/Application key derivation
- 0-RTT key derivation for session resumption
"""

from .hkdf import hkdf_extract, hkdf_expand_label
from .keys import (
    derive_initial_secrets,
    derive_server_initial_secrets,
    derive_handshake_secrets,
    derive_application_secrets,
    compute_finished_verify_data,
    build_client_finished_message,
    perform_ecdh,
    derive_resumption_master_secret,
    derive_0rtt_secrets,
    derive_0rtt_application_secrets,
    derive_handshake_secrets_with_psk,
    derive_next_application_secrets,
)
from .aead import (
    encrypt_payload,
    decrypt_payload,
    apply_header_protection,
    remove_header_protection,
)

