"""
QUIC Protocol Constants (RFC 9000, RFC 9001)
"""

# QUIC Version 1
QUIC_VERSION = 0x00000001

# QUIC Initial salt for version 1 (RFC 9001)
QUIC_V1_INITIAL_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

# TLS 1.3 fixed secrets (no PSK, so these are constants)
# Early Secret = HKDF-Extract(salt=0, IKM=0) - always the same
TLS13_EARLY_SECRET = bytes.fromhex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")

# Derived Secret = HKDF-Expand-Label(early_secret, "derived", empty_hash, 32) - always the same
TLS13_DERIVED_SECRET = bytes.fromhex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba")

# QUIC Long Header Packet Types
PACKET_TYPE_INITIAL = 0
PACKET_TYPE_0RTT = 1
PACKET_TYPE_HANDSHAKE = 2
PACKET_TYPE_RETRY = 3

PACKET_TYPE_NAMES = {
    0: "Initial",
    1: "0-RTT",
    2: "Handshake",
    3: "Retry"
}

# QUIC Frame Types
FRAME_PADDING = 0x00
FRAME_PING = 0x01
FRAME_ACK = 0x02
FRAME_ACK_ECN = 0x03
FRAME_RESET_STREAM = 0x04
FRAME_STOP_SENDING = 0x05
FRAME_CRYPTO = 0x06
FRAME_NEW_TOKEN = 0x07
FRAME_STREAM_BASE = 0x08
FRAME_MAX_DATA = 0x10
FRAME_MAX_STREAM_DATA = 0x11
FRAME_MAX_STREAMS_BIDI = 0x12
FRAME_MAX_STREAMS_UNI = 0x13
FRAME_DATA_BLOCKED = 0x14
FRAME_STREAM_DATA_BLOCKED = 0x15
FRAME_STREAMS_BLOCKED_BIDI = 0x16
FRAME_STREAMS_BLOCKED_UNI = 0x17
FRAME_NEW_CONNECTION_ID = 0x18
FRAME_RETIRE_CONNECTION_ID = 0x19
FRAME_PATH_CHALLENGE = 0x1a
FRAME_PATH_RESPONSE = 0x1b
FRAME_CONNECTION_CLOSE = 0x1c
FRAME_CONNECTION_CLOSE_APP = 0x1d
FRAME_HANDSHAKE_DONE = 0x1e

# QUIC Transport Parameters (RFC 9000 Section 18)
TRANSPORT_PARAM_NAMES = {
    0x00: "original_destination_connection_id",
    0x01: "max_idle_timeout",
    0x02: "stateless_reset_token",
    0x03: "max_udp_payload_size",
    0x04: "initial_max_data",
    0x05: "initial_max_stream_data_bidi_local",
    0x06: "initial_max_stream_data_bidi_remote",
    0x07: "initial_max_stream_data_uni",
    0x08: "initial_max_streams_bidi",
    0x09: "initial_max_streams_uni",
    0x0a: "ack_delay_exponent",
    0x0b: "max_ack_delay",
    0x0c: "disable_active_migration",
    0x0d: "preferred_address",
    0x0e: "active_connection_id_limit",
    0x0f: "initial_source_connection_id",
    0x10: "retry_source_connection_id",
}

# Binary transport parameters (connection IDs, tokens)
TRANSPORT_PARAM_BINARY = {0x00, 0x02, 0x0f, 0x10}

# Flag transport parameters (presence means True)
TRANSPORT_PARAM_FLAGS = {0x0c}

