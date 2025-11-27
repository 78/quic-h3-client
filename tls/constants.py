"""
TLS 1.3 Constants (RFC 8446)
"""

# TLS 1.3 cipher suite
TLS_AES_128_GCM_SHA256 = 0x1301
TLS_AES_256_GCM_SHA384 = 0x1302
TLS_CHACHA20_POLY1305_SHA256 = 0x1303

CIPHER_SUITE_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256"
}

# TLS extensions
EXT_SERVER_NAME = 0
EXT_SUPPORTED_GROUPS = 10
EXT_SIGNATURE_ALGORITHMS = 13
EXT_ALPN = 16
EXT_EARLY_DATA = 42
EXT_SUPPORTED_VERSIONS = 43
EXT_PSK_KEY_EXCHANGE_MODES = 45
EXT_PRE_SHARED_KEY = 41
EXT_KEY_SHARE = 51
EXT_QUIC_TRANSPORT_PARAMS = 57

# PSK key exchange modes
PSK_KE_MODE = 0  # PSK-only key exchange (no ECDH)
PSK_DHE_KE_MODE = 1  # PSK with ECDH key exchange

EXTENSION_NAMES = {
    0: "server_name",
    10: "supported_groups",
    13: "signature_algorithms",
    16: "alpn",
    41: "pre_shared_key",
    42: "early_data",
    43: "supported_versions",
    45: "psk_key_exchange_modes",
    51: "key_share",
    57: "quic_transport_params"
}

# Named groups
GROUP_X25519 = 29
GROUP_SECP256R1 = 23
GROUP_SECP384R1 = 24
GROUP_SECP521R1 = 25

GROUP_NAMES = {
    23: "secp256r1",
    24: "secp384r1",
    25: "secp521r1",
    29: "x25519",
    30: "x448",
    256: "ffdhe2048",
    257: "ffdhe3072",
    258: "ffdhe4096",
}

# Signature algorithms
SIG_ECDSA_SECP256R1_SHA256 = 0x0403
SIG_RSA_PSS_RSAE_SHA256 = 0x0804
SIG_RSA_PKCS1_SHA256 = 0x0401

SIGNATURE_ALGORITHM_NAMES = {
    0x0401: "rsa_pkcs1_sha256",
    0x0501: "rsa_pkcs1_sha384",
    0x0601: "rsa_pkcs1_sha512",
    0x0403: "ecdsa_secp256r1_sha256",
    0x0503: "ecdsa_secp384r1_sha384",
    0x0603: "ecdsa_secp521r1_sha512",
    0x0804: "rsa_pss_rsae_sha256",
    0x0805: "rsa_pss_rsae_sha384",
    0x0806: "rsa_pss_rsae_sha512",
    0x0807: "ed25519",
    0x0808: "ed448",
}

# TLS handshake message types
HANDSHAKE_CLIENT_HELLO = 1
HANDSHAKE_SERVER_HELLO = 2
HANDSHAKE_NEW_SESSION_TICKET = 4
HANDSHAKE_ENCRYPTED_EXTENSIONS = 8
HANDSHAKE_CERTIFICATE = 11
HANDSHAKE_CERTIFICATE_REQUEST = 13
HANDSHAKE_CERTIFICATE_VERIFY = 15
HANDSHAKE_FINISHED = 20

HANDSHAKE_TYPE_NAMES = {
    1: "ClientHello",
    2: "ServerHello",
    4: "NewSessionTicket",
    8: "EncryptedExtensions",
    11: "Certificate",
    13: "CertificateRequest",
    15: "CertificateVerify",
    20: "Finished"
}

