"""
Key Logging Utilities for Wireshark/tshark

Writes TLS secrets in SSLKEYLOGFILE format for packet inspection.
"""


def write_keylog(keylog_file: str, client_random: bytes, 
                 client_hs_secret: bytes = None, server_hs_secret: bytes = None,
                 client_traffic_secret: bytes = None, server_traffic_secret: bytes = None,
                 client_early_secret: bytes = None) -> list:
    """
    Write secrets to keylog file in SSLKEYLOGFILE format for Wireshark.
    
    Format:
        CLIENT_EARLY_TRAFFIC_SECRET <client_random_hex> <secret_hex>
        SERVER_HANDSHAKE_TRAFFIC_SECRET <client_random_hex> <secret_hex>
        CLIENT_HANDSHAKE_TRAFFIC_SECRET <client_random_hex> <secret_hex>
        SERVER_TRAFFIC_SECRET_0 <client_random_hex> <secret_hex>
        CLIENT_TRAFFIC_SECRET_0 <client_random_hex> <secret_hex>
    
    Args:
        keylog_file: Path to the keylog file
        client_random: 32-byte client random from ClientHello
        client_hs_secret: Client handshake traffic secret
        server_hs_secret: Server handshake traffic secret
        client_traffic_secret: Client application traffic secret
        server_traffic_secret: Server application traffic secret
        client_early_secret: Client early (0-RTT) traffic secret
        
    Returns:
        list: Lines that were written to the file
    """
    client_random_hex = client_random.hex()
    lines = []
    
    # 0-RTT early traffic secret (must be first for Wireshark)
    if client_early_secret:
        lines.append(f"CLIENT_EARLY_TRAFFIC_SECRET {client_random_hex} {client_early_secret.hex()}")
    
    if server_hs_secret:
        lines.append(f"SERVER_HANDSHAKE_TRAFFIC_SECRET {client_random_hex} {server_hs_secret.hex()}")
    if client_hs_secret:
        lines.append(f"CLIENT_HANDSHAKE_TRAFFIC_SECRET {client_random_hex} {client_hs_secret.hex()}")
    if server_traffic_secret:
        lines.append(f"SERVER_TRAFFIC_SECRET_0 {client_random_hex} {server_traffic_secret.hex()}")
    if client_traffic_secret:
        lines.append(f"CLIENT_TRAFFIC_SECRET_0 {client_random_hex} {client_traffic_secret.hex()}")
    
    with open(keylog_file, "a") as f:
        for line in lines:
            f.write(line + "\n")
    
    return lines

