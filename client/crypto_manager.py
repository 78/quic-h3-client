"""
QUIC Crypto Manager - Key derivation and encryption/decryption

Handles all cryptographic operations:
- Initial, Handshake, Application key derivation
- 0-RTT key derivation
- Key Update
- Packet encryption and decryption
"""

import hashlib
from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from quic.crypto import (
    derive_initial_secrets, derive_server_initial_secrets,
    derive_handshake_secrets, derive_application_secrets,
    build_client_finished_message, perform_ecdh,
    remove_header_protection, decrypt_payload, encrypt_payload,
    apply_header_protection,
    derive_resumption_master_secret, derive_0rtt_secrets,
    derive_0rtt_application_secrets, derive_handshake_secrets_with_psk,
    derive_next_application_secrets,
)


@dataclass
class CryptoSecrets:
    """Container for encryption secrets at a given level."""
    key: bytes = b""
    iv: bytes = b""
    hp: bytes = b""  # Header protection key
    traffic_secret: bytes = b""


@dataclass
class CryptoState:
    """Complete crypto state for the connection."""
    # Initial secrets
    client_initial: Optional[Dict[str, Any]] = None
    server_initial: Optional[Dict[str, Any]] = None
    
    # Handshake secrets
    handshake_secrets: Optional[Dict[str, Any]] = None
    handshake_secret: Optional[bytes] = None  # For deriving application secrets
    
    # Application (1-RTT) secrets
    application_secrets: Optional[Dict[str, Any]] = None
    
    # 0-RTT secrets
    zero_rtt_secrets: Optional[Dict[str, Any]] = None
    
    # Resumption
    resumption_master_secret: Optional[bytes] = None
    
    # Key update state
    key_phase: int = 0
    key_update_generation: int = 0
    previous_application_secrets: Optional[Dict[str, Any]] = None


class CryptoManager:
    """
    Manages all cryptographic operations for a QUIC connection.
    
    Responsibilities:
    - Key derivation (Initial, Handshake, Application, 0-RTT)
    - Packet encryption and decryption
    - Header protection
    - Key Update
    """
    
    def __init__(self, debug: bool = False):
        self.debug = debug
        self.state = CryptoState()
        
        # TLS handshake data
        self.private_key: Optional[X25519PrivateKey] = None
        self.client_hello: Optional[bytes] = None
        self.client_random: Optional[bytes] = None
        self.server_hello_data: Optional[bytes] = None
        self.client_finished_message: Optional[bytes] = None
        
        # 0-RTT specific
        self.zero_rtt_psk: Optional[bytes] = None
        self.zero_rtt_early_secret: Optional[bytes] = None
        self.zero_rtt_enabled: bool = False
        
        # Keylog callback
        self.on_keys_derived: Optional[callable] = None
    
    # =========================================================================
    # Initial Keys
    # =========================================================================
    
    def derive_initial_keys(self, dcid: bytes) -> None:
        """
        Derive Initial encryption keys from DCID.
        
        Args:
            dcid: Destination Connection ID
        """
        self.state.client_initial = derive_initial_secrets(dcid)
        self.state.server_initial = derive_server_initial_secrets(dcid)
        
        if self.debug:
            print(f"    ✓ Initial keys derived")
    
    @property
    def has_initial_keys(self) -> bool:
        return self.state.client_initial is not None
    
    @property
    def client_initial_secrets(self) -> Optional[Dict]:
        return self.state.client_initial
    
    @property
    def server_initial_secrets(self) -> Optional[Dict]:
        return self.state.server_initial
    
    # =========================================================================
    # Handshake Keys
    # =========================================================================
    
    def derive_handshake_keys(self, server_public_key: bytes, 
                               server_hello_data: bytes) -> None:
        """
        Derive Handshake keys from ECDH shared secret.
        
        Args:
            server_public_key: Server's X25519 public key from ServerHello
            server_hello_data: Raw ServerHello message
        """
        self.server_hello_data = server_hello_data
        
        shared_secret = perform_ecdh(self.private_key, server_public_key)
        transcript = self.client_hello + server_hello_data
        transcript_hash = hashlib.sha256(transcript).digest()
        
        # Use PSK-aware derivation if doing 0-RTT
        if self.zero_rtt_enabled and self.zero_rtt_psk:
            hs_secrets = derive_handshake_secrets_with_psk(
                shared_secret, transcript_hash,
                psk=self.zero_rtt_psk, debug=self.debug
            )
        else:
            hs_secrets = derive_handshake_secrets(
                shared_secret, transcript_hash, debug=self.debug
            )
        
        self.state.handshake_secrets = hs_secrets
        
        if self.debug:
            print(f"    ✓ Handshake keys derived")
            print(f"      ECDH shared secret: {shared_secret.hex()[:32]}...")
            if self.zero_rtt_enabled:
                print(f"      (with PSK for 0-RTT)")
        
        # Notify for keylog
        if self.on_keys_derived:
            self.on_keys_derived("handshake", {
                "client_secret": hs_secrets["client"]["traffic_secret"],
                "server_secret": hs_secrets["server"]["traffic_secret"],
            })
    
    @property
    def has_handshake_keys(self) -> bool:
        return self.state.handshake_secrets is not None
    
    @property
    def handshake_secrets(self) -> Optional[Dict]:
        return self.state.handshake_secrets
    
    # =========================================================================
    # Application Keys
    # =========================================================================
    
    def derive_application_keys(self, handshake_crypto_data: bytes) -> bytes:
        """
        Derive Application (1-RTT) keys and build Client Finished message.
        
        Args:
            handshake_crypto_data: Contiguous CRYPTO data from Handshake packets
            
        Returns:
            bytes: Client Finished message to be sent
        """
        if not self.has_handshake_keys:
            raise RuntimeError("Cannot derive application keys: no handshake keys")
        
        # Build transcript for Client Finished
        transcript = self.client_hello + self.server_hello_data + handshake_crypto_data
        transcript_hash = hashlib.sha256(transcript).digest()
        
        if self.debug:
            print(f"    📝 Transcript hash for Client Finished: {transcript_hash.hex()[:32]}...")
        
        # Build Client Finished TLS message
        client_hs_traffic_secret = self.state.handshake_secrets["client"]["traffic_secret"]
        finished_msg = build_client_finished_message(client_hs_traffic_secret, transcript_hash)
        self.client_finished_message = finished_msg
        
        if self.debug:
            print(f"    📝 Client Finished message: {len(finished_msg)} bytes")
            print(f"    📝 Deriving Application (1-RTT) secrets...")
        
        # Derive Application secrets
        self.state.application_secrets = derive_application_secrets(
            self.state.handshake_secrets["handshake_secret"],
            transcript_hash,
            debug=self.debug
        )
        
        # Compute transcript hash including Client Finished for resumption
        transcript_with_cf = transcript + finished_msg
        transcript_hash_with_cf = hashlib.sha256(transcript_with_cf).digest()
        
        # Derive Resumption Master Secret
        self.state.resumption_master_secret = derive_resumption_master_secret(
            self.state.application_secrets["master_secret"],
            transcript_hash_with_cf,
            debug=self.debug
        )
        
        if self.debug:
            print(f"    📝 Resumption Master Secret derived")
        
        # Notify for keylog
        if self.on_keys_derived:
            self.on_keys_derived("application", {
                "client_secret": self.state.application_secrets["client"]["traffic_secret"],
                "server_secret": self.state.application_secrets["server"]["traffic_secret"],
            })
        
        return finished_msg
    
    @property
    def has_application_keys(self) -> bool:
        return self.state.application_secrets is not None
    
    @property
    def application_secrets(self) -> Optional[Dict]:
        return self.state.application_secrets
    
    @property
    def resumption_master_secret(self) -> Optional[bytes]:
        return self.state.resumption_master_secret
    
    # =========================================================================
    # 0-RTT Keys
    # =========================================================================
    
    def derive_0rtt_keys(self, early_secret: bytes) -> None:
        """
        Derive 0-RTT keys from early secret.
        
        Args:
            early_secret: TLS early secret derived from PSK
        """
        self.zero_rtt_early_secret = early_secret
        client_hello_hash = hashlib.sha256(self.client_hello).digest()
        
        self.state.zero_rtt_secrets = derive_0rtt_application_secrets(
            early_secret, client_hello_hash, debug=self.debug
        )
        
        if self.debug:
            print(f"    ✓ 0-RTT keys derived")
        
        # Notify for keylog
        if self.on_keys_derived:
            self.on_keys_derived("early_data", {
                "client_secret": self.state.zero_rtt_secrets["client"]["traffic_secret"],
            })
    
    @property
    def has_0rtt_keys(self) -> bool:
        return self.state.zero_rtt_secrets is not None
    
    @property
    def zero_rtt_secrets(self) -> Optional[Dict]:
        return self.state.zero_rtt_secrets
    
    # =========================================================================
    # Key Update (RFC 9001 Section 6)
    # =========================================================================
    
    def initiate_key_update(self) -> bool:
        """
        Initiate a Key Update.
        
        Returns:
            bool: True if key update was initiated
        """
        if not self.has_application_keys:
            if self.debug:
                print(f"    ⚠️ Cannot initiate Key Update: no application secrets")
            return False
        
        # Derive next generation secrets
        next_secrets = derive_next_application_secrets(
            self.state.application_secrets, debug=self.debug
        )
        
        # Save current as previous
        self.state.previous_application_secrets = self.state.application_secrets
        
        # Switch to new keys
        self.state.application_secrets = next_secrets
        
        # Flip key phase
        self.state.key_phase = 1 - self.state.key_phase
        self.state.key_update_generation += 1
        
        if self.debug:
            print(f"    🔑 Key Update initiated!")
            print(f"       Generation: {self.state.key_update_generation}")
            print(f"       Key Phase: {self.state.key_phase}")
        
        # Notify for keylog
        if self.on_keys_derived:
            self.on_keys_derived("application", {
                "client_secret": self.state.application_secrets["client"]["traffic_secret"],
                "server_secret": self.state.application_secrets["server"]["traffic_secret"],
            })
        
        return True
    
    def handle_peer_key_update(self, received_key_phase: int) -> None:
        """
        Handle a Key Update initiated by the peer.
        
        Args:
            received_key_phase: Key phase from received packet
        """
        if received_key_phase == self.state.key_phase:
            return
        
        if self.debug:
            print(f"    🔑 Peer initiated Key Update (phase: {self.state.key_phase} → {received_key_phase})")
        
        # Save current as previous
        self.state.previous_application_secrets = self.state.application_secrets
        
        # Derive next secrets
        next_secrets = derive_next_application_secrets(
            self.state.application_secrets, debug=self.debug
        )
        
        # Update
        self.state.application_secrets = next_secrets
        self.state.key_phase = received_key_phase
        self.state.key_update_generation += 1
        
        # Notify for keylog
        if self.on_keys_derived:
            self.on_keys_derived("application", {
                "client_secret": self.state.application_secrets["client"]["traffic_secret"],
                "server_secret": self.state.application_secrets["server"]["traffic_secret"],
            })
        
        if self.debug:
            print(f"    ✅ Keys updated to generation {self.state.key_update_generation}")
    
    def complete_key_update(self) -> None:
        """Complete key update after receiving confirmation."""
        self.state.previous_application_secrets = None
        
        if self.debug:
            print(f"    ✅ Key Update complete (generation {self.state.key_update_generation})")
    
    @property
    def key_phase(self) -> int:
        return self.state.key_phase
    
    @property
    def has_previous_keys(self) -> bool:
        return self.state.previous_application_secrets is not None
    
    @property
    def previous_application_secrets(self) -> Optional[Dict]:
        return self.state.previous_application_secrets
    
    # =========================================================================
    # Packet Encryption/Decryption
    # =========================================================================
    
    def decrypt_initial_packet(self, packet: bytes, pn_offset: int,
                                largest_pn: int) -> tuple:
        """
        Decrypt an Initial packet.
        
        Args:
            packet: Raw packet bytes
            pn_offset: Offset to packet number
            largest_pn: Largest packet number seen (for PN reconstruction)
            
        Returns:
            tuple: (plaintext, packet_number) or (None, -1) on failure
        """
        return self._decrypt_long_header_packet(
            packet, pn_offset, largest_pn,
            self.state.server_initial, "Initial"
        )
    
    def decrypt_handshake_packet(self, packet: bytes, pn_offset: int,
                                  length: int, largest_pn: int) -> tuple:
        """
        Decrypt a Handshake packet.
        
        Args:
            packet: Raw packet bytes
            pn_offset: Offset to packet number
            length: Length field from header
            largest_pn: Largest packet number seen
            
        Returns:
            tuple: (plaintext, packet_number) or (None, -1) on failure
        """
        return self._decrypt_long_header_packet(
            packet, pn_offset, largest_pn,
            self.state.handshake_secrets["server"], "Handshake"
        )
    
    def _decrypt_long_header_packet(self, packet: bytes, pn_offset: int,
                                     largest_pn: int, secrets: Dict,
                                     level: str) -> tuple:
        """Common decryption logic for long header packets."""
        from quic.varint import decode_packet_number
        
        try:
            header, truncated_pn, pn_len = remove_header_protection(
                secrets, packet, pn_offset
            )
            
            pn = decode_packet_number(largest_pn, truncated_pn, pn_len * 8)
            
            # Calculate payload bounds
            # For long headers, we need the length field to determine payload end
            # The header info should be passed in, but we can work with pn_offset
            encrypted_payload = packet[pn_offset + pn_len:]
            
            plaintext = decrypt_payload(secrets, pn, header, encrypted_payload)
            
            if plaintext is None:
                if self.debug:
                    print(f"    ❌ {level} decryption failed PN={pn}")
                return None, -1
            
            if self.debug:
                print(f"    ✓ {level} decrypted PN={pn}, {len(plaintext)} bytes")
            
            return plaintext, pn
            
        except Exception as e:
            if self.debug:
                print(f"    ❌ {level} decryption exception: {e}")
            return None, -1
    
    def decrypt_1rtt_packet(self, packet: bytes, dcid_len: int,
                            largest_pn: int) -> tuple:
        """
        Decrypt a 1-RTT (Short Header) packet.
        
        Handles Key Phase detection for Key Update.
        
        Args:
            packet: Raw packet bytes
            dcid_len: Length of Destination Connection ID
            largest_pn: Largest packet number seen
            
        Returns:
            tuple: (plaintext, packet_number, key_phase) or (None, -1, -1) on failure
        """
        from quic.varint import decode_packet_number
        
        if len(packet) < 1 + dcid_len:
            return None, -1, -1
        
        first_byte = packet[0]
        pn_offset = 1 + dcid_len
        
        try:
            sample_offset = pn_offset + 4
            if sample_offset + 16 > len(packet):
                if self.debug:
                    print(f"    ❌ 1-RTT packet too short for sample")
                return None, -1, -1
            
            sample = packet[sample_offset:sample_offset + 16]
            
            # Try current keys first
            secrets_to_try = [
                (self.state.application_secrets, "current", self.state.key_phase),
            ]
            
            # If key update in progress, try previous keys too
            if self.state.previous_application_secrets:
                secrets_to_try.append(
                    (self.state.previous_application_secrets, "previous", 
                     1 - self.state.key_phase)
                )
            
            plaintext = None
            received_key_phase = None
            pn = None
            
            for secrets, secrets_name, expected_phase in secrets_to_try:
                hp_key = secrets["server"]["hp"]
                
                cipher = Cipher(algorithms.AES(hp_key), modes.ECB())
                encryptor = cipher.encryptor()
                mask = encryptor.update(sample) + encryptor.finalize()
                
                decrypted_first_byte = first_byte ^ (mask[0] & 0x1f)
                pn_length = (decrypted_first_byte & 0x03) + 1
                
                received_key_phase = (decrypted_first_byte >> 2) & 0x01
                
                pn_bytes = bytearray(packet[pn_offset:pn_offset + pn_length])
                for i in range(pn_length):
                    pn_bytes[i] ^= mask[1 + i]
                
                truncated_pn = 0
                for b in pn_bytes:
                    truncated_pn = (truncated_pn << 8) | b
                
                pn = decode_packet_number(largest_pn, truncated_pn, pn_length * 8)
                
                header = bytes([decrypted_first_byte]) + packet[1:pn_offset] + bytes(pn_bytes)
                encrypted_payload = packet[pn_offset + pn_length:]
                
                plaintext = decrypt_payload(secrets["server"], pn, header, encrypted_payload)
                
                if plaintext is not None:
                    break
            
            # If decryption failed, try deriving next keys (peer may have initiated update)
            if plaintext is None and received_key_phase is not None:
                if received_key_phase != self.state.key_phase:
                    next_secrets = derive_next_application_secrets(
                        self.state.application_secrets, debug=False
                    )
                    
                    hp_key = next_secrets["server"]["hp"]
                    cipher = Cipher(algorithms.AES(hp_key), modes.ECB())
                    encryptor = cipher.encryptor()
                    mask = encryptor.update(sample) + encryptor.finalize()
                    
                    decrypted_first_byte = first_byte ^ (mask[0] & 0x1f)
                    pn_length = (decrypted_first_byte & 0x03) + 1
                    
                    pn_bytes = bytearray(packet[pn_offset:pn_offset + pn_length])
                    for i in range(pn_length):
                        pn_bytes[i] ^= mask[1 + i]
                    
                    truncated_pn = 0
                    for b in pn_bytes:
                        truncated_pn = (truncated_pn << 8) | b
                    
                    pn = decode_packet_number(largest_pn, truncated_pn, pn_length * 8)
                    
                    header = bytes([decrypted_first_byte]) + packet[1:pn_offset] + bytes(pn_bytes)
                    encrypted_payload = packet[pn_offset + pn_length:]
                    
                    plaintext = decrypt_payload(next_secrets["server"], pn, header, encrypted_payload)
                    
                    if plaintext is not None:
                        # Peer initiated key update
                        self.handle_peer_key_update(received_key_phase)
            
            if plaintext is None:
                if self.debug:
                    print(f"    ❌ 1-RTT decryption failed")
                return None, -1, -1
            
            return plaintext, pn, received_key_phase
            
        except Exception as e:
            if self.debug:
                print(f"    ❌ 1-RTT decryption exception: {e}")
            return None, -1, -1
    
    def build_short_header_packet(self, dcid: bytes, pn: int, payload: bytes) -> bytes:
        """
        Build a 1-RTT (Short Header) packet.
        
        Args:
            dcid: Destination Connection ID
            pn: Packet number
            payload: Plaintext payload
            
        Returns:
            bytes: Complete encrypted packet
        """
        import struct
        
        # Determine PN length
        if pn < 0x100:
            pn_len = 1
            pn_bytes = bytes([pn])
        elif pn < 0x10000:
            pn_len = 2
            pn_bytes = struct.pack(">H", pn)
        elif pn < 0x1000000:
            pn_len = 3
            pn_bytes = struct.pack(">I", pn)[1:]
        else:
            pn_len = 4
            pn_bytes = struct.pack(">I", pn)
        
        # First byte with Key Phase
        first_byte = 0x40 | (pn_len - 1) | (self.state.key_phase << 2)
        
        # Header
        header = bytes([first_byte]) + dcid + pn_bytes
        
        # Get keys
        key = self.state.application_secrets["client"]["key"]
        iv = self.state.application_secrets["client"]["iv"]
        hp_key = self.state.application_secrets["client"]["hp"]
        
        # Ensure payload large enough for header protection
        min_payload_len = 4
        if len(payload) < min_payload_len:
            payload = payload + (b'\x00' * (min_payload_len - len(payload)))
        
        # Build nonce
        nonce = bytearray(iv)
        pn_bytes_padded = pn.to_bytes(len(iv), 'big')
        for i in range(len(nonce)):
            nonce[i] ^= pn_bytes_padded[i]
        
        # Encrypt
        cipher = AESGCM(key)
        ciphertext = cipher.encrypt(bytes(nonce), payload, header)
        
        # Header protection
        sample_offset = 4 - pn_len
        if sample_offset < 0:
            sample_offset = 0
        sample = ciphertext[sample_offset:sample_offset + 16]
        
        hp_cipher = Cipher(algorithms.AES(hp_key), modes.ECB())
        encryptor = hp_cipher.encryptor()
        mask = encryptor.update(sample) + encryptor.finalize()
        
        protected_first_byte = first_byte ^ (mask[0] & 0x1f)
        
        protected_pn = bytearray(pn_bytes)
        for i in range(pn_len):
            protected_pn[i] ^= mask[1 + i]
        
        protected_header = bytes([protected_first_byte]) + dcid + bytes(protected_pn)
        return protected_header + ciphertext
    
    def get_key_update_stats(self) -> dict:
        """Get Key Update statistics."""
        return {
            "key_phase": self.state.key_phase,
            "generation": self.state.key_update_generation,
            "has_previous_keys": self.has_previous_keys,
        }

