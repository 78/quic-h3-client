"""
TLS 1.3 Session Ticket Management for 0-RTT (RFC 8446)
"""

import struct
import time
import json
import os
from quic.crypto.hkdf import hkdf_expand_label


class SessionTicket:
    """
    TLS 1.3 Session Ticket for 0-RTT Early Data.
    
    Stores all information needed to resume a session:
    - ticket: The opaque ticket value
    - ticket_lifetime: How long the ticket is valid (seconds)
    - ticket_age_add: Value to obfuscate ticket age
    - ticket_nonce: Unique nonce for this ticket
    - max_early_data_size: Maximum 0-RTT data allowed
    - resumption_master_secret: For deriving PSK (set externally)
    - cipher_suite: The cipher suite used
    - creation_time: When the ticket was received
    """
    def __init__(self):
        self.ticket = b""
        self.ticket_lifetime = 0
        self.ticket_age_add = 0
        self.ticket_nonce = b""
        self.max_early_data_size = 0
        self.resumption_master_secret = None
        self.cipher_suite = 0x1301  # TLS_AES_128_GCM_SHA256 by default
        self.creation_time = 0.0
        self.server_name = ""
        self.alpn = ""
    
    def compute_psk(self) -> bytes:
        """
        Compute PSK from resumption_master_secret and ticket_nonce.
        PSK = HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, hash_len)
        """
        if self.resumption_master_secret is None:
            raise ValueError("resumption_master_secret not set")
        
        return hkdf_expand_label(
            self.resumption_master_secret,
            b"resumption",
            self.ticket_nonce,
            32  # SHA-256 hash length
        )
    
    def get_obfuscated_ticket_age(self, current_time: float) -> int:
        """
        Calculate obfuscated ticket age for 0-RTT.
        obfuscated_age = (age_ms + ticket_age_add) mod 2^32
        """
        age_ms = int((current_time - self.creation_time) * 1000)
        obfuscated_age = (age_ms + self.ticket_age_add) & 0xFFFFFFFF
        return obfuscated_age
    
    def is_valid(self, current_time: float) -> bool:
        """Check if the ticket is still valid."""
        age = current_time - self.creation_time
        return age < self.ticket_lifetime
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        result = {
            "ticket": self.ticket.hex(),
            "ticket_lifetime": self.ticket_lifetime,
            "ticket_age_add": self.ticket_age_add,
            "ticket_nonce": self.ticket_nonce.hex(),
            "max_early_data_size": self.max_early_data_size,
            "cipher_suite": f"0x{self.cipher_suite:04x}",
            "creation_time": self.creation_time,
            "server_name": self.server_name,
            "alpn": self.alpn,
        }
        # Include resumption_master_secret if available
        if self.resumption_master_secret:
            result["resumption_master_secret"] = self.resumption_master_secret.hex()
        return result
    
    @classmethod
    def from_dict(cls, data: dict) -> 'SessionTicket':
        """Create from dictionary."""
        ticket = cls()
        ticket.ticket = bytes.fromhex(data["ticket"])
        ticket.ticket_lifetime = data["ticket_lifetime"]
        ticket.ticket_age_add = data["ticket_age_add"]
        ticket.ticket_nonce = bytes.fromhex(data["ticket_nonce"])
        ticket.max_early_data_size = data.get("max_early_data_size", 0)
        ticket.cipher_suite = int(data.get("cipher_suite", "0x1301"), 16)
        ticket.creation_time = data.get("creation_time", 0.0)
        ticket.server_name = data.get("server_name", "")
        ticket.alpn = data.get("alpn", "")
        # Load resumption_master_secret if available
        if "resumption_master_secret" in data:
            ticket.resumption_master_secret = bytes.fromhex(data["resumption_master_secret"])
        return ticket
    
    def __repr__(self):
        return (f"SessionTicket(lifetime={self.ticket_lifetime}s, "
                f"ticket_len={len(self.ticket)}, "
                f"max_early_data={self.max_early_data_size})")


class SessionTicketStore:
    """
    Store for session tickets, supporting persistence and lookup.
    """
    def __init__(self, filename: str = None):
        self.tickets = {}  # server_name -> list of SessionTicket
        self.filename = filename
        if filename:
            self.load()
    
    def add_ticket(self, ticket: SessionTicket):
        """Add a ticket to the store."""
        key = ticket.server_name or "default"
        if key not in self.tickets:
            self.tickets[key] = []
        self.tickets[key].append(ticket)
        
        # Keep only last 2 tickets per server
        if len(self.tickets[key]) > 2:
            self.tickets[key] = self.tickets[key][-2:]
        
        if self.filename:
            self.save()
    
    def get_ticket(self, server_name: str, current_time: float = None) -> SessionTicket:
        """Get a valid ticket for the server."""
        if current_time is None:
            current_time = time.time()
        
        key = server_name or "default"
        if key not in self.tickets:
            return None
        
        # Find the newest valid ticket
        for ticket in reversed(self.tickets[key]):
            if ticket.is_valid(current_time):
                return ticket
        
        return None
    
    def save(self):
        """Save tickets to file."""
        if not self.filename:
            return
        
        data = {}
        for server, tickets in self.tickets.items():
            data[server] = [t.to_dict() for t in tickets]
        
        with open(self.filename, 'w') as f:
            json.dump(data, f, indent=2)
    
    def load(self):
        """Load tickets from file."""
        if not self.filename or not os.path.exists(self.filename):
            return
        
        try:
            with open(self.filename, 'r') as f:
                data = json.load(f)
            
            for server, ticket_list in data.items():
                self.tickets[server] = [SessionTicket.from_dict(t) for t in ticket_list]
        except (json.JSONDecodeError, IOError):
            pass


def parse_new_session_ticket(data: bytes, debug: bool = False) -> dict:
    """
    Parse TLS 1.3 NewSessionTicket message (RFC 8446 Section 4.6.1).
    
    struct {
        uint32 ticket_lifetime;           // 4 bytes
        uint32 ticket_age_add;            // 4 bytes  
        opaque ticket_nonce<0..255>;      // 1 byte length + nonce
        opaque ticket<1..2^16-1>;         // 2 bytes length + ticket
        Extension extensions<0..2^16-2>;  // 2 bytes length + extensions
    } NewSessionTicket;
    
    Returns dict with parsed fields and a SessionTicket object.
    """
    result = {
        "ticket_lifetime": 0,
        "ticket_age_add": 0,
        "ticket_nonce": b"",
        "ticket": b"",
        "max_early_data_size": 0,
        "extensions": [],
        "session_ticket": None,
    }
    
    if len(data) < 13:  # Minimum: 4+4+1+2+2 = 13 bytes
        if debug:
            print(f"    ❌ NewSessionTicket too short: {len(data)} bytes")
        return result
    
    offset = 0
    
    # ticket_lifetime (4 bytes)
    result["ticket_lifetime"] = struct.unpack(">I", data[offset:offset+4])[0]
    offset += 4
    
    # ticket_age_add (4 bytes)
    result["ticket_age_add"] = struct.unpack(">I", data[offset:offset+4])[0]
    offset += 4
    
    # ticket_nonce (1 byte length + nonce)
    nonce_len = data[offset]
    offset += 1
    result["ticket_nonce"] = data[offset:offset+nonce_len]
    offset += nonce_len
    
    # ticket (2 bytes length + ticket)
    if offset + 2 > len(data):
        return result
    ticket_len = struct.unpack(">H", data[offset:offset+2])[0]
    offset += 2
    result["ticket"] = data[offset:offset+ticket_len]
    offset += ticket_len
    
    # extensions (2 bytes length + extensions)
    if offset + 2 > len(data):
        return result
    ext_len = struct.unpack(">H", data[offset:offset+2])[0]
    offset += 2
    ext_data = data[offset:offset+ext_len]
    
    # Parse extensions
    ext_offset = 0
    while ext_offset + 4 <= len(ext_data):
        ext_type = struct.unpack(">H", ext_data[ext_offset:ext_offset+2])[0]
        ext_length = struct.unpack(">H", ext_data[ext_offset+2:ext_offset+4])[0]
        ext_value = ext_data[ext_offset+4:ext_offset+4+ext_length]
        
        ext_info = {
            "type": ext_type,
            "length": ext_length,
        }
        
        # early_data extension (type 42)
        if ext_type == 42 and ext_length == 4:
            max_early_data = struct.unpack(">I", ext_value)[0]
            ext_info["name"] = "early_data"
            ext_info["max_early_data_size"] = max_early_data
            result["max_early_data_size"] = max_early_data
        else:
            ext_info["name"] = f"unknown(0x{ext_type:04x})"
            ext_info["data"] = ext_value.hex()
        
        result["extensions"].append(ext_info)
        ext_offset += 4 + ext_length
    
    # Create SessionTicket object
    session_ticket = SessionTicket()
    session_ticket.ticket = result["ticket"]
    session_ticket.ticket_lifetime = result["ticket_lifetime"]
    session_ticket.ticket_age_add = result["ticket_age_add"]
    session_ticket.ticket_nonce = result["ticket_nonce"]
    session_ticket.max_early_data_size = result["max_early_data_size"]
    session_ticket.creation_time = time.time()
    result["session_ticket"] = session_ticket
    
    if debug:
        print(f"    📋 NewSessionTicket:")
        print(f"        Lifetime: {result['ticket_lifetime']} seconds ({result['ticket_lifetime']//60} minutes)")
        print(f"        Age Add: {result['ticket_age_add']}")
        print(f"        Nonce: {result['ticket_nonce'].hex()}")
        print(f"        Ticket Length: {len(result['ticket'])} bytes")
        print(f"        Ticket Preview: {result['ticket'][:32].hex()}...")
        if result["max_early_data_size"] > 0:
            print(f"        Max Early Data: {result['max_early_data_size']} bytes (0-RTT enabled)")
        if result["extensions"]:
            print(f"        Extensions: {len(result['extensions'])}")
            for ext in result["extensions"]:
                print(f"          - {ext.get('name', 'unknown')}: {ext}")
    
    return result

