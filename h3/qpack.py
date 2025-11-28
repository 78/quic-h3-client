"""
QPACK Dynamic Table Management (RFC 9204)

QPACK is the header compression format for HTTP/3.
This module manages the dynamic table and processes encoder stream instructions.
"""

from .constants import QPACK_STATIC_TABLE


class QPACKDynamicTable:
    """
    QPACK Dynamic Table (RFC 9204 Section 3.2).
    
    The dynamic table is a list of header name-value pairs.
    Entries are inserted at the beginning and evicted from the end.
    
    Indexing:
    - Absolute index: 0 for the first entry ever inserted, monotonically increasing
    - Relative index (for encoder): 0 for the most recently inserted entry
    - Post-base index: used when referencing entries inserted after the base
    """
    
    def __init__(self, max_capacity: int = 4096):
        self.max_capacity = max_capacity
        self.capacity = 0  # Current allocated capacity (set by encoder)
        self.entries = []  # List of (name, value) tuples
        self.size = 0  # Current size in bytes
        self.insert_count = 0  # Total number of entries ever inserted (absolute index base)
        self.acknowledged_insert_count = 0  # Insert count acknowledged by decoder
        self._debug = False
    
    def set_debug(self, debug: bool):
        """Enable/disable debug output."""
        self._debug = debug
    
    def set_capacity(self, capacity: int):
        """
        Set the dynamic table capacity (RFC 9204 Section 3.2.3).
        
        This is called when processing a Set Dynamic Table Capacity instruction.
        """
        if capacity > self.max_capacity:
            if self._debug:
                print(f"        ⚠️ QPACK: Requested capacity {capacity} exceeds max {self.max_capacity}")
            capacity = self.max_capacity
        
        self.capacity = capacity
        self._evict_to_fit(0)  # Evict entries if needed to meet new capacity
        
        if self._debug:
            print(f"        📊 QPACK: Dynamic table capacity set to {capacity} bytes")
    
    def _entry_size(self, name: str, value: str) -> int:
        """
        Calculate the size of an entry (RFC 9204 Section 3.2.1).
        
        Size = len(name) + len(value) + 32
        """
        return len(name.encode('utf-8')) + len(value.encode('utf-8')) + 32
    
    def _evict_to_fit(self, required_space: int):
        """Evict entries from the end of the table to make room."""
        while self.entries and self.size + required_space > self.capacity:
            name, value = self.entries.pop()
            entry_size = self._entry_size(name, value)
            self.size -= entry_size
            if self._debug:
                print(f"        🗑️ QPACK: Evicted entry '{name}: {value[:30]}...' ({entry_size} bytes)")
    
    def insert(self, name: str, value: str) -> int:
        """
        Insert a new entry into the dynamic table.
        
        Returns:
            int: The absolute index of the inserted entry
        """
        entry_size = self._entry_size(name, value)
        
        # Evict entries if needed
        self._evict_to_fit(entry_size)
        
        # Check if entry fits
        if entry_size > self.capacity:
            if self._debug:
                print(f"        ⚠️ QPACK: Entry too large ({entry_size} > {self.capacity}), not inserted")
            return -1
        
        # Insert at the beginning (most recent)
        self.entries.insert(0, (name, value))
        self.size += entry_size
        absolute_index = self.insert_count
        self.insert_count += 1
        
        if self._debug:
            print(f"        ➕ QPACK: Inserted entry[{absolute_index}] '{name}: {value[:50]}' ({entry_size} bytes)")
            print(f"           Table: {len(self.entries)} entries, {self.size}/{self.capacity} bytes")
        
        return absolute_index
    
    def insert_with_name_reference(self, name_index: int, is_static: bool, value: str) -> int:
        """
        Insert entry using name from static or dynamic table (RFC 9204 Section 4.3.2).
        
        Args:
            name_index: Index of the name in the referenced table
            is_static: True if referencing static table, False for dynamic
            value: The header value
            
        Returns:
            int: The absolute index of the inserted entry, or -1 on failure
        """
        if is_static:
            if name_index < len(QPACK_STATIC_TABLE):
                name = QPACK_STATIC_TABLE[name_index][0]
            else:
                if self._debug:
                    print(f"        ⚠️ QPACK: Invalid static table index {name_index}")
                return -1
        else:
            # Dynamic table reference - convert from relative index
            # Relative index 0 = most recently inserted entry
            if name_index < len(self.entries):
                name = self.entries[name_index][0]
            else:
                if self._debug:
                    print(f"        ⚠️ QPACK: Invalid dynamic table index {name_index}")
                return -1
        
        return self.insert(name, value)
    
    def duplicate(self, relative_index: int) -> int:
        """
        Duplicate an existing entry (RFC 9204 Section 4.3.4).
        
        Args:
            relative_index: Relative index (0 = most recent entry)
            
        Returns:
            int: The absolute index of the new entry, or -1 on failure
        """
        if relative_index >= len(self.entries):
            if self._debug:
                print(f"        ⚠️ QPACK: Cannot duplicate, invalid index {relative_index}")
            return -1
        
        name, value = self.entries[relative_index]
        return self.insert(name, value)
    
    def get_by_relative_index(self, relative_index: int):
        """
        Get entry by relative index (used during encoding reference).
        
        Relative index 0 = most recently inserted entry.
        
        Returns:
            tuple: (name, value) or None if not found
        """
        if 0 <= relative_index < len(self.entries):
            return self.entries[relative_index]
        return None
    
    def get_by_absolute_index(self, absolute_index: int):
        """
        Get entry by absolute index.
        
        Absolute index is the total insert count when the entry was added.
        
        Returns:
            tuple: (name, value) or None if not found
        """
        # Convert absolute index to position in current table
        # absolute_index = insert_count at time of insertion
        # Current relative position = (insert_count - 1 - absolute_index)
        # But we need to account for evictions
        
        # The entry at absolute_index X is at position:
        # (insert_count - 1) - X in the entries list, but only if it hasn't been evicted
        
        if absolute_index < 0 or absolute_index >= self.insert_count:
            return None
        
        # Calculate relative position from the end
        # Newest entry is at entries[0], has absolute_index = insert_count - 1
        # Entry at absolute_index X is at entries[insert_count - 1 - X]
        relative_from_newest = self.insert_count - 1 - absolute_index
        
        if relative_from_newest < len(self.entries):
            return self.entries[relative_from_newest]
        
        # Entry has been evicted
        return None
    
    def get_for_header_decode(self, index: int, base: int, is_post_base: bool):
        """
        Get entry for header block decoding (RFC 9204 Section 4.5).
        
        In the header block, dynamic table references can be:
        - Pre-base: index relative to Base
        - Post-base: index relative to Base (for entries inserted after Base)
        
        Args:
            index: The encoded index value
            base: The Base value from the header block prefix
            is_post_base: True if this is a post-base reference
            
        Returns:
            tuple: (name, value) or None if not found
        """
        if is_post_base:
            # Post-base index: references entries inserted after Base
            # Absolute index = Base + index
            absolute_index = base + index
        else:
            # Pre-base index: references entries before Base
            # Absolute index = Base - index - 1
            absolute_index = base - index - 1
        
        return self.get_by_absolute_index(absolute_index)
    
    def __len__(self):
        return len(self.entries)
    
    def __repr__(self):
        return f"QPACKDynamicTable(entries={len(self.entries)}, size={self.size}/{self.capacity})"


def parse_qpack_encoder_instructions(data: bytes, dynamic_table: QPACKDynamicTable, 
                                      debug: bool = False) -> int:
    """
    Parse QPACK encoder stream instructions (RFC 9204 Section 4.3).
    
    Encoder instructions:
    - Set Dynamic Table Capacity: 001xxxxx (5-bit prefix)
    - Insert With Name Reference: 1Txxxxxx (6-bit prefix for index)
    - Insert With Literal Name: 01Hxxxxx (5-bit prefix for name length)
    - Duplicate: 000xxxxx (5-bit prefix for index)
    
    Args:
        data: Raw encoder stream data (after stream type byte)
        dynamic_table: The dynamic table to update
        debug: Enable debug output
        
    Returns:
        int: Number of bytes consumed
    """
    offset = 0
    
    while offset < len(data):
        byte = data[offset]
        start_offset = offset  # Track start to detect no progress
        
        if byte & 0x80:
            # Insert With Name Reference: 1Txxxxxx
            # T=1: static table, T=0: dynamic table
            is_static = (byte & 0x40) != 0
            
            # Index with 6-bit prefix
            index, consumed = _decode_qpack_int(data, offset, 6)
            if consumed == 0:
                break  # Incomplete data
            offset += consumed
            
            # Value string
            value, consumed = _decode_qpack_string(data, offset)
            if consumed == 0:
                break  # Incomplete data
            offset += consumed
            
            res = dynamic_table.insert_with_name_reference(index, is_static, value)
            if res == -1:
                if debug:
                    print(f"    ⚠️ QPACK: Failed to insert with name reference (invalid index/size)")
                raise ValueError("QPACK corruption: Invalid insert with name reference")
            
            if debug:
                table_type = "static" if is_static else "dynamic"
                print(f"    📝 QPACK Encoder: Insert with {table_type} name ref[{index}] = '{value[:50]}'")
        
        elif byte & 0x40:
            # Insert With Literal Name: 01Hxxxxx
            # H: Huffman encoded name flag
            
            # Name string (5-bit prefix for length, but first bit is H flag)
            name, consumed = _decode_qpack_string_with_prefix(data, offset, 5)
            if consumed == 0:
                break  # Incomplete data
            offset += consumed
            
            # Value string
            value, consumed = _decode_qpack_string(data, offset)
            if consumed == 0:
                break  # Incomplete data
            offset += consumed
            
            res = dynamic_table.insert(name, value)
            if res == -1:
                if debug:
                    print(f"    ⚠️ QPACK: Failed to insert literal (invalid size)")
                raise ValueError("QPACK corruption: Invalid insert literal")
            
            if debug:
                print(f"    📝 QPACK Encoder: Insert literal '{name}' = '{value[:50]}'")
        
        elif byte & 0x20:
            # Set Dynamic Table Capacity: 001xxxxx
            capacity, consumed = _decode_qpack_int(data, offset, 5)
            if consumed == 0:
                break  # Incomplete data
            offset += consumed
            
            dynamic_table.set_capacity(capacity)
            
            if debug:
                print(f"    📝 QPACK Encoder: Set capacity = {capacity}")
        
        else:
            # Duplicate: 000xxxxx
            index, consumed = _decode_qpack_int(data, offset, 5)
            if consumed == 0:
                break  # Incomplete data
            offset += consumed
            
            res = dynamic_table.duplicate(index)
            if res == -1:
                if debug:
                    print(f"    ⚠️ QPACK: Failed to duplicate (invalid index)")
                raise ValueError("QPACK corruption: Invalid duplicate")
            
            if debug:
                print(f"    📝 QPACK Encoder: Duplicate entry[{index}]")
        
        # Safety check: ensure progress was made
        if offset == start_offset:
            break
    
    return offset


def _decode_qpack_int(data: bytes, offset: int, prefix_bits: int) -> tuple:
    """
    Decode QPACK integer encoding (RFC 9204 Section 4.1.1).
    
    Returns:
        tuple: (value, bytes_consumed) - returns (0, 0) if data is incomplete
    """
    if offset >= len(data):
        return 0, 0
    
    max_first = (1 << prefix_bits) - 1
    value = data[offset] & max_first
    consumed = 1
    
    if value < max_first:
        return value, consumed
    
    # Multi-byte encoding
    shift = 0
    complete = False
    while offset + consumed < len(data):
        byte = data[offset + consumed]
        value += (byte & 0x7f) << shift
        consumed += 1
        if not (byte & 0x80):
            # Last byte of multi-byte sequence (MSB is 0)
            complete = True
            break
        shift += 7
    
    # If we exited the loop without finding the last byte, data is incomplete
    if not complete:
        return 0, 0
    
    return value, consumed


def _decode_qpack_string(data: bytes, offset: int) -> tuple:
    """
    Decode QPACK string (7-bit prefix for length).
    
    Returns:
        tuple: (string, bytes_consumed)
    """
    return _decode_qpack_string_with_prefix(data, offset, 7)


def _decode_qpack_string_with_prefix(data: bytes, offset: int, prefix_bits: int) -> tuple:
    """
    Decode QPACK string with specified prefix bits.
    
    First bit of prefix byte indicates Huffman encoding (H flag).
    
    Returns:
        tuple: (string, bytes_consumed)
    """
    if offset >= len(data):
        return "", 0
    
    # H bit indicates Huffman encoding
    huffman = (data[offset] & (1 << prefix_bits)) != 0
    
    # Length with specified prefix
    length, len_consumed = _decode_qpack_int(data, offset, prefix_bits)
    
    if offset + len_consumed + length > len(data):
        return "", 0
    
    string_bytes = data[offset + len_consumed:offset + len_consumed + length]
    
    if huffman:
        try:
            from .frames import huffman_decode
            return huffman_decode(string_bytes), len_consumed + length
        except:
            return f"[huffman:{string_bytes.hex()}]", len_consumed + length
    
    try:
        return string_bytes.decode('utf-8'), len_consumed + length
    except:
        return string_bytes.hex(), len_consumed + length


def build_section_acknowledgment(stream_id: int) -> bytes:
    """
    Build QPACK Section Acknowledgment instruction (RFC 9204 Section 4.4.1).
    
    Sent on decoder stream to acknowledge header block processing.
    Format: 1xxxxxxx (7-bit prefix for stream ID)
    
    Args:
        stream_id: The stream ID being acknowledged
        
    Returns:
        bytes: Encoded instruction
    """
    # 1xxxxxxx with 7-bit prefix
    if stream_id < 127:
        return bytes([0x80 | stream_id])
    
    # Multi-byte encoding
    result = bytearray([0x80 | 0x7f])
    stream_id -= 127
    
    while stream_id >= 128:
        result.append((stream_id & 0x7f) | 0x80)
        stream_id >>= 7
    
    result.append(stream_id)
    return bytes(result)


def build_stream_cancellation(stream_id: int) -> bytes:
    """
    Build QPACK Stream Cancellation instruction (RFC 9204 Section 4.4.2).
    
    Sent on decoder stream when a stream is reset before completion.
    Format: 01xxxxxx (6-bit prefix for stream ID)
    
    Args:
        stream_id: The stream ID being cancelled
        
    Returns:
        bytes: Encoded instruction
    """
    # 01xxxxxx with 6-bit prefix
    if stream_id < 63:
        return bytes([0x40 | stream_id])
    
    # Multi-byte encoding
    result = bytearray([0x40 | 0x3f])
    stream_id -= 63
    
    while stream_id >= 128:
        result.append((stream_id & 0x7f) | 0x80)
        stream_id >>= 7
    
    result.append(stream_id)
    return bytes(result)


def build_insert_count_increment(increment: int) -> bytes:
    """
    Build QPACK Insert Count Increment instruction (RFC 9204 Section 4.4.3).
    
    Sent on decoder stream to increase Known Received Count.
    Format: 00xxxxxx (6-bit prefix for increment)
    
    Args:
        increment: The increment value
        
    Returns:
        bytes: Encoded instruction
    """
    # 00xxxxxx with 6-bit prefix
    if increment < 63:
        return bytes([increment])
    
    # Multi-byte encoding
    result = bytearray([0x3f])
    increment -= 63
    
    while increment >= 128:
        result.append((increment & 0x7f) | 0x80)
        increment >>= 7
    
    result.append(increment)
    return bytes(result)

