"""
HTTP/3 Protocol Implementation (RFC 9114)

Provides:
- HTTP/3 frame building and parsing
- QPACK header compression with dynamic table support
- Stream management
"""

from .constants import *
from .frames import (
    build_h3_settings_frame,
    build_h3_max_push_id_frame,
    build_h3_control_stream_data,
    build_h3_qpack_encoder_stream_data,
    build_h3_qpack_decoder_stream_data,
    build_h3_headers_frame,
    build_h3_data_frame,
    build_qpack_request_headers,
    parse_h3_frames,
    parse_h3_settings,
    decode_qpack_headers,
)
from .streams import H3StreamManager, describe_stream_id
from .qpack import (
    QPACKDynamicTable,
    parse_qpack_encoder_instructions,
    build_section_acknowledgment,
    build_stream_cancellation,
    build_insert_count_increment,
)

