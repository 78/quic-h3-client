"""
HTTP/3 Protocol Constants (RFC 9114)
"""

# HTTP/3 Unidirectional Stream Types
H3_STREAM_TYPE_CONTROL = 0x00
H3_STREAM_TYPE_PUSH = 0x01
H3_STREAM_TYPE_QPACK_ENCODER = 0x02
H3_STREAM_TYPE_QPACK_DECODER = 0x03

H3_STREAM_TYPE_NAMES = {
    0x00: "Control Stream",
    0x01: "Push Stream",
    0x02: "QPACK Encoder Stream",
    0x03: "QPACK Decoder Stream",
}

# HTTP/3 Frame Types
H3_FRAME_DATA = 0x00
H3_FRAME_HEADERS = 0x01
H3_FRAME_CANCEL_PUSH = 0x03
H3_FRAME_SETTINGS = 0x04
H3_FRAME_PUSH_PROMISE = 0x05
H3_FRAME_GOAWAY = 0x07
H3_FRAME_MAX_PUSH_ID = 0x0d

H3_FRAME_TYPE_NAMES = {
    0x00: "DATA",
    0x01: "HEADERS",
    0x03: "CANCEL_PUSH",
    0x04: "SETTINGS",
    0x05: "PUSH_PROMISE",
    0x07: "GOAWAY",
    0x0d: "MAX_PUSH_ID",
}

# HTTP/3 Settings Parameters
H3_SETTINGS_MAX_TABLE_CAPACITY = 0x01      # QPACK max dynamic table capacity
H3_SETTINGS_MAX_HEADER_LIST_SIZE = 0x06   # Max header list size
H3_SETTINGS_BLOCKED_STREAMS = 0x07         # QPACK blocked streams
H3_SETTINGS_EXTENDED_CONNECT = 0x08        # Extended CONNECT for WebTransport

H3_SETTINGS_NAMES = {
    0x01: "QPACK_MAX_TABLE_CAPACITY",
    0x06: "MAX_HEADER_LIST_SIZE",
    0x07: "QPACK_BLOCKED_STREAMS",
    0x08: "EXTENDED_CONNECT",
}

# HTTP/3 Error Codes
H3_ERROR_NAMES = {
    0x0100: "H3_NO_ERROR",
    0x0101: "H3_GENERAL_PROTOCOL_ERROR",
    0x0102: "H3_INTERNAL_ERROR",
    0x0103: "H3_STREAM_CREATION_ERROR",
    0x0104: "H3_CLOSED_CRITICAL_STREAM",
    0x0105: "H3_FRAME_UNEXPECTED",
    0x0106: "H3_FRAME_ERROR",
    0x0107: "H3_EXCESSIVE_LOAD",
    0x0108: "H3_ID_ERROR",
    0x0109: "H3_SETTINGS_ERROR",
    0x010a: "H3_MISSING_SETTINGS",
    0x010b: "H3_REQUEST_REJECTED",
    0x010c: "H3_REQUEST_CANCELLED",
    0x010d: "H3_REQUEST_INCOMPLETE",
    0x010e: "H3_MESSAGE_ERROR",
    0x010f: "H3_CONNECT_ERROR",
    0x0110: "H3_VERSION_FALLBACK",
    0x0200: "QPACK_DECOMPRESSION_FAILED",
    0x0201: "QPACK_ENCODER_STREAM_ERROR",
    0x0202: "QPACK_DECODER_STREAM_ERROR",
}

# QPACK Static Table (RFC 9204 Appendix A)
# Index -> (name, value) for frequently used headers
QPACK_STATIC_TABLE = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    ("strict-transport-security", "max-age=31536000; includesubdomains"),
    ("strict-transport-security", "max-age=31536000; includesubdomains; preload"),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
]

# Build reverse lookup for QPACK encoding
QPACK_STATIC_TABLE_BY_NAME = {}
for idx, (name, value) in enumerate(QPACK_STATIC_TABLE):
    if name not in QPACK_STATIC_TABLE_BY_NAME:
        QPACK_STATIC_TABLE_BY_NAME[name] = []
    QPACK_STATIC_TABLE_BY_NAME[name].append((idx, value))

