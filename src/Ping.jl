module Ping
# src/frames/ping.jl
# PING frame implementation for HTTP/2
# RFC 7540 Section 6.7
using ..FrameTypes
using ..Exc

import ..serialize_payload
import ..frame_type
import ..frame_flags
import ..stream_id

export PingFrame,
    PingAckFrame,
    deserialize_ping_frame,
    is_ping_ack,
    get_ping_data,
    get_ping_data_as_uint64,
    # The following are high-level and useful
    process_ping_frame,
    generate_ping_data,
    generate_ping_data_with_timestamp


const PING_ACK = 0x1

"""
    PingFrame

Represents an HTTP/2 PING frame.

PING frames are used to measure round-trip time and check connection liveness.
They can be sent by either endpoint and must be acknowledged with a PING frame
with the ACK flag set.

## Frame Format
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Opaque Data (64)                         |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

"""
struct PingFrame <: HTTP2Frame
    ack::Bool
    data::Vector{UInt8}

    function PingFrame(data::Vector{UInt8}; ack::Bool = false)
        if length(data) != 8
            throw(
                FrameSizeError(
                    "PING frame data must be exactly 8 bytes, got $(length(data))",
                ),
            )
        end
        return new(ack, data)
    end
    function PingFrame(data::NTuple{8,UInt8}; ack::Bool = false)
        return new(ack, collect(data))
    end
    function PingFrame(data::UInt64; ack::Bool = false)
        return new(ack, reinterpret(UInt8, [hton(data)]))
    end
end



"""
    PingAckFrame(ping_frame::PingFrame)

Create a PING ACK frame responding to the given PING frame.
The ACK frame will contain the same data as the original PING.
"""
PingAckFrame(ping_request::PingFrame) = PingFrame(ping_request.data; ack = true)

# Frame type identification
frame_type(::PingFrame) = PING_FRAME
stream_id(::PingFrame) = 0
frame_flags(frame::PingFrame) = frame.ack ? PING_ACK : UInt8(0)


# Flag checking
"""
    is_ping_ack(frame::PingFrame) -> Bool

Check if this PING frame is an acknowledgment (has ACK flag set).
"""
is_ping_ack(frame::PingFrame) = frame.ack

"""
    is_ping_request(frame::PingFrame) -> Bool

Check if this PING frame is a request (does not have ACK flag set).
"""
is_ping_request(frame::PingFrame) = !frame.ack

# Data access helpers
"""
    get_ping_data(frame::PingFrame) -> Vector{UInt8}

Get the 8-byte opaque data from a PING frame.
"""
get_ping_data(frame::PingFrame) = frame.data

"""
    get_ping_data_as_uint64(frame::PingFrame) -> UInt64

Get the PING frame data as a 64-bit unsigned integer.
"""
function get_ping_data_as_uint64(frame::PingFrame)
    # Use ntoh and reinterpret for efficient conversion
    return ntoh(reinterpret(UInt64, frame.data)[1])
end
# Serialization
"""
    serialize_frame(frame::PingFrame) -> Vector{UInt8}

Serialize a PING frame to its wire format.
"""
function serialize_payload(frame::PingFrame)
    # The payload is simply the 8-byte data.
    return frame.data
end

"""
    deserialize_ping_frame(header::FrameHeader, payload::Vector{UInt8}) -> PingFrame

Deserialize a PING frame from its wire format.
"""
function deserialize_ping_frame(header::FrameHeader, payload::Vector{UInt8})
    if header.frame_type != PING_FRAME || header.stream_id != 0
        throw(ProtocolError("Malformed PING frame header", header.stream_id))
    end
    if length(payload) != 8
        throw(FrameSizeError("PING frame payload must be 8 bytes", header.stream_id))
    end
    ack = (header.flags & PING_ACK) != 0
    return PingFrame(payload; ack = ack)
end

"""
    generate_ping_data() -> Vector{UInt8}

Generate 8 bytes of random data for a PING frame.
This can be used to create unique PING requests.
"""
generate_ping_data() = rand(UInt8, 8)

"""
    generate_ping_data_with_timestamp() -> Vector{UInt8}

Generate PING data that includes the current timestamp.
This can be useful for measuring round-trip times.
"""
function generate_ping_data_with_timestamp()
    timestamp = time()
    # Convert timestamp to UInt64 (microseconds since epoch)
    timestamp_us = UInt64(timestamp * 1_000_000)
    return collect(reinterpret(UInt8, [timestamp_us]))
end



# String representation for debugging
function Base.show(io::IO, frame::PingFrame)
    ack_str = is_ping_ack(frame) ? " (ACK)" : ""
    data_hex = join([string(b, base = 16, pad = 2) for b in frame.data], "")
    print(io, "PingFrame$(ack_str)(data=0x$data_hex)")
end

end
