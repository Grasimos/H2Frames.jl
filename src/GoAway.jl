module GoAway
# src/frames/goaway.jl
# GOAWAY frame implementation for HTTP/2
# RFC 7540 Section 6.8
using ..FrameTypes
using ..Exc

import ..serialize_payload
import ..frame_type
import ..frame_flags
import ..stream_id


export GoAwayFrame,
    deserialize_goaway_frame,
    graceful_shutdown_goaway,
    protocol_error_goaway,
    internal_error_goaway,
    enhance_your_calm_goaway,
    get_last_stream_id, # Helper
    get_error_code  # Helper


"""
    GoAwayFrame

Represents an HTTP/2 GOAWAY frame.

GOAWAY frames are used to initiate shutdown of a connection or to signal serious
error conditions. They contain the highest stream ID that was processed and an
error code indicating the reason for the connection termination.

## Frame Format
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|R|                  Last-Stream-ID (31)                      |
+-+-------------------------------------------------------------+
|                      Error Code (32)                         |
+---------------------------------------------------------------+
|                  Additional Debug Data (*)                   |
+---------------------------------------------------------------+
```

## Fields
- `stream_id`: Must be 0 (connection-level frame)
- `flags`: No flags defined (should be 0)
- `last_stream_id`: The highest numbered stream ID processed
- `error_code`: Error code indicating reason for GOAWAY
- `debug_data`: Optional additional debug information
"""
struct GoAwayFrame <: HTTP2Frame

    last_stream_id::UInt32
    error_code::UInt32
    debug_data::Vector{UInt8}

    function GoAwayFrame(
        last_stream_id::UInt32,
        error_code::UInt32,
        debug_data::Vector{UInt8} = UInt8[],
    )
        if (last_stream_id & RESERVED_STREAM_ID_BIT) != 0
            throw(ProtocolError("GOAWAY last_stream_id reserved bit must be 0", 0))
        end
        new(last_stream_id, error_code, debug_data)
    end

    GoAwayFrame(last_stream_id::UInt32, error_code::UInt32, debug_message::String) =
        new(last_stream_id, error_code, Vector{UInt8}(debug_message))

    # Multiple dispatch outer constructor for GoAwayFrame to accept Int/UInt/Integer and promote to correct types
    function GoAwayFrame(
        last_stream_id::Integer,
        error_code::Integer,
        debug_data::Vector{UInt8} = UInt8[],
    )
        GoAwayFrame(UInt32(last_stream_id), UInt32(error_code), debug_data)
    end
    function GoAwayFrame(
        last_stream_id::Integer,
        error_code::Integer,
        debug_message::String,
    )
        GoAwayFrame(UInt32(last_stream_id), UInt32(error_code), debug_message)
    end
end
# Implementation of the full interface required by Frames.jl
frame_type(::GoAwayFrame) = GOAWAY_FRAME
stream_id(::GoAwayFrame) = 0 # Always 0 for GOAWAY
frame_flags(::GoAwayFrame) = 0x00 # Always 0, no flags



# Common GOAWAY frame constructors for RFC error codes
"""
    graceful_shutdown_goaway(last_stream_id::UInt32)

GOAWAY with NO_ERROR (0x0)
"""
graceful_shutdown_goaway(last_stream_id::UInt32) =
    GoAwayFrame(last_stream_id, GOAWAY_NO_ERROR)

"""
    protocol_error_goaway(last_stream_id::UInt32)

GOAWAY with PROTOCOL_ERROR (0x1)
"""
protocol_error_goaway(last_stream_id::UInt32) =
    GoAwayFrame(last_stream_id, GOAWAY_PROTOCOL_ERROR)

"""
    internal_error_goaway(last_stream_id::UInt32)

GOAWAY with INTERNAL_ERROR (0x2)
"""
internal_error_goaway(last_stream_id::UInt32) =
    GoAwayFrame(last_stream_id, GOAWAY_INTERNAL_ERROR)

"""
    enhance_your_calm_goaway(last_stream_id::UInt32)

GOAWAY with ENHANCE_YOUR_CALM (0xb)
"""
enhance_your_calm_goaway(last_stream_id::UInt32) =
    GoAwayFrame(last_stream_id, GOAWAY_ENHANCE_YOUR_CALM)



# Data access helpers
"""
    get_last_stream_id(frame::GoAwayFrame) -> UInt32

Get the last stream ID from a GOAWAY frame.
"""
get_last_stream_id(frame::GoAwayFrame) = frame.last_stream_id

"""
    get_error_code(frame::GoAwayFrame) -> UInt32

Get the error code from a GOAWAY frame.
"""
get_error_code(frame::GoAwayFrame) = frame.error_code

"""
    get_error_code_enum(frame::GoAwayFrame) -> ErrorCode

Get the error code as an enum from a GOAWAY frame.
"""
get_error_code_enum(frame::GoAwayFrame) = ErrorCode(frame.error_code)

"""
    get_debug_data(frame::GoAwayFrame) -> Vector{UInt8}

Get the debug data from a GOAWAY frame.
"""
get_debug_data(frame::GoAwayFrame) = frame.debug_data


# Serialization
"""
    serialize_frame(frame::GoAwayFrame) -> Vector{UInt8}

Serialize a GOAWAY frame to its wire format.
"""
function serialize_payload(frame::GoAwayFrame)
    buffer = IOBuffer()
    # R bit (31) + Last-Stream-ID (31 bits)
    write(buffer, hton(frame.last_stream_id & 0x7FFFFFFF))
    # Error Code (32 bits)
    write(buffer, hton(frame.error_code))
    # Additional Debug Data (*)
    if !isempty(frame.debug_data)
        write(buffer, frame.debug_data)
    end
    return take!(buffer)
end

"""
    deserialize_goaway_frame(header::FrameHeader, payload::Vector{UInt8}) -> GoAwayFrame

Deserialize a GOAWAY frame from its wire format.
"""
function deserialize_goaway_frame(header::FrameHeader, payload::Vector{UInt8})
    if header.frame_type != GOAWAY_FRAME || header.stream_id != 0
        throw(ProtocolError("Malformed GOAWAY frame header", header.stream_id))
    end
    if length(payload) < 8
        throw(
            FrameSizeError(
                "GOAWAY frame payload must be at least 8 bytes",
                header.stream_id,
            ),
        )
    end

    reader = IOBuffer(payload)
    last_stream_id = ntoh(read(reader, UInt32)) & 0x7FFFFFFF
    error_code = ntoh(read(reader, UInt32))
    debug_data = read(reader) # Reads the remaining bytes

    return GoAwayFrame(last_stream_id, error_code, debug_data)
end

"""
    validate_goaway_frame(frame::GoAwayFrame) -> Bool

Validate a GOAWAY frame according to HTTP/2 specification.
Returns true if valid, throws an exception if invalid.
"""
function validate_goaway_frame(frame::GoAwayFrame)
    if (frame.last_stream_id & RESERVED_STREAM_ID_BIT) != 0
        throw(FrameError("GOAWAY last_stream_id reserved bit must be 0"))
    end
    # The stream_id and flags are now checked by the interface.
    return true
end

# String representation for debugging
function Base.show(io::IO, frame::GoAwayFrame)
    error_name = try
        string(ErrorCode(frame.error_code))
    catch
        "UNKNOWN($(frame.error_code))"
    end

    debug_msg = get_debug_message(frame)
    debug_str = isempty(debug_msg) ? "" : ", debug=\"$debug_msg\""

    print(
        io,
        "GoAwayFrame(last_stream_id=$(frame.last_stream_id), error=$error_name$debug_str)",
    )
end

end
