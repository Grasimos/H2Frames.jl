module WindowUpdate
# frames/window_update.jl
# WINDOW_UPDATE frame implementation for HTTP/2
# RFC 7540 Section 6.9
using ..FrameTypes
using ..Exc

import ..serialize_payload
import ..frame_type
import ..frame_flags
import ..stream_id

export WindowUpdateFrame,
    deserialize_window_update_frame,
    is_connection_level,
    is_stream_level,
    create_connection_window_update,
    create_stream_window_update



"""
    WindowUpdateFrame

Represents an HTTP/2 WINDOW_UPDATE frame.

The WINDOW_UPDATE frame is used to implement flow control. It can apply to either
a specific stream or to the entire connection.

Frame Format:
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|R|              Window Size Increment (31)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Fields:
- `stream_id`: Stream identifier (0 for connection-level)
- `window_size_increment`: The number of octets to increment the flow control window
"""
struct WindowUpdateFrame <: HTTP2Frame
    stream_id::UInt32
    window_size_increment::UInt32

    function WindowUpdateFrame(stream_id::UInt32, window_size_increment::UInt32)
        if window_size_increment == 0
            throw(ProtocolError("WINDOW_UPDATE increment must be non-zero", stream_id))
        end
        if window_size_increment > STREAM_ID_MASK  # 2^31 - 1
            throw(
                FlowControlError(
                    "WINDOW_UPDATE increment exceeds maximum value",
                    stream_id,
                ),
            )
        end
        new(stream_id, window_size_increment)
    end

    # Multiple dispatch outer constructor for WindowUpdateFrame to accept Int/UInt/Integer and promote to correct types
    function WindowUpdateFrame(stream_id::Integer, window_size_increment::Integer)
        WindowUpdateFrame(UInt32(stream_id), UInt32(window_size_increment))
    end
end

"""
    frame_type(::Type{WindowUpdateFrame}) -> UInt8

Returns the frame type identifier for WINDOW_UPDATE frames (0x8).
"""
frame_type(::WindowUpdateFrame) = WINDOW_UPDATE_FRAME

stream_id(frame::WindowUpdateFrame) = frame.stream_id
frame_flags(::WindowUpdateFrame) = 0x00


"""
    serialize_payload(frame::WindowUpdateFrame) -> Vector{UInt8}

Serializes a WINDOW_UPDATE frame to its binary representation.
"""
function serialize_payload(frame::WindowUpdateFrame)
    return collect(reinterpret(UInt8, [hton(frame.window_size_increment & STREAM_ID_MASK)]))
end

"""
    deserialize_window_update_frame(stream_id::UInt32, flags::UInt8, payload::Vector{UInt8}) -> WindowUpdateFrame

Deserializes a WINDOW_UPDATE frame from its binary representation.
"""
function deserialize_window_update_frame(
    stream_id::UInt32,
    flags::UInt8,
    payload::Vector{UInt8},
)
    if length(payload) != 4
        throw(
            FrameError(
                FRAME_SIZE_ERROR,
                stream_id,
                "WINDOW_UPDATE frame payload must be exactly 4 bytes, got $(length(payload))",
            ),
        )
    end

    # RFC 7540 states that the receiver MUST ignore the flags for this frame.

    increment = ntoh(reinterpret(UInt32, payload)[1]) & STREAM_ID_MASK

    # The check for increment == 0 is now done in the constructor.
    return WindowUpdateFrame(stream_id, increment)
end

"""
    is_connection_level(frame::WindowUpdateFrame) -> Bool

Returns true if this WINDOW_UPDATE frame applies to the connection level (stream_id == 0).
"""
is_connection_level(frame::WindowUpdateFrame) = frame.stream_id == 0

"""
    is_stream_level(frame::WindowUpdateFrame) -> Bool

Returns true if this WINDOW_UPDATE frame applies to a specific stream (stream_id > 0).
"""
is_stream_level(frame::WindowUpdateFrame) = frame.stream_id > 0

"""
    create_window_update(stream_id::UInt32, increment::UInt32) -> WindowUpdateFrame

Convenience function to create a WINDOW_UPDATE frame.
"""
create_connection_window_update(increment::UInt32) = WindowUpdateFrame(UInt32(0), increment)

"""
    create_stream_window_update(stream_id::UInt32, increment::UInt32) -> WindowUpdateFrame

Convenience function to create a stream-level WINDOW_UPDATE frame.
"""
function create_stream_window_update(stream_id::UInt32, increment::UInt32)
    if stream_id == 0
        throw(ArgumentError("Stream ID for stream-level WINDOW_UPDATE cannot be 0"))
    end
    return WindowUpdateFrame(stream_id, increment)
end

# Pretty printing
function Base.show(io::IO, frame::WindowUpdateFrame)
    level = is_connection_level(frame) ? "connection" : "stream $(frame.stream_id)"
    print(io, "WindowUpdateFrame($(level), increment=$(frame.window_size_increment))")
end

function Base.show(io::IO, ::MIME"text/plain", frame::WindowUpdateFrame)
    println(io, "WindowUpdateFrame:")
    println(io, "  Stream ID: $(frame.stream_id)")
    println(io, "  Window Size Increment: $(frame.window_size_increment)")
    println(io, "  Flags: 0x$(string(frame.flags, base=16, pad=2))")
    level = is_connection_level(frame) ? "Connection-level" : "Stream-level"
    println(io, "  Level: $(level)")
end
end
