module RstStream
# HTTP/2 RST_STREAM Frame Implementation
# RFC 7540 Section 6.4
using ..FrameTypes
using ..Exc

import ..serialize_payload
import ..frame_type
import ..frame_flags
import ..stream_id

export RstStreamFrame,
    decode_rst_stream_frame, validate_rst_stream_frame, create_rst_stream_response


"""
    RstStreamFrame

Represents an HTTP/2 RST_STREAM frame.

The RST_STREAM frame (type=0x3) allows for immediate termination of a stream.
Upon receipt of a RST_STREAM frame, the receiver must not send additional frames
for that stream, with the exception of PRIORITY frames.

# Fields
- `stream_id::UInt32`: Stream identifier (must not be 0x0)
- `error_code::UInt32`: Error code indicating why the stream is being reset

# Frame Format
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Error Code (32)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
"""
struct RstStreamFrame <: HTTP2Frame
    stream_id::UInt32
    error_code::UInt32

    function RstStreamFrame(stream_id::UInt32, error_code::UInt32)
        # Validate stream_id
        if stream_id == 0x0
            throw(
                ProtocolError(
                    "RST_STREAM frames must have a non-zero stream identifier",
                    stream_id,
                ),
            )
        end

        new(stream_id, error_code)
    end
end

RstStreamFrame(stream_id::UInt32, error_code::Integer) = RstStreamFrame(stream_id, UInt32(error_code))


"""
    frame_type(::Type{RstStreamFrame}) -> UInt8

Returns the frame type identifier for RST_STREAM frames (0x3).
"""
frame_type(::RstStreamFrame) = RST_STREAM_FRAME

stream_id(frame::RstStreamFrame) = frame.stream_id

"""
    frame_flags(frame::RstStreamFrame) -> UInt8

Returns the flags for RST_STREAM frames (always 0x0 - no flags defined).
"""
frame_flags(frame::RstStreamFrame) = 0x00



"""
    serialize_payload(frame::RstStreamFrame) -> Vector{UInt8}

Encodes a RST_STREAM frame into its binary representation.

# Returns
A 4-byte vector containing the encoded error code.
"""
function serialize_payload(frame::RstStreamFrame)
    return collect(reinterpret(UInt8, [hton(frame.error_code)]))
end

"""
    decode_rst_stream_frame(stream_id::UInt32, flags::UInt8, payload::Vector{UInt8}) -> RstStreamFrame

Decodes a RST_STREAM frame from its binary representation.

# Arguments
- `stream_id`: The stream identifier from the frame header
- `flags`: The flags from the frame header (should be 0x0)
- `payload`: The frame payload (must be exactly 4 bytes)

# Returns
A `RstStreamFrame` instance.

# Throws
- `ProtocolError`: If the payload length is incorrect or flags are invalid
- `ArgumentError`: If stream identifier is invalid
"""
function decode_rst_stream_frame(stream_id::UInt32, flags::UInt8, payload::Vector{UInt8})
    # Validate frame format
    if length(payload) != 4
        throw(
            ProtocolError(
                "RST_STREAM frame payload must be exactly 4 bytes, got $(length(payload))",
            ),
        )
    end

    if flags != 0x00
        throw(
            ProtocolError(
                "RST_STREAM frame must not have any flags set, got 0x$(string(flags, base=16, pad=2))",
            ),
        )
    end

    # Decode error code
    error_code = ntoh(reinterpret(UInt32, payload)[1])

    return RstStreamFrame(stream_id, error_code)
end

"""
    validate_rst_stream_frame(frame::RstStreamFrame, connection_state=nothing) -> Nothing

Validates a RST_STREAM frame according to HTTP/2 protocol rules.

# Validation Rules
1. Stream ID must not be 0x0 (connection-level errors use GOAWAY)
2. Error code should be a known value (warning for unknown codes)

# Throws
- `ProtocolError`: If validation fails
"""
function validate_rst_stream_frame(frame::RstStreamFrame, connection_state = nothing)
    if !haskey(Dict(instances(HTTP2ErrorCode)), frame.error_code)
        @warn "RST_STREAM frame uses unknown error code" stream_id=frame.stream_id error_code=frame.error_code
    end

    return true
end


"""
    should_close_connection(frame::RstStreamFrame) -> Bool

Determines if a RST_STREAM frame indicates that the connection should be closed.
Some errors, while sent as RST_STREAM, may indicate broader connection issues.
"""
function should_close_connection(frame::RstStreamFrame)
    # Some error codes may indicate a problem across the connection.
    if frame.error_code == COMPRESSION_ERROR || frame.error_code == CONNECT_ERROR
        return true
    end
    return false
end

"""
    clear_stream_buffers!(connection_state, stream_id::UInt32)

Helper function to clear all buffers associated with a stream.
"""
function clear_stream_buffers!(connection_state, stream_id::UInt32)
    if hasfield(typeof(connection_state), :streams) &&
       haskey(connection_state.streams, stream_id)
        stream = connection_state.streams[stream_id]

        # Clear various types of buffers that might exist
        for field_name in [:send_buffer, :recv_buffer, :header_buffer, :data_buffer]
            if hasfield(typeof(stream), field_name)
                buffer = getfield(stream, field_name)
                if isa(buffer, Vector) || isa(buffer, AbstractVector)
                    empty!(buffer)
                elseif isa(buffer, Dict) || isa(buffer, AbstractDict)
                    empty!(buffer)
                end
            end
        end
    end
end

"""
    create_rst_stream_response(stream_id::UInt32, error::Exception) -> RstStreamFrame

Creates an appropriate RST_STREAM frame for a given exception/error condition.
"""

function create_rst_stream_response(stream_id::UInt32, error::Exception)
    error_code = if isa(error, ProtocolError)
        GOAWAY_PROTOCOL_ERROR
    elseif isa(error, FlowControlError)
        GOAWAY_FLOW_CONTROL_ERROR
    elseif isa(error, CompressionError)
        GOAWAY_COMPRESSION_ERROR
    elseif isa(error, FrameSizeError)
        GOAWAY_FRAME_SIZE_ERROR
    else
        GOAWAY_INTERNAL_ERROR
    end
    return RstStreamFrame(stream_id, UInt32(error_code))
end

"""
    rst_stream_frame_summary(frame::RstStreamFrame) -> String

Returns a human-readable summary of the RST_STREAM frame.
"""
function rst_stream_frame_summary(frame::RstStreamFrame)
    return "RST_STREAM[stream=$(frame.stream_id), error=($(frame.error_code))]"
end

# Display methods
function Base.show(io::IO, frame::RstStreamFrame)
    print(io, rst_stream_frame_summary(frame))
end

function Base.show(io::IO, ::MIME"text/plain", frame::RstStreamFrame)
    println(io, "HTTP/2 RST_STREAM Frame:")
    println(io, "  Stream ID: $(frame.stream_id)")
    println(io, "  Error Code: $(frame.error_code)")
end

# Equality and hashing
function Base.:(==)(a::RstStreamFrame, b::RstStreamFrame)
    return a.stream_id == b.stream_id && a.error_code == b.error_code
end

function Base.hash(frame::RstStreamFrame, h::UInt)
    h = hash(frame.stream_id, h)
    h = hash(frame.error_code, h)
    return h
end

end
