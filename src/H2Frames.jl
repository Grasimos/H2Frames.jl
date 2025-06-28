module H2Frames

# HTTP/2 Frame Interface and Binary Protocol Implementation
# Based on RFC 7540: https://tools.ietf.org/html/rfc7540

using HPACK # https://github.com/Grasimos/HPACK.jl
include("Exc.jl");
using .Exc
include("FrameTypes.jl");
using .FrameTypes

"""
    frame_type(frame::HTTP2Frame) -> FrameType

Get the frame type for any HTTP/2 frame.
Must be implemented by all concrete frame types.
"""
function frame_type end

"""
    frame_flags(frame::HTTP2Frame) -> UInt8

Get the flags byte for any HTTP/2 frame.
Must be implemented by all concrete frame types.
"""
function frame_flags end

"""
    stream_id(frame::HTTP2Frame) -> Int32

Get the stream ID for any HTTP/2 frame.
Must be implemented by all concrete frame types.
"""
function stream_id end


"""
    serialize_payload(frame::HTTP2Frame) -> Vector{UInt8}

Serialize the frame payload to bytes.
Must be implemented by all concrete frame types.
"""
function serialize_payload end

"""
    serialize_frame(frame::HTTP2Frame) -> Vector{UInt8}

Serialize a complete frame (header + payload) to bytes efficiently using an IOBuffer.
This function acts as the central entry point for serializing any frame type.
"""
function serialize_frame(frame::HTTP2Frame)
    payload = serialize_payload(frame)

    header = FrameHeader(
        length(payload),
        frame_type(frame),
        frame_flags(frame),
        stream_id(frame),
    )

    buffer = IOBuffer()
    write(buffer, serialize_frame_header(header))
    write(buffer, payload)

    return take!(buffer)
end


"""
    serialize_frame_header(header::FrameHeader) -> Vector{UInt8}

Serialize a frame header to 9 bytes.
"""
function serialize_frame_header(header::FrameHeader)
    buffer = Vector{UInt8}(undef, FRAME_HEADER_SIZE)
    buffer[1:3] = write_uint24_be(header.length) # 
    buffer[4] = UInt8(header.frame_type)
    buffer[5] = header.flags
    stream_id_with_reserved = UInt32(header.stream_id) & STREAM_ID_MASK # 
    buffer[6:9] = reinterpret(UInt8, [hton(stream_id_with_reserved)])
    return buffer
end

"""
    write_uint24_be(x::Integer) -> Vector{UInt8}

Write a 24-bit unsigned integer in big-endian format.
"""
function write_uint24_be(x::Integer)
    return UInt8[(x>>16)&0xFF, (x>>8)&0xFF, x&0xFF]
end



"""
    deserialize_frame_header(data::AbstractVector{UInt8}) -> FrameHeader

Deserialize 9 bytes into a frame header.
"""
function deserialize_frame_header(data::AbstractVector{UInt8})
    if length(data) < FRAME_HEADER_SIZE
        throw(
            ArgumentError(
                "Need at least $FRAME_HEADER_SIZE bytes for frame header, got $(length(data))",
            ),
        )
    end
    length_val = (UInt32(data[1]) << 16) | (UInt32(data[2]) << 8) | UInt32(data[3]) # 
    type_val = FrameType(data[4])
    flags_val = data[5]
    stream_id_val = ntoh(reinterpret(UInt32, data[6:9])[1]) & STREAM_ID_MASK # 
    return FrameHeader(length_val, type_val, flags_val, stream_id_val)
end

"""
    frames_reset!(reader::FrameReader)

Reset the frame reader state.
"""
function frames_reset!(reader::FrameReader)
    empty!(reader.buffer)
    reader.position = 1
    reader.expected_frame_size = nothing
    reader.header = nothing
    return reader
end

"""
    feed_data!(reader::FrameReader, data::AbstractVector{UInt8})

Feed new data into the frame reader.
"""
function feed_data!(reader::FrameReader, data::AbstractVector{UInt8})
    append!(reader.buffer, data)
    return reader
end

"""
    bytes_available(reader::FrameReader) -> Int

Get number of bytes available for reading.
"""
function bytes_available(reader::FrameReader)
    return length(reader.buffer) - reader.position + 1
end

"""
    try_read_frame_header(reader::FrameReader) -> Union{FrameHeader, Nothing}

Try to read a frame header. Returns nothing if insufficient data.
"""
function try_read_frame_header(reader::FrameReader)
    if reader.header !== nothing
        return reader.header
    end

    if bytes_available(reader) < FRAME_HEADER_SIZE
        return nothing
    end

    # Read header
    header_data = reader.buffer[reader.position:(reader.position+FRAME_HEADER_SIZE-1)]
    reader.header = deserialize_frame_header(header_data)
    reader.position += FRAME_HEADER_SIZE
    reader.expected_frame_size = FRAME_HEADER_SIZE + Int(reader.header.length)

    return reader.header
end

"""
    try_read_complete_frame(reader::FrameReader) -> Union{Tuple{FrameHeader, Vector{UInt8}}, Nothing}

Try to read a complete frame. Returns (header, payload) tuple or nothing if insufficient data.
"""
function try_read_complete_frame(reader::FrameReader)
    if reader.header === nothing
        if bytes_available(reader) < FRAME_HEADER_SIZE
            return nothing
        end
        header_data =
            view(reader.buffer, reader.position:(reader.position+FRAME_HEADER_SIZE-1))
        reader.header = deserialize_frame_header(header_data)
    end

    header = reader.header
    total_frame_size = FRAME_HEADER_SIZE + Int(header.length)
    if bytes_available(reader) < total_frame_size
        return nothing
    end

    payload_start = reader.position + FRAME_HEADER_SIZE
    payload_end = payload_start + Int(header.length) - 1
    payload = view(reader.buffer, payload_start:payload_end)

    # Prepare for the next frame
    reader.position += total_frame_size
    reader.header = nothing

    # Return a copy of the payload to ensure it's safe
    return (header, copy(payload))
end

"""
    compact_buffer!(reader::FrameReader)

Remove processed data from the buffer to prevent unbounded growth.
"""
function compact_buffer!(reader::FrameReader)
    if reader.position > 1
        unprocessed_start = reader.position
        unprocessed_data = reader.buffer[unprocessed_start:end]

        empty!(reader.buffer)
        append!(reader.buffer, unprocessed_data)

        reader.position = 1
    end

    return reader
end


# =============================================================================
# Frame Factory
# =============================================================================

"""
    create_frame(header::FrameHeader, payload::Vector{UInt8}) -> HTTP2Frame

Factory function to create specific frame types from header and payload.
This will be extended as we implement specific frame types.
"""
function create_frame(header::FrameHeader, payload::Vector{UInt8})
    ft = header.frame_type
    sid = header.stream_id
    flags = header.flags

    if ft == DATA_FRAME
        return deserialize_data_frame(header, payload) # 
    elseif ft == HEADERS_FRAME
        return deserialize_headers_frame(header, payload) # 
    elseif ft == PRIORITY_FRAME
        return decode_priority_frame(UInt32(sid), flags, payload) # 
    elseif ft == RST_STREAM_FRAME
        return decode_rst_stream_frame(UInt32(sid), flags, payload) # 
    elseif ft == SETTINGS_FRAME
        return deserialize_settings_frame(header, payload) # 
    elseif ft == PUSH_PROMISE_FRAME
        return deserialize_push_promise_frame(header, payload) # 
    elseif ft == PING_FRAME
        return deserialize_ping_frame(header, payload) # 
    elseif ft == GOAWAY_FRAME
        return deserialize_goaway_frame(header, payload) # 
    elseif ft == WINDOW_UPDATE_FRAME
        return deserialize_window_update_frame(UInt32(sid), flags, payload) # 
    elseif ft == CONTINUATION_FRAME
        return decode_continuation_frame(header, payload) # 
    else
        # Fallback for unknown frame types.
        @warn "Received unknown frame type: $(ft). Wrapping in GenericFrame."
        return GenericFrame(header, payload) # 
    end
end
"""
    GenericFrame

Generic frame wrapper for unknown or unimplemented frame types.
"""
struct GenericFrame <: HTTP2Frame
    header::FrameHeader
    payload::Vector{UInt8}
end

# Implement required interface for GenericFrame
frame_type(frame::GenericFrame) = frame.header.frame_type
frame_flags(frame::GenericFrame) = frame.header.flags
stream_id(frame::GenericFrame) = frame.header.stream_id
serialize_payload(frame::GenericFrame) = copy(frame.payload)

# =============================================================================
# Utility Functions
# =============================================================================
# Map frame type numbers to names per RFC 7540
function frame_type_name(frame_type::Integer)
    names = Dict(
        0x0 => :DATA,
        0x1 => :HEADERS,
        0x2 => :PRIORITY,
        0x3 => :RST_STREAM,
        0x4 => :SETTINGS,
        0x5 => :PUSH_PROMISE,
        0x6 => :PING,
        0x7 => :GOAWAY,
        0x8 => :WINDOW_UPDATE,
        0x9 => :CONTINUATION
    )
    return get(names, frame_type, :UNKNOWN)
end



"""
    frame_summary(frame::HTTP2Frame) -> String

Get a summary string for any frame type.
"""
function frame_summary(frame::HTTP2Frame)
    len = length(serialize_payload(frame))
    typ_name = frame_type_name(frame_type(frame))
    flgs = frame_flags(frame)
    sid = stream_id(frame)
    # ---------------------------------

    return "$(typ_name)(len=$(len), " *
           "flags=0x$(string(flgs, base=16, pad=2)), " *
           "stream=$(sid))"
end

# Utility: Validate stream ID for HTTP/2 frames (must be > 0 and <= MAX_STREAM_ID)
function is_valid_stream_id(stream_id)
    return stream_id > 0 && stream_id <= MAX_STREAM_ID
end


include("FrameData.jl");
using .FrameData
include("Headers.jl");
using .Headers
include("Priority.jl");
using .Priority
include("FrameSettings.jl");
using .FrameSettings
include("WindowUpdate.jl");
using .WindowUpdate
include("RstStream.jl");
using .RstStream
include("Ping.jl");
using .Ping
include("GoAway.jl");
using .GoAway
include("PushPromise.jl");
using .PushPromise
include("Continuation.jl");
using .Continuation

# Re-export frame type constants and Ping helpers for test and API convenience
export DATA_FRAME,
    PING_FRAME,
    GOAWAY_FRAME,
    WINDOW_UPDATE_FRAME,
    PRIORITY_FRAME,
    SETTINGS_FRAME,
    PUSH_PROMISE_FRAME,
    CONTINUATION_FRAME,
    HEADERS_FRAME,
    RST_STREAM_FRAME
# Re-export all public symbols from all submodules for a flat API
export HTTP2Frame
export DataFrame, deserialize_data_frame, create_data_frame, combine_data_frames
export HeadersFrame, create_headers_frame, deserialize_headers_frame
export PriorityFrame,
    decode_priority_frame, actual_weight, validate_priority_frame, apply_priority_frame!
export SettingsFrame,
    is_ack,
    deserialize_settings_frame,
    create_settings_ack,
    create_initial_settings,
    validate_settings_frame,
    get_setting,
    has_setting,
    settings_to_string,
    SETTINGS_HEADER_TABLE_SIZE,
    SETTINGS_ENABLE_PUSH,
    SETTINGS_MAX_CONCURRENT_STREAMS,
    SETTINGS_INITIAL_WINDOW_SIZE,
    SETTINGS_MAX_FRAME_SIZE,
    SETTINGS_MAX_HEADER_LIST_SIZE,
    SETTINGS_ENABLE_CONNECT_PROTOCOL
export WindowUpdateFrame,
    deserialize_window_update_frame,
    is_connection_level,
    is_stream_level,
    create_connection_window_update,
    create_stream_window_update
export PingFrame,
    PingAckFrame,
    deserialize_ping_frame,
    is_ping_ack,
    get_ping_data,
    get_ping_data_as_uint64,
    process_ping_frame,
    generate_ping_data,
    generate_ping_data_with_timestamp
export GoAwayFrame,
    deserialize_goaway_frame,
    graceful_shutdown_goaway,
    protocol_error_goaway,
    internal_error_goaway,
    enhance_your_calm_goaway,
    get_last_stream_id,
    get_error_code
export PushPromiseFrame, deserialize_push_promise_frame
export ContinuationFrame, deserialize_continuation_frame
export HTTP2Exception, ConnectionLevelError, StreamLevelError,
       ProtocolError, InternalError, CompressionError, FlowControlError, FrameSizeError,
       SettingsTimeoutError, StreamClosedError, RefusedStreamError, CancelError,
       ConnectError, EnhanceYourCalmError, InadequateSecurityError,
       exception_to_error_code, error_code_name, error_code_description,
       ErrorCode,
       NO_ERROR, PROTOCOL_ERROR, INTERNAL_ERROR, FLOW_CONTROL_ERROR, SETTINGS_TIMEOUT,
       STREAM_CLOSED_ERROR, FRAME_SIZE_ERROR, REFUSED_STREAM, CANCEL, COMPRESSION_ERROR,
       CONNECT_ERROR, ENHANCE_YOUR_CALM, INADEQUATE_SECURITY, HTTP_1_1_REQUIRED
export frame_type_name

end
