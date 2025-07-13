module Headers
# frames/headers.jl - HTTP/2 HEADERS frame implementation

using Http2Hpack
using ..FrameTypes
using ..Exc
using ..Http2Frames: is_valid_stream_id


import ..serialize_payload
import ..frame_type
import ..frame_flags
import ..stream_id


export HeadersFrame,
    PriorityInfo,
    deserialize_headers_frame,
    create_headers_frame,
    decode_headers_frame,
    split_headers_frame,
    priority_weight

const HEADERS_END_STREAM = 0x1  # END_STREAM flag
const HEADERS_END_HEADERS = 0x4 # END_HEADERS flag (no CONTINUATION follows)
const HEADERS_PADDED = 0x8      # PADDED flag
const HEADERS_PRIORITY = 0x20   # PRIORITY flag

"""
    PriorityInfo

Priority information for HEADERS frames with PRIORITY flag set.

# Fields  
- `exclusive::Bool`: Exclusive dependency flag
- `stream_dependency::UInt32`: Stream dependency (31-bit identifier)
- `weight::UInt8`: Priority weight (1-256, stored as weight-1)
"""
struct PriorityInfo
    exclusive::Bool
    stream_dependency::UInt32  # 31-bit stream ID
    weight::UInt8              # 1-256 mapped to 0-255

    function PriorityInfo(exclusive::Bool, stream_dependency::UInt32, weight::UInt8)
        if stream_dependency > 0x7FFFFFFF
            ;
            throw(ArgumentError("Stream dependency must be 31-bit value"));
        end
        new(exclusive, stream_dependency, weight)
    end
end

# Convenience constructor with weight 1-256
PriorityInfo(exclusive::Bool, stream_dependency::UInt32, weight::Int) =
    PriorityInfo(exclusive, stream_dependency, UInt8(weight-1))


# Get actual weight (1-256)
priority_weight(info::PriorityInfo) = Int(info.weight) + 1


"""
    HeadersFrame

Represents an HTTP/2 HEADERS frame.

HEADERS frames are used to open a stream and carry header block fragments.
They can carry the compressed header block for HTTP request or response headers.

# Fields
- `stream_id::UInt32`: Stream identifier (must be > 0)
- `header_block_fragment::Vector{UInt8}`: Compressed header block fragment (Http2Hpack encoded)
- `end_stream::Bool`: END_STREAM flag - no more frames for this stream
- `end_headers::Bool`: END_HEADERS flag - complete header block (no CONTINUATION frames follow)
- `padded::Bool`: PADDED flag - indicates frame is padded
- `priority::Bool`: PRIORITY flag - indicates priority information is present
- `pad_length::UInt8`: Length of padding (only used if padded=true)
- `priority_info::Union{PriorityInfo, Nothing}`: Priority information (only if priority=true)

# Flags
- `END_STREAM` (0x1): Indicates that this frame is the last for the stream
- `END_HEADERS` (0x4): Indicates that this frame ends the header block (no CONTINUATION frames)
- `PADDED` (0x8): Indicates that padding is present
- `PRIORITY` (0x20): Indicates that priority information is present
"""
struct HeadersFrame <: HTTP2Frame
    stream_id::UInt32
    header_block_fragment::Vector{UInt8}
    end_stream::Bool
    end_headers::Bool
    padded::Bool
    priority::Bool
    pad_length::UInt8
    priority_info::Union{PriorityInfo,Nothing}

    # Simplified constructor to avoid errors
    function HeadersFrame(
        stream_id::UInt32,
        header_block::Vector{UInt8};
        end_stream::Bool = false,
        end_headers::Bool = true,
        padded::Bool = false,
        priority::Bool = false,
        pad_length::UInt8 = 0x00,
        priority_info::Union{PriorityInfo,Nothing} = nothing,
    )

        if stream_id == 0
            throw(ArgumentError("HEADERS frames must have stream_id > 0"))
        end
        if priority && priority_info === nothing
            throw(ArgumentError("PRIORITY flag set but no priority information provided"))
        end
        if priority_info !== nothing && priority_info.stream_dependency == stream_id
            throw(ArgumentError("Stream cannot depend on itself"))
        end

        # Padding check must consider priority info
        priority_size = priority ? 5 : 0
        if padded && pad_length >= (length(header_block) + priority_size + 1)
            throw(ArgumentError("Pad length must be less than frame payload length"))
        end

        new(
            stream_id,
            header_block,
            end_stream,
            end_headers,
            padded,
            priority,
            pad_length,
            priority_info,
        )
    end
end



"""
    frame_type(::Type{HeadersFrame})

Returns the frame type identifier for HEADERS frames.
"""
frame_type(::HeadersFrame) = HEADERS_FRAME

"""
    stream_id(frame::HeadersFrame)

Returns the stream ID for the HEADERS frame.
"""
stream_id(frame::HeadersFrame) = frame.stream_id

"""
    frame_flags(frame::HeadersFrame) -> UInt8

Computes the flags byte for a HEADERS frame by combining its boolean properties.
This method is required by the frame serialization interface.
"""
function frame_flags(frame::HeadersFrame)
    flags = 0x00
    if frame.end_stream
        # Use constants from Constants.jl
        flags |= HEADERS_END_STREAM
    end
    if frame.end_headers
        flags |= HEADERS_END_HEADERS
    end
    if frame.padded
        flags |= HEADERS_PADDED
    end
    if frame.priority
        flags |= HEADERS_PRIORITY
    end
    return UInt8(flags)
end
"""
    serialize_payload(frame::HeadersFrame) -> Vector{UInt8}

Serializes a HEADERS frame to its binary representation according to RFC 7540.

# Frame Format:
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Length (24)                   |
+-----------+---+-------------------------------+---------------+
|   Type (8)    |   Flags (8)   |
+-----------+---+---------------+-+-------------+---------------+
|R|                 Stream Identifier (31)                      |
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
|Pad Length? (8)|
+-+-------------+-----------------------------------------------+
|E|                 Stream Dependency? (31)                     |
+-+-------------+-----------------------------------------------+
|  Weight? (8)  |
+-+-------------+-----------------------------------------------+
|                   Header Block Fragment (*)                 ...
+---------------------------------------------------------------+
|                           Padding (*)                      ...
+---------------------------------------------------------------+
```
"""
function serialize_payload(frame::HeadersFrame)
    buffer = IOBuffer()

    # The payload has a specific order:
    # 1. Pad Length (if present)
    if frame.padded
        write(buffer, frame.pad_length)
    end

    # 2. Priority Info (if present)
    if frame.priority && !isnothing(frame.priority_info)
        info = frame.priority_info
        dep_with_exclusive = info.stream_dependency
        if info.exclusive
            dep_with_exclusive |= 0x80000000 # Set exclusive bit
        end
        write(buffer, hton(dep_with_exclusive))
        write(buffer, info.weight)
    end

    # 3. Header Block Fragment
    write(buffer, frame.header_block_fragment)

    # 4. Padding (if present)
    if frame.padded && frame.pad_length > 0
        write(buffer, zeros(UInt8, frame.pad_length))
    end

    return take!(buffer)
end

"""
    deserialize_headers_frame(header::FrameHeader, payload::Vector{UInt8}) -> HeadersFrame

Deserializes a HEADERS frame from its binary representation.

# Arguments
- `header::FrameHeader`: The parsed frame header
- `payload::Vector{UInt8}`: The frame payload bytes

# Returns
- `HeadersFrame`: The deserialized HEADERS frame

# Throws
- `HTTP2Error`: If the frame is malformed or violates protocol constraints
"""
function deserialize_headers_frame(header::FrameHeader, payload::Vector{UInt8})
    # Validate frame type
    if header.frame_type != HEADERS_FRAME || header.stream_id == 0
        throw(ProtocolError("Malformed HEADERS frame header"))
    end

    # Parse flags
    end_stream = (header.flags & HEADERS_END_STREAM) != 0
    end_headers = (header.flags & HEADERS_END_HEADERS) != 0
    padded = (header.flags & HEADERS_PADDED) != 0
    priority = (header.flags & HEADERS_PRIORITY) != 0

    reader = IOBuffer(payload)
    pad_length = UInt8(0)
    priority_info = nothing

    # Parse pad length if padded
    if padded
        !eof(reader) || throw(FrameSizeError("Missing Pad Length"))
        pad_length = read(reader, UInt8)
    end

    # Parse priority information if present
    if priority
        bytesavailable(reader) >= 5 || throw(FrameSizeError("Missing Priority Info"))
        dep_raw = ntoh(read(reader, UInt32))
        exclusive = (dep_raw & 0x80000000) != 0
        stream_dependency = dep_raw & 0x7FFFFFFF
        weight = read(reader, UInt8)
        priority_info = PriorityInfo(exclusive, stream_dependency, weight)
    end

    # Validate padding length
    total_payload_size = length(payload)
    header_fragment_size = total_payload_size - position(reader) - pad_length

    if header_fragment_size < 0
        throw(ProtocolError("Invalid pad length"))
    end

    header_block_fragment = read(reader, header_fragment_size)

    # The rest is padding, which is ignored.

    return HeadersFrame(
        UInt32(header.stream_id),
        header_block_fragment;
        end_stream = end_stream,
        end_headers = end_headers,
        padded = padded,
        priority = priority,
        pad_length = pad_length,
        priority_info = priority_info,
    )
end

"""
    create_headers_frame(stream_id::UInt32, headers::Vector{Pair{String, String}}; 
                        end_stream::Bool=false, priority_info::Union{PriorityInfo, Nothing}=nothing,
                        encoder::HPACKEncoder) -> HeadersFrame

Convenience function to create a HEADERS frame from header name-value pairs.
This function handles HPACK encoding of the headers.

# Arguments
- `stream_id::UInt32`: Stream identifier
- `headers::Vector{Pair{String, String}}`: Header name-value pairs to encode
- `end_stream::Bool`: Whether to set END_STREAM flag
- `priority_info`: Optional priority information
- `encoder::HPACKEncoder`: HPACK encoder context

# Returns
- `HeadersFrame`: The encoded HEADERS frame
"""
function create_headers_frame(
    stream_id::UInt32,
    headers::Vector{Pair{String,String}};
    end_stream::Bool = false,
    priority_info::Union{PriorityInfo,Nothing} = nothing,
    encoder::HPACKEncoder,
)
    # Encode headers using Http2Hpack
    header_block = encode_headers(encoder, headers)

    return HeadersFrame(
        stream_id,
        header_block;
        end_stream = end_stream,
        end_headers = true,  # Single frame for now
        priority = !isnothing(priority_info),
        priority_info = priority_info,
    )
end

# Multiple dispatch outer constructor for create_headers_frame to accept Int/UInt/Integer stream_id
function create_headers_frame(
    stream_id::Integer,
    headers::Vector{Pair{String,String}},
    encoder::HPACKEncoder;
    kwargs...,
)
    create_headers_frame(UInt32(stream_id), headers; encoder = encoder, kwargs...)
end

"""
    decode_headers_frame(frame::HeadersFrame, decoder::HPACKDecoder) -> Vector{Pair{String, String}}

Convenience function to decode HPACK-encoded headers from a HEADERS frame.

# Arguments
- `frame::HeadersFrame`: The HEADERS frame to decode
- `decoder::HPACKDecoder`: HPACK decoder context

# Returns
- `Vector{Pair{String, String}}`: Decoded header name-value pairs

# Throws
- `HTTP2Error`: If HPACK decoding fails
"""
function decode_headers_frame(frame::HeadersFrame, decoder::HPACKDecoder)
    try
        return decode_headers(decoder, frame.header_block_fragment)
    catch e
        throw(HTTP2Error(COMPRESSION_ERROR, "Failed to decode HPACK headers: $(e)"))
    end
end

"""
    split_headers_frame(frame::HeadersFrame, max_frame_size::Int) -> Vector{Union{HeadersFrame, ContinuationFrame}}

Splits a large HEADERS frame into multiple frames if it exceeds the maximum frame size.
Returns a HEADERS frame followed by zero or more CONTINUATION frames.

# Arguments
- `frame::HeadersFrame`: The original HEADERS frame
- `max_frame_size::Int`: Maximum frame size

# Returns
- `Vector{Union{HeadersFrame, ContinuationFrame}}`: Split frames
"""
function split_headers_frame(frame::HeadersFrame, max_frame_size::Int)
    # Calculate overhead for the first frame
    overhead = 0
    if frame.padded
        overhead += 1  # pad length
    end
    if frame.priority
        overhead += 5  # priority info
    end
    if frame.padded
        overhead += frame.pad_length  # padding
    end

    # If frame fits within limit, return as-is
    total_size = overhead + length(frame.header_block_fragment)
    if total_size <= max_frame_size
        return [frame]
    end

    frames = []
    fragment = frame.header_block_fragment
    offset = 1
    first_frame = true

    while offset <= length(fragment)
        if first_frame
            # First frame: HEADERS frame with reduced header block
            available_space = max_frame_size - overhead
            chunk_size = min(available_space, length(fragment) - offset + 1)

            chunk = fragment[offset:(offset+chunk_size-1)]
            headers_frame = HeadersFrame(
                frame.stream_id,
                chunk;
                end_stream = frame.end_stream,
                end_headers = false,  # More frames follow
                padded = frame.padded,
                priority = frame.priority,
                pad_length = frame.pad_length,
                priority_info = frame.priority_info,
            )
            push!(frames, headers_frame)
            first_frame = false
        else
            # Subsequent frames: CONTINUATION frames
            chunk_size = min(max_frame_size, length(fragment) - offset + 1)
            chunk = fragment[offset:(offset+chunk_size-1)]

            is_last = (offset + chunk_size - 1) >= length(fragment)
            continuation_frame =
                ContinuationFrame(frame.stream_id, chunk, end_headers = is_last)
            push!(frames, continuation_frame)
        end

        offset += chunk_size
    end

    # Set END_HEADERS flag on the last frame
    if !isempty(frames)
        last_frame = frames[end]
        if isa(last_frame, HeadersFrame)
            frames[end] = HeadersFrame(
                last_frame.stream_id,
                last_frame.header_block_fragment;
                end_stream = last_frame.end_stream,
                end_headers = true,
                padded = last_frame.padded,
                priority = last_frame.priority,
                pad_length = last_frame.pad_length,
                priority_info = last_frame.priority_info,
            )
        else  # ContinuationFrame
            frames[end] = ContinuationFrame(
                last_frame.stream_id,
                last_frame.header_block_fragment,
                end_headers = true,
            )
        end
    end

    return frames
end

# Pretty printing
function Base.show(io::IO, frame::HeadersFrame)
    print(io, "HeadersFrame(")
    print(io, "stream_id=", frame.stream_id)
    print(io, ", fragment_length=", length(frame.header_block_fragment))
    if frame.end_stream
        print(io, ", END_STREAM")
    end
    if frame.end_headers
        print(io, ", END_HEADERS")
    end
    if frame.priority
        print(io, ", PRIORITY")
    end
    if frame.padded
        print(io, ", PADDED(", frame.pad_length, ")")
    end
    print(io, ")")
end

function Base.show(io::IO, ::MIME"text/plain", frame::HeadersFrame)
    println(io, "HTTP/2 HEADERS Frame:")
    println(io, "  Stream ID: ", frame.stream_id)
    println(io, "  Header Block Length: ", length(frame.header_block_fragment), " bytes")

    flags = String[]
    frame.end_stream && push!(flags, "END_STREAM")
    frame.end_headers && push!(flags, "END_HEADERS")
    frame.padded && push!(flags, "PADDED")
    frame.priority && push!(flags, "PRIORITY")
    println(io, "  Flags: ", isempty(flags) ? "none" : join(flags, ", "))

    if frame.padded
        println(io, "  Pad Length: ", frame.pad_length)
    end

    if frame.priority && !isnothing(frame.priority_info)
        println(io, "  Priority Info:")
        println(io, "    Exclusive: ", frame.priority_info.exclusive)
        println(io, "    Stream Dependency: ", frame.priority_info.stream_dependency)
        println(io, "    Weight: ", priority_weight(frame.priority_info))
    end
end

function Base.show(io::IO, info::PriorityInfo)
    print(io, "PriorityInfo(")
    print(io, "exclusive=", info.exclusive)
    print(io, ", dependency=", info.stream_dependency)
    print(io, ", weight=", priority_weight(info))
    print(io, ")")
end
end
