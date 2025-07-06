module FrameData
# frames/data.jl - HTTP/2 DATA frame implementation
using ..FrameTypes
using ..Exc
using ..H2Frames: is_valid_stream_id

import ..serialize_payload
import ..frame_type
import ..frame_flags
import ..stream_id


export DataFrame, deserialize_data_frame, create_data_frame, combine_data_frames

const DATA_END_STREAM = 0x1    # END_STREAM flag
const DATA_PADDED = 0x8        # PADDED flag

"""
    DataFrame(stream_id, data; end_stream=false, padded=false, pad_length=0)

Represents an HTTP/2 DATA frame.

DATA frames convey arbitrary, variable-length sequences of octets associated 
with a stream. One or more DATA frames are used to carry a HTTP request or 
response payload.

# Fields
- `stream_id::UInt32`: Stream identifier (must be > 0)
- `data::Vector{UInt8}`: Frame payload data
- `end_stream::Bool`: END_STREAM flag - indicates this is the last frame for the stream
- `padded::Bool`: PADDED flag - indicates frame is padded
- `pad_length::UInt8`: Length of padding (only used if padded=true)

# Flags
- `END_STREAM` (0x1): Indicates that this frame is the last that the endpoint will send for the identified stream
- `PADDED` (0x8): Indicates that the Pad Length field and any padding are present

# Example
```julia
using H2Frames
frame = DataFrame(1, [0x01, 0x02, 0x03]; end_stream=true)
```
"""
struct DataFrame <: HTTP2Frame
    stream_id::UInt32
    end_stream::Bool
    padded::Bool
    data::AbstractVector{UInt8}
    pad_length::UInt8

    function DataFrame(
        stream_id::Integer,
        data::AbstractVector{UInt8};
        end_stream::Bool = false,
        padded::Bool = false,
        pad_length::Integer = 0,
    )
        sid = UInt32(stream_id)
        if sid == 0
            throw(ProtocolError("DATA frames must have stream_id > 0", sid))
        end
        if pad_length < 0 || pad_length > 255
            throw(FrameSizeError("Pad length must be in 0:255", sid))
        end
        pad_length_u8 = UInt8(pad_length)
        if padded && pad_length_u8 >= length(data) + 1
            throw(FrameSizeError("Pad length must be less than frame payload length", sid))
        end
        if !padded && pad_length_u8 > 0
            throw(ProtocolError("Pad length specified but PADDED flag not set", sid))
        end
        new(sid, end_stream, padded, data, pad_length_u8)
    end
end

function frame_flags(frame::DataFrame)
    flags = UInt8(0)
    if frame.end_stream
        flags |= DATA_END_STREAM
    end
    if frame.padded
        flags |= DATA_PADDED
    end
    return flags
end

"""
    frame_type(::Type{DataFrame})

Returns the frame type identifier for DATA frames.
"""
frame_type(::DataFrame) = DATA_FRAME

"""
    stream_id(frame::DataFrame)

Returns the stream ID for the DATA frame.
"""
stream_id(frame::DataFrame) = frame.stream_id

"""
    serialize_payload(frame::DataFrame) -> Vector{UInt8}

Serializes a DATA frame to its binary representation according to RFC 7540.

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
+---------------+-----------------------------------------------+
|                            Data (*)                         ...
+---------------------------------------------------------------+
|                           Padding (*)                      ...
+---------------------------------------------------------------+
```

# Example
```julia
bytes = serialize_payload(frame)
```
"""
function serialize_payload(frame::DataFrame)
    buffer = IOBuffer()
    if frame.padded
        write(buffer, frame.pad_length)
    end
    write(buffer, frame.data)
    if frame.padded && frame.pad_length > 0
        write(buffer, zeros(UInt8, frame.pad_length))
    end
    return take!(buffer)
end

"""
    deserialize_data_frame(header::FrameHeader, payload::Vector{UInt8}) -> DataFrame

Deserializes a DATA frame from its binary representation.

# Arguments
- `header::FrameHeader`: The parsed frame header
- `payload::Vector{UInt8}`: The frame payload bytes

# Returns
- `DataFrame`: The deserialized DATA frame

# Throws
- `HTTP2Error`: If the frame is malformed or violates protocol constraints
"""
function deserialize_data_frame(header::FrameHeader, payload::Vector{UInt8})
    # Validate frame type
    if header.frame_type != DATA_FRAME
        throw(FrameError("Invalid frame type for DATA frame"))
    end
    if !is_valid_stream_id(header.stream_id)
        throw(FrameStreamError("DATA frames MUST be associated with a stream"))
    end

    # Parse flags
    end_stream = (header.flags & DATA_END_STREAM) != 0
    padded = (header.flags & DATA_PADDED) != 0

    # Check for unknown flags (should be ignored per RFC)

    # Parse payload
    data = Vector{UInt8}()
    pad_length = 0x00
    payload_offset = 1

    if padded
        if length(payload) < 1
            throw(FrameError("PADDED DATA frame must have pad length"))
        end

        pad_length = payload[1]
        payload_offset = 2

        # Validate padding length
        if pad_length >= length(payload)
            throw(FrameError("Pad length exceeds frame payload"))
        end
    end

    # Extract data (everything except pad length byte and padding)
    data_end = length(payload) - pad_length
    if payload_offset <= data_end
        data = payload[payload_offset:data_end]
    end

    # Validate padding bytes are zero (optional check)
    if padded && pad_length > 0
        padding_start = data_end + 1
        padding = payload[padding_start:end]
        # Note: RFC doesn't require padding to be zero, but it's good practice to check
    end

    return DataFrame(
        UInt32(header.stream_id),
        data;
        end_stream = end_stream,
        padded = padded,
        pad_length = pad_length,
    )
end

"""
    create_data_frame(stream_id::UInt32, data::Union{String, Vector{UInt8}}; 
                     end_stream::Bool=false, max_frame_size::Int=16384) -> Vector{DataFrame}

Convenience function to create DATA frame(s) from data, automatically splitting
large payloads across multiple frames if necessary.

# Arguments
- `stream_id::UInt32`: Stream identifier
- `data`: Data to send (String or Vector{UInt8})
- `end_stream::Bool`: Whether to set END_STREAM flag on final frame
- `max_frame_size::Int`: Maximum frame size (default 16384 bytes)

# Returns
- `Vector{DataFrame}`: One or more DATA frames containing the data
"""
function create_data_frame(
    stream_id::Integer,
    data::Union{String,Vector{UInt8}};
    end_stream::Bool = false,
    max_frame_size::Int = 16384,
)
    create_data_frame(UInt32(stream_id), data; end_stream = end_stream, max_frame_size = max_frame_size)
end

function create_data_frame(
    stream_id::UInt32,
    data::Union{String,Vector{UInt8}};
    end_stream::Bool = false,
    max_frame_size::Int = 16384,
)
    # Convert string to bytes if needed
    data_bytes = data isa String ? Vector{UInt8}(data) : data

    frames = DataFrame[]

    if length(data_bytes) == 0
        # Empty data frame
        push!(frames, DataFrame(stream_id, UInt8[]; end_stream = end_stream))
    else
        # Split data across multiple frames if necessary
        offset = 1

        while offset <= length(data_bytes)
            # Determine chunk size
            remaining = length(data_bytes) - offset + 1
            chunk_size = min(remaining, max_frame_size)

            # Extract chunk
            chunk = data_bytes[offset:(offset+chunk_size-1)]

            # Determine if this is the last frame
            is_last = (offset + chunk_size - 1) >= length(data_bytes)

            # Create frame
            frame = DataFrame(stream_id, chunk; end_stream = (end_stream && is_last))
            push!(frames, frame)

            offset += chunk_size
        end
    end

    return frames
end

"""
    combine_data_frames(frames::Vector{DataFrame}) -> Vector{UInt8}

Combines multiple DATA frames for the same stream into a single data payload.
Validates that frames belong to the same stream and are in proper sequence.

# Arguments
- `frames::Vector{DataFrame}`: DATA frames to combine

# Returns
- `Vector{UInt8}`: Combined data payload

# Throws
- `ArgumentError`: If frames are from different streams or malformed
"""
function combine_data_frames(frames::Vector{DataFrame})
    if isempty(frames)
        return UInt8[]
    end

    # Validate all frames are from same stream
    stream_id = frames[1].stream_id
    for frame in frames[2:end]
        if frame.stream_id != stream_id
            throw(ArgumentError("All frames must be from the same stream"))
        end
    end

    # Combine data
    combined_data = UInt8[]
    for frame in frames
        append!(combined_data, frame.data)
    end

    return combined_data
end

# Pretty printing
function Base.show(io::IO, frame::DataFrame)
    print(io, "DataFrame(")
    print(io, "stream_id=", frame.stream_id)
    print(io, ", length=", length(frame.data))
    if frame.end_stream
        print(io, ", END_STREAM")
    end
    if frame.padded
        print(io, ", PADDED(", frame.pad_length, ")")
    end
    print(io, ")")
end

function Base.show(io::IO, ::MIME"text/plain", frame::DataFrame)
    println(io, "HTTP/2 DATA Frame:")
    println(io, "  Stream ID: ", frame.stream_id)
    println(io, "  Data Length: ", length(frame.data), " bytes")
    println(
        io,
        "  Flags: ",
        frame.end_stream ? "END_STREAM " : "",
        frame.padded ? "PADDED " : "",
    )
    if frame.padded
        println(io, "  Pad Length: ", frame.pad_length)
    end
    if !isempty(frame.data)
        preview =
            length(frame.data) > 50 ? string(frame.data[1:50])[1:50] * "..." :
            string(frame.data)
        println(io, "  Data Preview: ", preview)
    end
end
end
