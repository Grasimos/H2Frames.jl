module Continuation
# frames/continuation.jl - CONTINUATION frame implementation
# Implements RFC 7540 Section 6.10 - CONTINUATION frame

using ..FrameTypes
using ..Exc
using ..H2Frames: is_valid_stream_id

import ..serialize_payload
import ..frame_type
import ..frame_flags
import ..stream_id

export ContinuationFrame,
    decode_continuation_frame,
    validate_continuation_frame,
    create_continuation_frames,
    reconstruct_header_block

const CONTINUATION_END_HEADERS = 0x4

"""
    ContinuationFrame

CONTINUATION frames are used to continue a sequence of header block fragments.
Any number of CONTINUATION frames can be sent, as long as the preceding frame
is on the same stream and is a HEADERS, PUSH_PROMISE, or CONTINUATION frame
without the END_HEADERS flag set.

Frame Format:
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Header Block Fragment (*)                 ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Flags:
- END_HEADERS (0x4): Indicates that this frame ends a header block
"""
struct ContinuationFrame <: HTTP2Frame
    stream_id::UInt32
    end_headers::Bool
    header_block_fragment::Vector{UInt8}

    function ContinuationFrame(
        stream_id::UInt32,
        header_block_fragment::Vector{UInt8};
        end_headers::Bool = false,
    )
        # Validate stream ID
        if !is_valid_stream_id(stream_id)
            throw(
                ProtocolError(
                    "CONTINUATION frames MUST be associated with a stream",
                    stream_id,
                ),
            )
        end

        new(stream_id, end_headers, header_block_fragment)
    end
end

# Multiple dispatch outer constructor for ContinuationFrame to accept Int/UInt/Integer and promote to correct types
function ContinuationFrame(
    stream_id::Integer,
    header_block_fragment::Vector{UInt8};
    kwargs...,
)
    ContinuationFrame(UInt32(stream_id), header_block_fragment; kwargs...)
end


"""
    frame_type(::Type{ContinuationFrame}) -> UInt8

Returns the frame type identifier for CONTINUATION frames.
"""
frame_type(::ContinuationFrame) = CONTINUATION_FRAME

stream_id(frame::ContinuationFrame) = frame.stream_id

"""
    frame_flags(frame::ContinuationFrame) -> UInt8

Returns the flags byte for the CONTINUATION frame.
"""
function frame_flags(frame::ContinuationFrame)
    flags = UInt8(0)
    if frame.end_headers
        flags |= CONTINUATION_END_HEADERS
    end
    return flags
end

"""
    serialize_payload(frame::ContinuationFrame) -> Vector{UInt8}

Encode a CONTINUATION frame into its binary representation.
"""
function serialize_payload(frame::ContinuationFrame)
    # The payload is simply the header block fragment.
    return frame.header_block_fragment
end

"""
    decode_continuation_frame(header::FrameHeader, payload::Vector{UInt8}) -> ContinuationFrame

Decode a CONTINUATION frame from its binary representation.
"""
function decode_continuation_frame(header::FrameHeader, payload::Vector{UInt8})
    # Validate frame type
    if header.frame_type != CONTINUATION_FRAME
        throw(FrameError("Invalid frame type for CONTINUATION frame"))
    end
    # Validate stream ID
    if !is_valid_stream_id(header.stream_id)
        throw(FrameStreamError("CONTINUATION frames MUST be associated with a stream"))
    end
    # Validate payload length
    if !is_valid_frame_size(length(payload); max_frame_size = header.length)
        throw(FrameSizeError("CONTINUATION frame payload length mismatch"))
    end
    end_headers = (header.flags & CONTINUATION_END_HEADERS) != 0
    # The entire payload is the header block fragment
    header_block_fragment = copy(payload)

    return ContinuationFrame(
        UInt32(header.stream_id),
        header_block_fragment;
        end_headers = end_headers,
    )
end


"""
    create_continuation_frames(header_block::Vector{UInt8}, stream_id::UInt32, 
                             max_frame_size::UInt32) -> Vector{ContinuationFrame}

Split a large header block into multiple CONTINUATION frames if necessary.
The first frame should be a HEADERS or PUSH_PROMISE frame, followed by
CONTINUATION frames created by this function.
"""
function create_continuation_frames(
    header_block::Vector{UInt8},
    stream_id::UInt32,
    max_frame_size::UInt32,
)
    frames = Vector{ContinuationFrame}()

    if isempty(header_block)
        return frames
    end

    offset = 1
    header_block_length = length(header_block)

    while offset <= header_block_length
        # Calculate fragment size (leave room for frame header overhead)
        remaining = header_block_length - offset + 1
        fragment_size = min(remaining, Int(max_frame_size))

        # Extract fragment
        fragment_end = offset + fragment_size - 1
        fragment = header_block[offset:fragment_end]

        # Determine if this is the last frame
        is_last = fragment_end >= header_block_length

        # Create CONTINUATION frame
        frame = ContinuationFrame(stream_id, fragment; end_headers = is_last)
        push!(frames, frame)

        offset = fragment_end + 1
    end

    return frames
end

"""
    reconstruct_header_block(frames::Vector{ContinuationFrame}) -> Vector{UInt8}

Reconstruct a complete header block from a sequence of CONTINUATION frames.
"""
function reconstruct_header_block(frames::Vector{<:HTTP2Frame}) # Accepts HEADERS/PUSH_PROMISE as well
    if isempty(frames)
        return UInt8[]
    end

    buffer = IOBuffer()
    expected_stream_id = first(frames).stream_id

    for (i, frame) in enumerate(frames)
        if frame.stream_id != expected_stream_id
            throw(HTTP2ProtocolError("CONTINUATION frames must belong to the same stream"))
        end

        is_last_frame = (i == length(frames))

        # The END_HEADERS flag must be set ONLY on the last frame of the sequence.
        if !is_last_frame && frame.end_headers
            throw(
                FrameError(
                    "Only the last frame in a header block sequence can have the END_HEADERS flag set",
                ),
            )
        elseif is_last_frame && !frame.end_headers
            throw(
                FrameError(
                    "The last frame in a header block sequence must have the END_HEADERS flag set",
                ),
            )
        end

        write(buffer, frame.header_block_fragment)
    end

    return take!(buffer)
end

# Convenience methods for frame interface
Base.show(io::IO, frame::ContinuationFrame) = print(
    io,
    "ContinuationFrame(stream_id=$(frame.stream_id), " *
    "end_headers=$(frame.end_headers), " *
    "fragment_length=$(length(frame.header_block_fragment)))",
)

end
