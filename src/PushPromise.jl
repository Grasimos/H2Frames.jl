module PushPromise
# PUSH_PROMISE Frame Implementation
# RFC 7540 Section 6.6
using Http2Hpack #https://github.com/Grasimos/Http2Hpack.jl
using ..FrameTypes
using ..Exc
using ..Http2Frames: is_valid_stream_id

import ..serialize_payload
import ..frame_type
import ..frame_flags
import ..stream_id

export PushPromiseFrame, deserialize_push_promise_frame, create_push_promise_frame

const PUSH_PROMISE_END_HEADERS = 0x4  # END_HEADERS flag
const PUSH_PROMISE_PADDED = 0x8       # PADDED flag

"""
    PushPromiseFrame

PUSH_PROMISE frames are used to notify the peer endpoint in advance of streams 
that the sender intends to initiate. The PUSH_PROMISE frame includes the unsigned 
31-bit identifier of the stream the endpoint plans to create along with a set of 
headers that provide additional context for the stream.

Frame Format:
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Pad Length? (8)|
+-+-------------+-----------------------------------------------+
|R|                  Promised Stream ID (31)                    |
+-+-------------------------------------------------------------+
|                   Header Block Fragment (*)                 ...
+-+-------------------------------------------------------------+
|                           Padding (*)                      ...
+-+-------------------------------------------------------------+

Fields:
- Pad Length: 8-bit field containing the length of the frame padding (only if PADDED flag is set)
- R: Reserved 1-bit field
- Promised Stream ID: 31-bit stream identifier for the stream reserved by the PUSH_PROMISE
- Header Block Fragment: HPACK-encoded header block
- Padding: Padding octets (only if PADDED flag is set)
"""
struct PushPromiseFrame <: HTTP2Frame
    stream_id::UInt32               # The stream to which the promise is sent
    padded::Bool
    end_headers::Bool
    pad_length::UInt8
    promised_stream_id::UInt32      # The ID of the stream being created
    header_block_fragment::Vector{UInt8}

    function PushPromiseFrame(
        stream_id::UInt32,
        promised_stream_id::UInt32,
        header_block::Vector{UInt8};
        padded::Bool = false,
        end_headers::Bool = true,
        pad_length::UInt8 = 0x00,
    )
        # Basic validation checks
        if stream_id == 0
            throw(
                ProtocolError(
                    "PUSH_PROMISE frames must be associated with an existing, open stream",
                    stream_id,
                ),
            )
        end
        if promised_stream_id == 0 || isodd(promised_stream_id)
            throw(
                ProtocolError(
                    "Promised Stream ID must be a non-zero, even number",
                    promised_stream_id,
                ),
            )
        end
        if padded && pad_length >= length(header_block) + 1
            throw(FrameSizeError("Missing Pad Length", stream_id))
        end
        if !padded && pad_length > 0
            throw(ProtocolError("Pad length specified but PADDED flag not set", stream_id))
        end
        new(stream_id, padded, end_headers, pad_length, promised_stream_id, header_block)
    end
end

# Multiple dispatch outer constructor for PushPromiseFrame to accept Int/UInt/Integer and promote to correct types
function PushPromiseFrame(
    stream_id::Integer,
    promised_stream_id::Integer,
    header_block::Vector{UInt8};
    kwargs...,
)
    PushPromiseFrame(UInt32(stream_id), UInt32(promised_stream_id), header_block; kwargs...)
end



"""
    frame_type(::Type{PushPromiseFrame}) -> UInt8

Return the frame type identifier for PUSH_PROMISE frames.
"""
frame_type(::PushPromiseFrame) = PUSH_PROMISE_FRAME

stream_id(frame::PushPromiseFrame) = frame.stream_id

function frame_flags(frame::PushPromiseFrame)
    flags = UInt8(0)
    if frame.end_headers
        ;
        flags |= PUSH_PROMISE_END_HEADERS;
    end
    if frame.padded
        ;
        flags |= PUSH_PROMISE_PADDED;
    end
    return flags
end

"""
    serialize_payload(frame::PushPromiseFrame) -> Vector{UInt8}

Serialize a PUSH_PROMISE frame to its wire format.
"""
function serialize_payload(frame::PushPromiseFrame)
    buffer = IOBuffer()

    # Payload order: [Pad Length?] Promised Stream ID, Header Block Fragment, [Padding]
    if frame.padded
        write(buffer, frame.pad_length)
    end

    # Write the Promised Stream ID (32-bit, with the R bit zeroed)
    write(buffer, hton(frame.promised_stream_id & STREAM_ID_MASK))

    # Write the HPACK-encoded header block
    write(buffer, frame.header_block_fragment)

    # Add the padding at the end
    if frame.padded && frame.pad_length > 0
        write(buffer, zeros(UInt8, frame.pad_length))
    end

    return take!(buffer)
end

"""
    deserialize_push_promise_frame(header::FrameHeader, payload::Vector{UInt8}) -> PushPromiseFrame

Deserialize a PUSH_PROMISE frame from its wire format.
"""
function deserialize_push_promise_frame(header::FrameHeader, payload::Vector{UInt8})
    if header.stream_id == 0
        throw(
            ProtocolError(
                "PUSH_PROMISE frames must be associated with an existing stream",
                0,
            ),
        )
    end

    padded = (header.flags & PUSH_PROMISE_PADDED) != 0
    end_headers = (header.flags & PUSH_PROMISE_END_HEADERS) != 0

    reader = IOBuffer(payload)
    pad_length = UInt8(0)

    if padded
        !eof(reader) || throw(FrameSizeError("Missing Pad Length", header.stream_id))
        pad_length = read(reader, UInt8)
    end

    bytesavailable(reader) >= 4 ||
        throw(FrameSizeError("Payload too short for Promised Stream ID", header.stream_id))
    promised_stream_id = ntoh(read(reader, UInt32)) & STREAM_ID_MASK

    if promised_stream_id == 0
        throw(ProtocolError("Promised Stream ID cannot be zero", header.stream_id))
    end

    header_fragment_size = bytesavailable(reader) - pad_length
    if header_fragment_size < 0
        throw(ProtocolError("Invalid padding length", header.stream_id))
    end

    header_block_fragment = read(reader, header_fragment_size)

    return PushPromiseFrame(
        header.stream_id,
        promised_stream_id,
        header_block_fragment;
        padded = padded,
        end_headers = end_headers,
        pad_length = pad_length,
    )
end



"""
    create_push_promise_frame(original_stream_id, promised_stream_id, headers, hpack_encoder)

Factory function to create a PUSH_PROMISE frame by encoding the request headers.
"""
function create_push_promise_frame(
    original_stream_id::UInt32,
    promised_stream_id::UInt32,
    request_headers::Vector{Pair{String,String}},
    hpack_encoder::HPACKEncoder,
)
    header_block = Http2Hpack.encode_headers(hpack_encoder, request_headers)

    return PushPromiseFrame(
        original_stream_id,
        promised_stream_id,
        header_block;
        end_headers = true,
    )
end

# Multiple dispatch: allow any Integer type for stream IDs
function create_push_promise_frame(
    original_stream_id::Integer,
    promised_stream_id::Integer,
    request_headers::Vector{Pair{String,String}},
    hpack_encoder::HPACKEncoder,
)
    create_push_promise_frame(
        UInt32(original_stream_id),
        UInt32(promised_stream_id),
        request_headers,
        hpack_encoder,
    )
end

end
