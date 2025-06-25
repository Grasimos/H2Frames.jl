module Priority
# HTTP/2 PRIORITY Frame Implementation
# RFC 7540 Section 6.3
using ..FrameTypes
using ..Exc

import ..serialize_payload
import ..frame_type
import ..frame_flags
import ..stream_id

export PriorityFrame,
    decode_priority_frame, actual_weight, validate_priority_frame, apply_priority_frame!


"""
    PriorityFrame(stream_id, exclusive, stream_dependency, weight)

Represents an HTTP/2 PRIORITY frame.

The PRIORITY frame (type=0x2) specifies the sender-advised priority of a stream.
It can be sent in any stream state, including idle or closed streams.

# Fields
- `stream_id::UInt32`: Stream identifier (must not be 0x0)
- `exclusive::Bool`: Indicates that the stream dependency is exclusive
- `stream_dependency::UInt32`: Stream dependency identifier
- `weight::UInt8`: Priority weight (1-256, stored as 0-255)

# Frame Format
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|E|                 Stream Dependency (31)                     |
+-+-------------+-----------------------------------------------+
|   Weight (8)  |
+-+-------------+
```

Where:
- E: A single-bit flag indicating exclusive dependency
- Stream Dependency: 31-bit stream identifier for the stream that this stream depends on
- Weight: An 8-bit weight value (actual weight is value + 1)

# Example
```julia
using H2Frames
frame = PriorityFrame(3, false, 1, 10)
```
"""
struct PriorityFrame <: HTTP2Frame
    stream_id::UInt32
    exclusive::Bool
    stream_dependency::UInt32
    weight::UInt8

    function PriorityFrame(
        stream_id::Integer,
        exclusive::Bool,
        stream_dependency::Integer,
        weight::Integer,
    )
        sid = UInt32(stream_id)
        dep = UInt32(stream_dependency)
        if sid == 0x0
            throw(
                ProtocolError(
                    "PRIORITY frames must have a non-zero stream identifier",
                    sid,
                ),
            )
        end
        if sid == dep
            throw(ProtocolError("PRIORITY frame cannot depend on itself", sid))
        end
        if weight < 1 || weight > 256
            throw(FrameSizeError("Weight must be in 1:256", sid))
        end
        # Store wire value (0-255), actual weight is weight (1-256)
        new(sid, exclusive, dep, UInt8(weight - 1))
    end
end

frame_type(frame::PriorityFrame) = PRIORITY_FRAME

# frame_type(::PriorityFrame) = PRIORITY_FRAME
stream_id(frame::PriorityFrame) = frame.stream_id



"""
    frame_flags(frame::PriorityFrame) -> UInt8

Returns the flags for PRIORITY frames (always 0x0 - no flags defined).
"""
frame_flags(frame::PriorityFrame) = 0x00

"""
    actual_weight(frame::PriorityFrame) -> UInt8

Returns the actual priority weight (1-256) from the stored weight (0-255).

# Example
```julia
w = actual_weight(frame)
```
"""
actual_weight(frame::PriorityFrame) = frame.weight + 0x01

"""
    encode_priority_frame(frame::PriorityFrame) -> Vector{UInt8}

Encodes a PRIORITY frame into its binary representation.

# Returns
A 5-byte vector containing the encoded priority information.
"""
function serialize_payload(frame::PriorityFrame)
    buffer = IOBuffer()

    dependency_with_flag = frame.stream_dependency
    if frame.exclusive
        dependency_with_flag |= RESERVED_STREAM_ID_BIT # Set the E flag
    end

    write(buffer, hton(dependency_with_flag))
    write(buffer, frame.weight)

    return take!(buffer)
end

"""
    decode_priority_frame(stream_id::UInt32, flags::UInt8, payload::Vector{UInt8}) -> PriorityFrame

Decodes a PRIORITY frame from its binary representation.

# Arguments
- `stream_id`: The stream identifier from the frame header
- `flags`: The flags from the frame header (should be 0x0)
- `payload`: The frame payload (must be exactly 5 bytes)

# Returns
A `PriorityFrame` instance.

# Throws
- `ProtocolError`: If the payload length is incorrect or flags are invalid
- `FrameError`: If stream identifiers are invalid
"""
function decode_priority_frame(stream_id::UInt32, flags::UInt8, payload::Vector{UInt8})
    if length(payload) != 5
        throw(FrameSizeError("PRIORITY frame payload must be exactly 5 bytes"))
    end
    if flags != 0x00
        throw(ProtocolError("PRIORITY frame must not have any flags set"))
    end

    reader = IOBuffer(payload)
    dependency_raw = ntoh(read(reader, UInt32))
    exclusive = (dependency_raw & RESERVED_STREAM_ID_BIT) != 0
    stream_dependency = dependency_raw & STREAM_ID_MASK
    weight = read(reader, UInt8)

    return PriorityFrame(stream_id, exclusive, stream_dependency, weight)
end

"""
    validate_priority_frame(frame::PriorityFrame, connection_state) -> Nothing

Validates a PRIORITY frame according to HTTP/2 protocol rules.

# Validation Rules
1. Stream ID must not be 0x0
2. Stream cannot depend on itself
3. Must not create circular dependencies (if connection state is provided)

# Throws
- `ProtocolError`: If validation fails
"""
function validate_priority_frame(frame::PriorityFrame, connection_state = nothing)
    # Basic checks are already done in the constructor.
    # More complex logic could be added here, e.g., checking for cycles.
    if connection_state !== nothing &&
       would_create_cycle(connection_state, frame.stream_id, frame.stream_dependency)
        throw(ProtocolError("PRIORITY frame would create circular dependency"))
    end
    return true
end

"""
    priority_frame_summary(frame::PriorityFrame) -> String

Returns a human-readable summary of the PRIORITY frame.
"""
function priority_frame_summary(frame::PriorityFrame)
    exclusive_str = frame.exclusive ? "exclusive" : "non-exclusive"
    return "PRIORITY[stream=$(frame.stream_id), depends_on=$(frame.stream_dependency), $(exclusive_str), weight=$(actual_weight(frame))]"
end

# Display methods
function Base.show(io::IO, frame::PriorityFrame)
    print(io, priority_frame_summary(frame))
end

function Base.show(io::IO, ::MIME"text/plain", frame::PriorityFrame)
    println(io, "HTTP/2 PRIORITY Frame:")
    println(io, "  Stream ID: $(frame.stream_id)")
    println(io, "  Stream Dependency: $(frame.stream_dependency)")
    println(io, "  Exclusive: $(frame.exclusive)")
    println(io, "  Weight: $(actual_weight(frame)) (stored as $(frame.weight))")
end

# Equality and hashing
function Base.:(==)(a::PriorityFrame, b::PriorityFrame)
    return a.stream_id == b.stream_id &&
           a.exclusive == b.exclusive &&
           a.stream_dependency == b.stream_dependency &&
           a.weight == b.weight
end

function Base.hash(frame::PriorityFrame, h::UInt)
    h = hash(frame.stream_id, h)
    h = hash(frame.exclusive, h)
    h = hash(frame.stream_dependency, h)
    h = hash(frame.weight, h)
    return h
end


end
