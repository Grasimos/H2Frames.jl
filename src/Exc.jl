module Exc
# --- RFC 7540 Frame Exception Types ---

export FrameException,
    ProtocolError,
    FrameSizeError,
    FlowControlError,
    CompressionError,
    SettingsError,
    UnknownFrameTypeError,
    FrameError,
    GOAWAY_NO_ERROR,
    GOAWAY_PROTOCOL_ERROR,
    GOAWAY_INTERNAL_ERROR,
    GOAWAY_FLOW_CONTROL_ERROR,
    GOAWAY_SETTINGS_TIMEOUT,
    GOAWAY_STREAM_CLOSED,
    GOAWAY_FRAME_SIZE_ERROR,
    GOAWAY_REFUSED_STREAM,
    GOAWAY_CANCEL,
    GOAWAY_COMPRESSION_ERROR,
    GOAWAY_CONNECT_ERROR,
    GOAWAY_ENHANCE_YOUR_CALM,
    GOAWAY_INADEQUATE_SECURITY,
    GOAWAY_HTTP_1_1_REQUIRED

abstract type FrameException end

"""
    ProtocolError(msg::String, stream_id::Union{Int,Nothing}=nothing)

Represents a generic HTTP/2 PROTOCOL_ERROR (0x1).
"""
# For compatibility with all frame modules, allow ProtocolError, FrameSizeError, FlowControlError to accept UInt32 as stream_id
struct ProtocolError <: FrameException
    msg::String
    stream_id::Union{Int,UInt32,Nothing}
    ProtocolError(msg::String, stream_id::Union{Int,UInt32,Nothing} = nothing) =
        new(msg, stream_id)
end
Base.showerror(io::IO, e::ProtocolError) = print(
    io,
    "ProtocolError: ",
    e.msg,
    isnothing(e.stream_id) ? "" : ", stream_id=" * string(e.stream_id),
)

"""
    FrameSizeError(message::String, stream_id::Union{Int,Nothing}=nothing)

Represents an error when a frame's size is invalid (FRAME_SIZE_ERROR, 0x6).
"""
struct FrameSizeError <: FrameException
    message::String
    stream_id::Union{Int,UInt32,Nothing}
    FrameSizeError(message::String, stream_id::Union{Int,UInt32,Nothing} = nothing) =
        new(message, stream_id)
end
Base.showerror(io::IO, e::FrameSizeError) = print(
    io,
    "FrameSizeError: ",
    e.message,
    isnothing(e.stream_id) ? "" : ", stream_id=" * string(e.stream_id),
)

"""
    FlowControlError(msg::String, stream_id::Union{Int,Nothing}=nothing)

Represents a FLOW_CONTROL_ERROR (0x3).
"""
struct FlowControlError <: FrameException
    msg::String
    stream_id::Union{Int,UInt32,Nothing}
    FlowControlError(msg::String, stream_id::Union{Int,UInt32,Nothing} = nothing) =
        new(msg, stream_id)
end
Base.showerror(io::IO, e::FlowControlError) = print(
    io,
    "FlowControlError: ",
    e.msg,
    isnothing(e.stream_id) ? "" : ", stream_id=" * string(e.stream_id),
)

"""
    CompressionError(msg::String, stream_id::Union{Int,Nothing}=nothing)

Represents a COMPRESSION_ERROR (0x9).
"""
struct CompressionError <: FrameException
    msg::String
    stream_id::Union{Int,Nothing}
    CompressionError(msg::String, stream_id::Union{Int,Nothing} = nothing) =
        new(msg, stream_id)
end
Base.showerror(io::IO, e::CompressionError) = print(
    io,
    "CompressionError: ",
    e.msg,
    isnothing(e.stream_id) ? "" : ", stream_id=" * string(e.stream_id),
)

"""
    SettingsError(msg::String)

Represents an error related to invalid or unsupported SETTINGS parameters.
"""
struct SettingsError <: FrameException
    msg::String
    stream_id::Union{Int,UInt32,Nothing}
    SettingsError(msg::String, stream_id::Union{Int,UInt32,Nothing} = nothing) =
        new(msg, stream_id)
end
Base.showerror(io::IO, e::SettingsError) = print(
    io,
    "SettingsError: ",
    e.msg,
    isnothing(e.stream_id) ? "" : ", stream_id=" * string(e.stream_id),
)

"""
    UnknownFrameTypeError(frame_type::UInt8)

Represents an unknown or unsupported frame type.
"""
struct UnknownFrameTypeError <: FrameException
    frame_type::UInt8
end
Base.showerror(io::IO, e::UnknownFrameTypeError) =
    print(io, "UnknownFrameTypeError: frame_type=", e.frame_type)

"""
    FrameError(msg::String, stream_id::Union{Int,UInt32,Nothing}=nothing)

Represents a generic error related to frame construction or validation.
"""
struct FrameError <: FrameException
    msg::String
    stream_id::Union{Int,UInt32,Nothing}
    FrameError(msg::String, stream_id::Union{Int,UInt32,Nothing} = nothing) =
        new(msg, stream_id)
end
Base.showerror(io::IO, e::FrameError) = print(
    io,
    "FrameError: ",
    e.msg,
    isnothing(e.stream_id) ? "" : ", stream_id=" * string(e.stream_id),
)

# HTTP/2 GOAWAY Error Codes (RFC 7540 Section 7)
const GOAWAY_NO_ERROR = 0x0
const GOAWAY_PROTOCOL_ERROR = 0x1
const GOAWAY_INTERNAL_ERROR = 0x2
const GOAWAY_FLOW_CONTROL_ERROR = 0x3
const GOAWAY_SETTINGS_TIMEOUT = 0x4
const GOAWAY_STREAM_CLOSED = 0x5
const GOAWAY_FRAME_SIZE_ERROR = 0x6
const GOAWAY_REFUSED_STREAM = 0x7
const GOAWAY_CANCEL = 0x8
const GOAWAY_COMPRESSION_ERROR = 0x9
const GOAWAY_CONNECT_ERROR = 0xa
const GOAWAY_ENHANCE_YOUR_CALM = 0xb
const GOAWAY_INADEQUATE_SECURITY = 0xc
const GOAWAY_HTTP_1_1_REQUIRED = 0xd

end
