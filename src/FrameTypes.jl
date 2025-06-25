module FrameTypes

export FRAME_HEADER_SIZE,
    DEFAULT_MAX_FRAME_SIZE,
    MAX_FRAME_SIZE_UPPER_BOUND,
    MAX_STREAM_ID,
    STREAM_ID_MASK,
    RESERVED_STREAM_ID_BIT,
    FrameHeader,
    FrameReader,
    SettingsParameter,
    HTTP2Frame
export FrameType,
    DATA_FRAME,
    HEADERS_FRAME,
    PRIORITY_FRAME,
    RST_STREAM_FRAME,
    SETTINGS_FRAME,
    PUSH_PROMISE_FRAME,
    PING_FRAME,
    GOAWAY_FRAME,
    WINDOW_UPDATE_FRAME,
    CONTINUATION_FRAME
export SettingsParameter,
    SETTINGS_HEADER_TABLE_SIZE,
    SETTINGS_ENABLE_PUSH,
    SETTINGS_MAX_CONCURRENT_STREAMS,
    SETTINGS_INITIAL_WINDOW_SIZE,
    SETTINGS_MAX_FRAME_SIZE,
    SETTINGS_MAX_HEADER_LIST_SIZE,
    SETTINGS_ENABLE_CONNECT_PROTOCOL


const FRAME_HEADER_SIZE = 9
const DEFAULT_MAX_FRAME_SIZE = 16384  # 2^14
const MAX_FRAME_SIZE_UPPER_BOUND = 16777215  # 2^24 - 1
const MAX_STREAM_ID = 2147483647  # 2^31 - 1
const STREAM_ID_MASK = 0x7fffffff
const RESERVED_STREAM_ID_BIT = 0x80000000


# Frame Types (8-bit values) - Section 6
@enum FrameType::UInt8 begin
    DATA_FRAME = 0x0            # Data frame
    HEADERS_FRAME = 0x1         # HTTP headers frame
    PRIORITY_FRAME = 0x2        # Stream priority frame
    RST_STREAM_FRAME = 0x3      # Stream reset frame
    SETTINGS_FRAME = 0x4        # Connection settings frame
    PUSH_PROMISE_FRAME = 0x5    # Server push promise frame
    PING_FRAME = 0x6            # Ping frame for connection check
    GOAWAY_FRAME = 0x7          # Connection shutdown frame
    WINDOW_UPDATE_FRAME = 0x8   # Flow control window update frame
    CONTINUATION_FRAME = 0x9    # Continuation of header block
end

# Settings Parameters (Section 6.5.2)
@enum SettingsParameter::UInt16 begin
    SETTINGS_HEADER_TABLE_SIZE = 0x1        # Header table size
    SETTINGS_ENABLE_PUSH = 0x2              # Enable server push
    SETTINGS_MAX_CONCURRENT_STREAMS = 0x3   # Max concurrent streams
    SETTINGS_INITIAL_WINDOW_SIZE = 0x4      # Initial flow control window size
    SETTINGS_MAX_FRAME_SIZE = 0x5           # Max frame size
    SETTINGS_MAX_HEADER_LIST_SIZE = 0x6     # Max header list size
    SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x8  # Enable extended CONNECT
end

# Settings validation limits (Section 6.5.2)
const SETTINGS_ENABLE_PUSH_MIN = 0          # Minimum value for ENABLE_PUSH
const SETTINGS_ENABLE_PUSH_MAX = 1          # Maximum value for ENABLE_PUSH
const SETTINGS_INITIAL_WINDOW_SIZE_MAX = 2147483647  # Maximum initial window size
const SETTINGS_MAX_FRAME_SIZE_MIN = 16384            # Minimum frame size
const SETTINGS_MAX_FRAME_SIZE_MAX = 16777215         # Maximum frame size

# Default Settings Values (Section 6.5.2)
const DEFAULT_SETTINGS = Dict{SettingsParameter,UInt32}(
    SETTINGS_HEADER_TABLE_SIZE => 4096,         # 4KB header table
    SETTINGS_ENABLE_PUSH => 1,                  # Server push enabled
    SETTINGS_MAX_CONCURRENT_STREAMS => typemax(UInt32),  # Unlimited streams
    SETTINGS_INITIAL_WINDOW_SIZE => 65535,      # 64KB - 1 initial window
    SETTINGS_MAX_FRAME_SIZE => 16384,           # 16KB max frame
    SETTINGS_MAX_HEADER_LIST_SIZE => typemax(UInt32),     # Unlimited headers
)

"""
Abstract base type for all HTTP/2 frames.
"""
abstract type HTTP2Frame end # Abstract base type for all HTTP/2 frames

"""
    FrameHeader

HTTP/2 frame header (9 bytes) containing frame metadata.
"""
struct FrameHeader # Struct that defines the frame header
    length::UInt32        # 24-bit frame payload length 
    frame_type::FrameType # 8-bit frame type 
    flags::UInt8          # 8-bit flags 
    stream_id::UInt32      # 31-bit stream identifier (1 bit reserved) 

    function FrameHeader(
        length::Integer,
        frame_type::FrameType,
        flags::Integer,
        stream_id::Integer,
    ) # Constructor with parameter validation
        if length > MAX_FRAME_SIZE_UPPER_BOUND
            throw(
                FrameSizeError(
                    "Frame length $length exceeds maximum $(MAX_FRAME_SIZE_UPPER_BOUND)",
                ),
            )
        end
        if stream_id < 0 || stream_id > MAX_STREAM_ID
            throw(
                ProtocolError(
                    "Stream ID $stream_id out of valid range [0, $MAX_STREAM_ID]",
                    stream_id,
                ),
            )
        end
        new(UInt32(length), frame_type, UInt8(flags), UInt32(stream_id)) # Creates new instance
    end
end


"""
    FrameReader

Stateful frame reader that handles partial reads and frame boundaries.
"""
mutable struct FrameReader # Mutable struct for reading frames
    buffer::Vector{UInt8} # Buffer for storing data
    position::Int # Current position in the buffer
    expected_frame_size::Union{Int,Nothing} # Expected frame size
    header::Union{FrameHeader,Nothing} # Frame header or Nothing

    FrameReader() = new(UInt8[], 1, nothing, nothing) # Default constructor
end

end
