module FrameSettings
using ..Exc

# SETTINGS Frame Implementation
# RFC 7540 Section 6.5
using ..FrameTypes
using ..Exc

import ..serialize_payload
import ..frame_type
import ..frame_flags
import ..stream_id
import ..serialize_frame

const SETTINGS_ACK = 0x1 

export SettingsFrame,
    is_ack,
    deserialize_settings_frame,
    create_settings_ack,
    create_initial_settings,
    validate_settings_frame,
    get_setting,
    has_setting,
    settings_to_string,
    SETTINGS_ACK,
    setting_name


"""
    SettingsFrame(parameters::Dict; ack=false)

Represents an HTTP/2 SETTINGS frame.

# Example
```julia
using H2Frames
frame = SettingsFrame(Dict(SETTINGS_ENABLE_PUSH => 1))
```
"""
struct SettingsFrame <: HTTP2Frame
    ack::Bool
    parameters::Dict{UInt16,UInt32}

    function SettingsFrame(
        parameters::Dict{UInt16,UInt32} = Dict{UInt16,UInt32}();
        ack::Bool = false,
    )
        if ack && !isempty(parameters)
            throw(FrameError("SETTINGS frames with ACK flag must have empty payload"))
        end
        for (identifier, value) in parameters
            validate_setting_parameter(identifier, value)
        end
        new(ack, parameters)
    end

    # Outer constructor for Dict{SettingsParameter, Integer}
    function SettingsFrame(parameters::Dict{SettingsParameter,Integer}; ack::Bool = false)
        converted = Dict{UInt16,UInt32}()
        for (k, v) in parameters
            converted[UInt16(k)] = UInt32(v)
        end
        # Validate here as well
        for (identifier, value) in converted
            validate_setting_parameter(identifier, value)
        end
        SettingsFrame(converted; ack = ack)
    end

    # Outer constructor for Dict{SettingsParameter, T}
    function SettingsFrame(
        parameters::Dict{SettingsParameter,T};
        ack::Bool = false,
    ) where {T}
        converted = Dict{UInt16,UInt32}()
        for (k, v) in parameters
            converted[UInt16(k)] = UInt32(v)
        end
        # Validate here as well
        for (identifier, value) in converted
            validate_setting_parameter(identifier, value)
        end
        SettingsFrame(converted; ack = ack)
    end
end


"""
    is_ack(frame::SettingsFrame) -> Bool

Check if the SETTINGS frame is an acknowledgment.
"""
is_ack(frame::SettingsFrame) = frame.ack

"""
    frame_type(::Type{SettingsFrame}) -> UInt8

Return the frame type identifier for SETTINGS frames.
"""
frame_type(::SettingsFrame) = SETTINGS_FRAME

stream_id(frame::SettingsFrame) = 0 # SETTINGS frame is always on stream 0

function frame_flags(frame::SettingsFrame)
    return frame.ack ? SETTINGS_ACK : UInt8(0)
end

const SETTINGS_ENABLE_PUSH_MIN = 0
const SETTINGS_ENABLE_PUSH_MAX = 1
const SETTINGS_MAX_FRAME_SIZE_MIN = 16384
const SETTINGS_MAX_FRAME_SIZE_MAX = 16777215

"""
    validate_setting_parameter(identifier::UInt16, value::UInt32) -> Nothing

Validate individual setting parameters according to HTTP/2 specification.

# Example
```julia
validate_setting_parameter(UInt16(SETTINGS_ENABLE_PUSH), 1)
```
"""
function validate_setting_parameter(identifier::UInt16, value::UInt32)
    if identifier == UInt16(SETTINGS_ENABLE_PUSH)
        if !(SETTINGS_ENABLE_PUSH_MIN <= value <= SETTINGS_ENABLE_PUSH_MAX)
            throw(FrameError("SETTINGS_ENABLE_PUSH must be 0 or 1"))
        end
    elseif identifier == UInt16(SETTINGS_MAX_FRAME_SIZE)
        if !(SETTINGS_MAX_FRAME_SIZE_MIN <= value <= SETTINGS_MAX_FRAME_SIZE_MAX)
            throw(
                SettingsError(
                    "SETTINGS_MAX_FRAME_SIZE must be between $SETTINGS_MAX_FRAME_SIZE_MIN and $SETTINGS_MAX_FRAME_SIZE_MAX",
                ),
            )
        end
    end
    # Other settings: no range restrictions
end

"""
    serialize_frame(frame::SettingsFrame) -> Vector{UInt8}

Serialize a SETTINGS frame to its wire format.
"""
function serialize_payload(frame::SettingsFrame)
    # For ACK frame, the payload is empty.
    if frame.ack
        return UInt8[]
    end

    buffer = IOBuffer()
    # RFC 7540: The payload is a sequence of Identifier/Value pairs.
    # Sorting is not required by the RFC, but makes the output predictable.
    for (identifier, value) in sort(collect(frame.parameters), by = first)
        write(buffer, hton(identifier)) # 16 bits
        write(buffer, hton(value))      # 32 bits
    end
    return take!(buffer)
end

"""
    deserialize_settings_frame(header::FrameHeader, payload::Vector{UInt8}) -> SettingsFrame

Deserialize a SETTINGS frame from its wire format.
"""
function deserialize_settings_frame(header::FrameHeader, payload::Vector{UInt8})
    if header.frame_type != SETTINGS_FRAME
        throw(FrameError("Invalid frame type for SETTINGS frame"))
    end

    if header.stream_id != 0
        throw(FrameStreamErrorError("SETTINGS frames must be sent on stream 0"))
    end

    ack = (header.flags & SETTINGS_ACK) != 0

    # ACK frames must have empty payload
    if ack && !isempty(payload)
        throw(FrameError("SETTINGS ACK frames must have empty payload"))
    end

    # Non-ACK frames must have payload length divisible by 6
    if !ack && length(payload) % 6 != 0
        throw(FrameError("SETTINGS frame payload length must be multiple of 6"))
    end

    parameters = Dict{UInt16,UInt32}()

    # Parse parameter/value pairs
    if !ack
        for i = 1:6:length(payload)
            identifier = ntoh(reinterpret(UInt16, payload[i:(i+1)])[1])
            value = ntoh(reinterpret(UInt32, payload[(i+2):(i+5)])[1])
            validate_setting_parameter(identifier, value)
            parameters[identifier] = value
        end
    end

    return SettingsFrame(parameters; ack = ack)
end

"""
    create_settings_ack() -> SettingsFrame

Create a SETTINGS ACK frame.
"""
function create_settings_ack()
    return SettingsFrame(; ack = true)
end

"""
    create_initial_settings(;
        header_table_size::Union{UInt32, Nothing}=nothing,
        enable_push::Union{Bool, Nothing}=nothing,
        max_concurrent_streams::Union{UInt32, Nothing}=nothing,
        initial_window_size::Union{UInt32, Nothing}=nothing,
        max_frame_size::Union{UInt32, Nothing}=nothing,
        max_header_list_size::Union{UInt32, Nothing}=nothing
    ) -> SettingsFrame

Create an initial SETTINGS frame with specified parameters.
"""
function create_initial_settings(;
    header_table_size::Union{UInt32,Nothing} = nothing,
    enable_push::Union{Bool,Nothing} = nothing,
    max_concurrent_streams::Union{UInt32,Nothing} = nothing,
    initial_window_size::Union{UInt32,Nothing} = nothing,
    max_frame_size::Union{UInt32,Nothing} = nothing,
    max_header_list_size::Union{UInt32,Nothing} = nothing,
)
    parameters = Dict{UInt16,UInt32}()

    if header_table_size !== nothing
        parameters[SETTINGS_HEADER_TABLE_SIZE] = header_table_size
    end

    if enable_push !== nothing
        parameters[SETTINGS_ENABLE_PUSH] = enable_push ? 1 : 0
    end

    if max_concurrent_streams !== nothing
        parameters[SETTINGS_MAX_CONCURRENT_STREAMS] = max_concurrent_streams
    end

    if initial_window_size !== nothing
        parameters[SETTINGS_INITIAL_WINDOW_SIZE] = initial_window_size
    end

    if max_frame_size !== nothing
        parameters[SETTINGS_MAX_FRAME_SIZE] = max_frame_size
    end

    if max_header_list_size !== nothing
        parameters[SETTINGS_MAX_HEADER_LIST_SIZE] = max_header_list_size
    end

    return SettingsFrame(parameters)
end



"""
    apply_settings_frame(frame::SettingsFrame, settings::Dict{UInt16, UInt32}) -> Dict{UInt16, UInt32}

Apply settings from a frame to a settings dictionary, returning updated settings.
"""
function apply_settings_frame(frame::SettingsFrame, settings::Dict{UInt16,UInt32})
    if is_ack(frame)
        return settings  # ACK frames don't change settings
    end

    new_settings = copy(settings)
    for (identifier, value) in frame.parameters
        new_settings[identifier] = value
    end

    return new_settings
end

"""
    get_setting_value(settings::Dict{UInt16, UInt32}, identifier::UInt16) -> UInt32

Get a setting value with default fallback.
"""
function get_setting_value(settings::Dict{UInt16,UInt32}, identifier::UInt16)
    return get(settings, identifier, get(DEFAULT_SETTINGS, identifier, 0))
end

"""
    settings_equal(settings1::Dict{UInt16, UInt32}, settings2::Dict{UInt16, UInt32}) -> Bool

Compare two settings dictionaries for equality, considering defaults.
"""
function settings_equal(settings1::Dict{UInt16,UInt32}, settings2::Dict{UInt16,UInt32})
    all_keys = union(keys(settings1), keys(settings2), keys(DEFAULT_SETTINGS))

    for key in all_keys
        val1 = get_setting_value(settings1, key)
        val2 = get_setting_value(settings2, key)
        if val1 != val2
            return false
        end
    end

    return true
end


"""
    settings_to_string(settings::Dict{UInt16, UInt32}) -> String

Convert settings dictionary to a human-readable string.
"""
function settings_to_string(settings::Dict{UInt16,UInt32})
    parts = String[]

    setting_names = Dict(
        SETTINGS_HEADER_TABLE_SIZE => "HEADER_TABLE_SIZE",
        SETTINGS_ENABLE_PUSH => "ENABLE_PUSH",
        SETTINGS_MAX_CONCURRENT_STREAMS => "MAX_CONCURRENT_STREAMS",
        SETTINGS_INITIAL_WINDOW_SIZE => "INITIAL_WINDOW_SIZE",
        SETTINGS_MAX_FRAME_SIZE => "MAX_FRAME_SIZE",
        SETTINGS_MAX_HEADER_LIST_SIZE => "MAX_HEADER_LIST_SIZE",
    )

    for (id, value) in sort(collect(settings))
        name = get(setting_names, id, "UNKNOWN_$(id)")
        push!(parts, "$name=$value")
    end

    return "{" * join(parts, ", ") * "}"
end

"""
    setting_name(setting_code::UInt16) -> Symbol

Μετατρέπει έναν κωδικό ρύθμισης UInt16 στο αντίστοιχο Symbol.
"""
function setting_name(setting_code::UInt16)
    return get(SETTING_NAMES, setting_code, :UNKNOWN_SETTING)
end


end
