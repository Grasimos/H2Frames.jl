# H2Frames.jl

A Julia package for working with HTTP/2 frames, including full support for all RFC 7540 frame types, robust error handling, and HPACK header compression. Suitable for building HTTP/2 protocol implementations, testing, and educational purposes.

## Installation

```julia
using Pkg
Pkg.add("H2Frames")
```

## Usage

```julia
using H2Frames

# --- DATA frame ---
data = [0x01, 0x02, 0x03]
df = DataFrame(1, data; end_stream=true)
bytes = serialize_frame(df)

# --- HEADERS frame with HPACK ---
using Http2Hpack
encoder = Http2Hpack.HPACKEncoder()
headers = ["content-type" => "text/plain", "x-test" => "ok"]
headers_frame = create_headers_frame(1, headers, encoder)

# --- PRIORITY frame ---
priority = PriorityFrame(3, false, 1, 10)

# --- SETTINGS frame ---
settings = SettingsFrame(Dict(SETTINGS_ENABLE_PUSH => 1))

# --- Error handling ---
try
    DataFrame(0, data) # Invalid stream_id
catch e
    @show e
end

# --- GOAWAY frame ---
goaway = GoAwayFrame(5, GOAWAY_NO_ERROR)

# --- WINDOW_UPDATE frame ---
window_update = WindowUpdateFrame(1, 100)

# --- PUSH_PROMISE frame ---
header_block = Http2Hpack.encode_headers(encoder, ["x-test" => "ok"])
push_promise = PushPromiseFrame(1, 2, header_block)

# --- CONTINUATION frame ---
continuation = ContinuationFrame(1, header_block)
```

## Error Types

All errors are subtypes of `FrameException` and include:
- `ProtocolError`
- `FrameSizeError`
- `FlowControlError`
- `CompressionError`
- `SettingsError`
- `UnknownFrameTypeError`
- `FrameError`

## Testing

Run tests with:

```julia
using Pkg
Pkg.test("H2Frames")
```

## Contributing

Contributions, bug reports, and feature requests are welcome! Please open an issue or submit a pull request on GitHub.

## Author

Gerasimos Panou
