using Test
using Http2Hpack
using Http2Frames

@testset "Http2Frames.jl - Frame Types and Serialization" begin
    # Test DATA frame
    data = rand(UInt8, 10)
    df = Http2Frames.DataFrame(1, data)
    @test Http2Frames.frame_type(df) == Http2Frames.DATA_FRAME
    @test Http2Frames.stream_id(df) == 1
    @test Http2Frames.serialize_payload(df) == data

    # Test PING frame
    ping_data = rand(UInt8, 8)
    pf = Http2Frames.PingFrame(ping_data)
    @test Http2Frames.frame_type(pf) == Http2Frames.PING_FRAME
    @test Http2Frames.get_ping_data(pf) == ping_data
    @test !Http2Frames.is_ping_ack(pf)
    pf_ack = Http2Frames.PingAckFrame(pf)
    @test Http2Frames.is_ping_ack(pf_ack)
    @test Http2Frames.get_ping_data(pf_ack) == ping_data

    # Test GOAWAY frame
    gaf = Http2Frames.GoAwayFrame(5, Http2Frames.GOAWAY_NO_ERROR)
    @test Http2Frames.frame_type(gaf) == Http2Frames.GOAWAY_FRAME
    @test Http2Frames.stream_id(gaf) == 0
    @test gaf.last_stream_id == 5
    @test gaf.error_code == Http2Frames.GOAWAY_NO_ERROR

    # Test WINDOW_UPDATE frame
    wuf = Http2Frames.WindowUpdateFrame(1, 100)
    @test Http2Frames.frame_type(wuf) == Http2Frames.WINDOW_UPDATE_FRAME
    @test Http2Frames.stream_id(wuf) == 1
    @test wuf.window_size_increment == 100

    # Test PRIORITY frame
    prf = Http2Frames.PriorityFrame(3, false, 1, 10)
    @test Http2Frames.frame_type(prf) == Http2Frames.PRIORITY_FRAME
    @test Http2Frames.stream_id(prf) == 3
    @test prf.stream_dependency == 1
    @test Http2Frames.actual_weight(prf) == UInt8(11)

    # Test SETTINGS frame
    sf = Http2Frames.SettingsFrame(Dict(Http2Frames.SETTINGS_ENABLE_PUSH => 1))
    @test Http2Frames.frame_type(sf) == Http2Frames.SETTINGS_FRAME
    @test Http2Frames.is_ack(sf) == false
    ack_sf = Http2Frames.create_settings_ack()
    @test Http2Frames.is_ack(ack_sf)

    # Test PUSH_PROMISE frame (with Http2Hpack)
    encoder = Http2Hpack.HPACKEncoder()
    headers = ["x-test" => "ok"]
    header_block = Http2Hpack.encode_headers(encoder, headers)
    ppf = Http2Frames.PushPromiseFrame(1, 2, header_block)
    @test Http2Frames.frame_type(ppf) == Http2Frames.PUSH_PROMISE_FRAME
    @test Http2Frames.stream_id(ppf) == 1
    @test ppf.promised_stream_id == 2
    @test ppf.header_block_fragment == header_block

    # Test CONTINUATION frame
    contf = Http2Frames.ContinuationFrame(1, header_block)
    @test Http2Frames.frame_type(contf) == Http2Frames.CONTINUATION_FRAME
    @test Http2Frames.stream_id(contf) == 1
    @test contf.header_block_fragment == header_block

    # Test HEADERS frame (with Http2Hpack)
    hf = Http2Frames.create_headers_frame(1, headers, encoder)
    @test Http2Frames.frame_type(hf) == Http2Frames.HEADERS_FRAME
    @test Http2Frames.stream_id(hf) == 1

    # Test frame serialization/deserialization roundtrip for DATA
    df_bytes = Http2Frames.serialize_frame(df)
    header, payload = Http2Frames.deserialize_frame_header(df_bytes[1:9]), df_bytes[10:end]
    df2 = Http2Frames.create_frame(header, payload)
    @test df2 isa Http2Frames.DataFrame
    @test Http2Frames.serialize_payload(df2) == data

    # --- Error handling and edge cases ---
    @test_throws Http2Frames.ProtocolError Http2Frames.DataFrame(0, data) # DATA frame with stream_id=0
    @test_throws Http2Frames.FrameSizeError Http2Frames.DataFrame(1, data; padded=true, pad_length=20) # Pad length too large
    @test_throws Http2Frames.ProtocolError Http2Frames.DataFrame(1, data; padded=false, pad_length=1) # Pad length without padded flag

    @test_throws Http2Frames.ProtocolError Http2Frames.GoAwayFrame(0x80000000, Http2Frames.GOAWAY_NO_ERROR) # Reserved bit set in last_stream_id

    @test_throws Http2Frames.ProtocolError Http2Frames.PriorityFrame(0, false, 1, 10) # PRIORITY frame with stream_id=0
    @test_throws Http2Frames.ProtocolError Http2Frames.PriorityFrame(3, false, 3, 10) # PRIORITY frame with self-dependency
    @test_throws Http2Frames.FrameSizeError Http2Frames.PriorityFrame(3, false, 1, -1) # PRIORITY frame with weight=0
    @test_throws Http2Frames.FrameSizeError Http2Frames.PriorityFrame(3, false, 1, 257) # PRIORITY frame with weight=257

    @test_throws Http2Frames.ProtocolError Http2Frames.WindowUpdateFrame(1, 0) # WINDOW_UPDATE with increment=0
    @test_throws Http2Frames.FlowControlError Http2Frames.WindowUpdateFrame(1, 0x80000000) # WINDOW_UPDATE with increment too large

    @test_throws Http2Frames.FrameError Http2Frames.SettingsFrame(Dict(Http2Frames.SETTINGS_ENABLE_PUSH => 2)) # SETTINGS_ENABLE_PUSH must be 0 or 1
    @test_throws Http2Frames.SettingsError Http2Frames.SettingsFrame(Dict(Http2Frames.SETTINGS_MAX_FRAME_SIZE => 10000)) # SETTINGS_MAX_FRAME_SIZE too small

    @test_throws Http2Frames.ProtocolError Http2Frames.PushPromiseFrame(0, 2, header_block) # PUSH_PROMISE with stream_id=0
    @test_throws Http2Frames.ProtocolError Http2Frames.ContinuationFrame(0, header_block) # CONTINUATION with stream_id=0
    @test_throws Http2Frames.ProtocolError Http2Frames.ContinuationFrame(Http2Frames.MAX_STREAM_ID+1, header_block) # CONTINUATION with stream_id too large
end
