-- prevent wireshark loading this file as a plugin
if not _G['secio_dissector'] then return end

local MSStates = require("multistream_state")
require("length-prefixed")
require("net_addresses")

multistream_proto = Proto ("multistream", "multistream 1.0.0 protocol")
local fields = multistream_proto.fields

-- Multistream protocol fields
fields.multistream_protocol = ProtoField.string ("multistream.protocol", "Protocol", base.NONE, nil, 0, "Protocol being negotiated on")
fields.multistream_raw_protocol = ProtoField.string ("multistream.raw_protocol", "Raw Protocol", base.NONE, nil, 0, "Protocol being negotiated on (only set on packets with raw data)")
fields.multistream_version = ProtoField.string ("multistream.version", "Version", base.NONE, nil, 0, "Multistream version used")
fields.multistream_dialer = ProtoField.bool ("multistream.dialer", "Dialer", base.NONE, nil, 0, "TRUE if the packet is sent from the dialer")
fields.multistream_listener = ProtoField.bool ("multistream.listener", "Listener", base.NONE, nil, 0, "TRUE if the packet is sent from the listener")
fields.multistream_handshake = ProtoField.bool ("multistream.handshake", "Handshake", base.NONE, nil, 0, "TRUE if the packet is part of the handshake process")
fields.multistream_data = ProtoField.bytes ("multistream.data", "Data", base.NONE, nil, 0, "Raw bytes transferred")

local function dissect_handshake(buffer, pinfo, state)
    local packet_len = buffer:len()
    local is_listener = false

    -- heuristic multistream detector should already set MSState.listener and MSState.dialer fields
    if (is_same_src_address(state.listener, pinfo)) then
        is_listener = true
    elseif (not is_same_src_address(state.dialer, pinfo)) then
        -- some error occured
        print("multistream dissector: ip:port are incorrect")
        return
    end

    if (is_listener) then
        if(state.listenerMSver == nil) then
            -- packet with protocol version
            if (packet_len < 1) then
                -- TODO: reassemble
                return
            end
            local protocol_name, _ = extract_lp_hex_string(buffer)
            if(protocol_name == nil) then
                -- TODO: reassemble
                return
            end

            state.listenerMSver = protocol_name:sub(1, -2)
            state.helloPacketId = pinfo.number
            return
        end
        -- ack/nack packets
        if (packet_len < 1) then
            -- TODO: reassemble
            return
        end
        local protocol_name, _ = extract_lp_hex_string(buffer)
        if(protocol_name == nil) then
            -- TODO: reassemble
            return
        end

        state.supported = protocol_name:sub(1, -2) == state.protocol
        state.handshaked = true
        state.ackPacketId = pinfo.number
        return
    end

    if(state.dialerMSver == nil) then
        -- select packet with protocol version
        if (packet_len < 21) then
            -- TODO: reassemble
            return
        end
        local protocol_name, bytes_len = extract_lp_hex_string(buffer)
        if(protocol_name == nil) then
            -- TODO: reassemble
            return
        end

        local req_protocol_name, tt = extract_lp_hex_string(buffer(bytes_len, -1))
        if(req_protocol_name == nil) then
            -- TODO: reassemble
            return
        end

        state.dialerMSver = protocol_name:sub(1, -2)
        state.protocol = req_protocol_name:sub(1, -2)
        state.selectPacketId = pinfo.number
    end
end

-- this disssector should be called after the "multistream 1.0.0" string observed
function multistream_proto.dissector (buffer, pinfo, tree)
    local state = MSStates:getState(pinfo)
    if (not state) then
        -- it is impossible to continue work without state
        print(string.format("multistream dissector: error while getting state on %s:%s - %s:%s",
            tonumber(pinfo.src),
            tonumber(pinfo.src_port),
            tonumber(pinfo.dst),
            tonumber(pinfo.dst_port)
        ))
        return
    end
    print(state.listener)

    if (not state.handshaked) then
        dissect_handshake(buffer, pinfo, state)
    end

    local subtree = tree:add(multistream_proto, multistream_proto.description)
    local packet_len = buffer:len()
    pinfo.cols.protocol = multistream_proto.name
    pinfo.cols.info = "multistream"

    if (state.helloPacketId == pinfo.number) then
        pinfo.cols.info = string.format("%s ready (%s)", pinfo.cols.info, state.listenerMSver)
        subtree:add(fields.multistream_version, buffer(0, packet_len)):append_text(" (" .. state.listenerMSver .. ")")
    elseif (state.selectPacketId == pinfo.number) then
        pinfo.cols.info = string.format("%s ready (%s) select (%s)", pinfo.cols.info, state.dialerMSver, state.protocol)
        subtree:add(fields.multistream_version, buffer(0, 20)):append_text(" (" .. state.dialerMSver .. ")")
        subtree:add(fields.multistream_protocol, buffer(21, -1)):append_text(" (" .. state.protocol .. ")")
    elseif (state.ackPacketId == pinfo.number) then
        if(state.supported) then
            pinfo.cols.info = string.format("%s ACK (%s)", pinfo.cols.info, state.protocol)
        else
            pinfo.cols.info = string.format("%s NACK", pinfo.cols.info)
        end
        subtree:add(fields.multistream_protocol, buffer(0, packet_len)):append_text(" (" .. state.protocol .. ")")
    else
        if (state.protocol == "/secio/1.0.0") then
            subtree:add(fields.multistream_protocol, buffer(0, 0)):append_text(" (" .. state.protocol .. ")")

            pinfo.private["listener_ip"] = state.listener["ip"]
            pinfo.private["listener_port"] = state.listener["port"]
            pinfo.private["dialer_ip"] = state.dialer["ip"]
            pinfo.private["dialer_port"] = state.dialer["port"]
            Dissector.get("secio"):call(buffer, pinfo, tree)
            return
        end

        if(state.protocol ~= nil) then
            print(string.format("multistream dissector: %s protocol is unsuported", state.protocol))
        else
            print("multistream dissector: underlying protocol is unsuported")
        end
    end
end

-- returns true if some packet contains a length-prefixed string "/multistream/1.0.0\n"
local function m_heuristic_checker(buffer, pinfo, tree)
    local m_ready_packet_size = 0x14
    local packet_len = buffer:len()
    if packet_len < m_ready_packet_size then
        return false
    end

    local protocol_name, byte_count = extract_lp_hex_string(buffer)
    if(byte_count == 0 or protocol_name == nil) then
        return false
    end

    if protocol_name ~= "/multistream/1.0.0\n" then
        return false
    end

    tcp_table = DissectorTable.get ("tcp.port")
    tcp_table:add(pinfo.src_port, multistream_proto)
    tcp_table:add(pinfo.dst_port, multistream_proto)

    local state = MSStates:addNewState(pinfo)

    if packet_len > m_ready_packet_size then
        set_address(state.dialer, pinfo.src, pinfo.src_port)
        set_address(state.listener, pinfo.dst, pinfo.dst_port)
    else
        set_address(state.listener, pinfo.src, pinfo.src_port)
        set_address(state.dialer, pinfo.dst, pinfo.dst_port)
    end
    print(state.listener)

    print(string.format("multistream dissector: dissector for (listener %s:%s) - (dialer %s:%s) registered",
        tostring(state.listener.ip),
        tostring(state.listener.port),
        tostring(state.dialer.ip),
        tostring(state.dialer.port))
    )

    multistream_proto.dissector(buffer, pinfo, tree)
    return true
end

multistream_proto:register_heuristic("udp", m_heuristic_checker)
multistream_proto:register_heuristic("tcp", m_heuristic_checker)
