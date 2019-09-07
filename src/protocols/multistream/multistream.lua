-- prevent wireshark loading this file as a plugin
if not _G['secio_dissector'] then return end

local config = require("config")
local MSState = require("multistream_state")

require("length-prefixed")
require("net_addresses")

multistream_proto = Proto ("multistream", "multistream 1.0.0 protocol")
local fields = multistream_proto.fields

-- Multistream fields
fields.multistream_protocol = ProtoField.string ("multistream.protocol", "Protocol", base.NONE, nil, 0, "Protocol being negotiated on")
fields.multistream_raw_protocol = ProtoField.string ("multistream.raw_protocol", "Raw Protocol", base.NONE, nil, 0, "Protocol being negotiated on (only set on packets with raw data)")
fields.multistream_version = ProtoField.string ("multistream.version", "Version", base.NONE, nil, 0, "Multistream version used")
fields.multistream_dialer = ProtoField.bool ("multistream.dialer", "Dialer", base.NONE, nil, 0, "TRUE if the packet is sent from the dialer")
fields.multistream_listener = ProtoField.bool ("multistream.listener", "Listener", base.NONE, nil, 0, "TRUE if the packet is sent from the listener")
fields.multistream_handshake = ProtoField.bool ("multistream.handshake", "Handshake", base.NONE, nil, 0, "TRUE if the packet is part of the handshake process")
fields.multistream_data = ProtoField.bytes ("multistream.data", "Data", base.NONE, nil, 0, "Raw bytes transferred")

local function dissect_handshake(buffer, pinfo, is_listener)
    local packet_len = buffer:len()

    if (is_listener == true) then
        if(MSState.listenerMSver == nil) then
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

            MSState.listenerMSver = protocol_name:sub(1, -2)
            MSState.helloPacketId = pinfo.number
        else
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

            MSState.supported = protocol_name:sub(1, -2) == MSState.protocol
            MSState.handshaked = true
            MSState.ackPacketId = pinfo.number
        end
        return
    end

    if(MSState.dialerMSver == nil) then
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

        MSState.dialerMSver = protocol_name:sub(1, -2)
        MSState.protocol = req_protocol_name:sub(1, -2)
        MSState.selectPacketId = pinfo.number
    end
end

-- this disssector should be called after the "multistream 1.0.0" string observed
function multistream_proto.dissector (buffer, pinfo, tree)
    local listener = false

    -- heuristic multistream detector should already set MSState.listener and MSState.dialer fields
    if(is_same_src_address(MSState.listener, pinfo)) then
        listener = true
    elseif(not is_same_src_address(MSState.dialer, pinfo)) then
        -- some error occured
        print("multistream dissector: ip:port are incorrect")
        return
    end

    if(MSState.handshaked == false) then
        dissect_handshake(buffer, pinfo, listener)
    end

    local subtree = tree:add(multistream_proto, multistream_proto.description)
    local packet_len = buffer:len()
    pinfo.cols.protocol = multistream_proto.name
    pinfo.cols.info = "multistream"
    if (MSState.helloPacketId == pinfo.number) then
        pinfo.cols.info = string.format("%s ready (%s)", pinfo.cols.info, MSState.listenerMSver)
        subtree:add(fields.multistream_version, buffer(0, packet_len)):append_text(" (" .. MSState.listenerMSver .. ")")
    elseif (MSState.selectPacketId == pinfo.number) then
        pinfo.cols.info = string.format("%s ready (%s) select (%s)", pinfo.cols.info, MSState.dialerMSver, MSState.protocol)
        subtree:add(fields.multistream_version, buffer(0, 20)):append_text(" (" .. MSState.dialerMSver .. ")")
        subtree:add(fields.multistream_protocol, buffer(21, -1)):append_text(" (" .. MSState.protocol .. ")")
    elseif (MSState.ackPacketId == pinfo.number) then
        if(MSState.supported) then
            pinfo.cols.info = string.format("%s ACK (%s)", pinfo.cols.info, MSState.protocol)
        else
            pinfo.cols.info = string.format("%s NACK", pinfo.cols.info)
        end
        subtree:add(fields.multistream_protocol, buffer(0, packet_len)):append_text(" (" .. MSState.protocol .. ")")
    else
        if (MSState.protocol == "/secio/1.0.0") then
            Dissector.get("secio"):call(buffer, pinfo, tree)
            return
        end

        error(MSState.protocol .. " protocol is unsuported")
    end
end

-- returns true if some packet contains a length-prefixed string "/multistream/1.0.0\n"
local function m_heuristic_checker(buffer, pinfo, tree)
    packet_len = buffer:len()
    if packet_len ~= 0x14 then
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

    -- TODO: add to MSState support of multi ip/port
    set_address(MSState.listener, pinfo.src, pinfo.src_port)
    set_address(MSState.dialer, pinfo.dst, pinfo.dst_port)

    multistream_proto.dissector(buffer, pinfo, tree)
    return true
end

multistream_proto:register_heuristic("udp", m_heuristic_checker)
multistream_proto:register_heuristic("tcp", m_heuristic_checker)
