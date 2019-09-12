-- prevent wireshark loading this file as a plugin
if not _G['libp2p_dissector'] then return end
require("net_addresses")

local MSStates = {}

local function initState(state)
    -- address of a listener peer
    state.listener = {}

    -- address of a dialer peer
    state.dialer = {}

    -- multistream protocol version of a listener peer
    state.listenerMSver = nil

    -- multistream protocol version of a dieler peer
    state.dialerMSver = nil

    -- synchronized protocol version
    state.protocol = nil

    -- true, if dialer supports proposal protocol
    state.supported = false

    -- number of a hello packet
    state.helloPacketId = -1

    -- number of a select packet
    state.selectPacketId = -1

    -- number of a ack packet
    state.ackPacketId = -1

    -- true, if all of hello, select and ack packets have been seen
    state.handshaked = false
end

function MSStates:addNewState(pinfo)
    -- check that there is already such state
    local key_1, key_2 = transform_pinfo_to_keys(pinfo)
    if self[key_1] ~= nil then
        return self[key_1]
    elseif self[key_2] ~= nil then
        return self[key_2]
    end
    self[key_1] = {}
    initState(self[key_1])

    return self[key_1]
end

function MSStates:getState(pinfo)
    -- check that there is already such state
    local key_1, key_2 = transform_pinfo_to_keys(pinfo)
    if self[key_1] ~= nil then
        return self[key_1]
    end

    return self[key_2]
end

return MSStates
