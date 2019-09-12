-- prevent wireshark loading this file as a plugin
if not _G['libp2p_dissector'] then return end

local config = require ("config")
local utils = require ("secio_misc")
require("net_addresses")

local SecioStates = {}

local function initState(state)
    -- address of a listener peer
    state.listener = {}

    -- address of a dialer peer
    state.dialer = {}

    -- packet id of a listener peer propose packet
    state.listenerProposePacketId = -1

    -- packet id of a dialer peer propose packet
    state.dialerProposePacketId = -1

    -- packet id of a listener peer exchange packet
    state.listenerExchangePacketId = -1

    -- packet id of a dialer peer exchange packet
    state.dialerExchangePacketId = -1

    -- table packet_num -> plain_text
    state.decryptedPayloads = {}

    -- size of listener HMAC in bytes
    state.listenerHMACType = nil

    -- size of dialer HMAC in bytes
    state.dialerHMACType = nil

    -- lambda that can decrypt listener messages
    state.listenerMsgDecryptor = nil

    -- lambda that can decrypt dialer messages
    state.dialerMsgDecryptor = nil

    -- table contains different crypto parameters from the config file
    state.cryptoParams = {}

    -- true, if propose and exchange packets both from listener and dialer have been seen
    state.handshaked = false
end

-- refactor functions related to states to a separate module
function SecioStates:addNewState(pinfo)
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

function SecioStates:getState(pinfo)
    -- check that there is already such state
    local key_1, key_2 = transform_pinfo_to_keys(pinfo)
    if self[key_1] ~= nil then
        return self[key_1]
    end

    return self[key_2]
end

function SecioStates:init_with_mstate(state, mstate)
    state.listener["ip"] = mstate.listener["ip"]
    state.listener["port"] = mstate.listener["port"]
    state.dialer["ip"] = mstate.dialer["ip"]
    state.dialer["port"] = mstate.dialer["port"]
end

function SecioStates:init_crypto_params(state, pinfo)
    state.cryptoParams = config:load_config_for(pinfo.src, pinfo.src_port, pinfo.dst, pinfo.dst_port)
    assert(next(state.cryptoParams) ~= nil, "secio dissector: error while reading config file")

    state.listenerHMACType = state.cryptoParams.local_hmac_type
    state.dialerHMACType = state.cryptoParams.remote_hmac_type
    state.listenerMsgDecryptor = utils:makeMsgDecryptor(
        state.cryptoParams.local_cipher_type,
        state.cryptoParams.local_key,
        state.cryptoParams.local_iv
    )
    state.dialerMsgDecryptor = utils:makeMsgDecryptor(
        state.cryptoParams.remote_cipher_type,
        state.cryptoParams.remote_key,
        state.cryptoParams.remote_iv
    )
end

return SecioStates
