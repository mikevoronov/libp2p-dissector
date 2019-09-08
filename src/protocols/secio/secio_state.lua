-- prevent wireshark loading this file as a plugin
if not _G['secio_dissector'] then return end

local config = require ("config")
local utils = require ("secio_misc")

local SecioState = {
    -- address of a listener peer
    listener = {},

    -- address of a dialer peer
    dialer = {},

    -- packet id of a listener peer propose packet
    listenerProposePacketId = -1,

    -- packet id of a dialer peer propose packet
    dialerProposePacketId = -1,

    -- packet id of a listener peer exchange packet
    listenerExchangePacketId = -1,

    -- packet id of a dialer peer exchange packet
    dialerExchangePacketId = -1,

    -- table packet_num -> plain_text
    decryptedPayloads = {},

    -- size of listener HMAC in bytes
    listenerHMACType = nil,

    -- size of dialer HMAC in bytes
    dialerHMACType = nil,

    -- lambda that can decrypt listener messages
    listenerMsgDecryptor = nil,

    -- lambda that can decrypt dialer messages
    dialerMsgDecryptor = nil,

    -- table contains different crypto parameters from the config file
    cryptoParams = {},

    -- true, if propose and exchange packets both from listener and dialer have been seen
    handshaked = false
}

function SecioState:init_with_private(private_table)
    self.listener["ip"] = private_table["listener_ip"]
    self.listener["port"] = private_table["listener_port"]
    self.dialer["ip"] = private_table["dialer_ip"]
    self.dialer["port"] = private_table["dialer_port"]
end

function SecioState:init_crypto_params(pinfo)
    self.cryptoParams = config:load_config_for(pinfo.src, pinfo.src_port, pinfo.dst, pinfo.dst_port)
    assert(next(self.cryptoParams) ~= nil, "secio dissector: error while reading config file")

    self.listenerHMACType = self.cryptoParams.local_hmac_type
    self.dialerHMACType = self.cryptoParams.remote_hmac_type
    self.listenerMsgDecryptor = utils:makeMsgDecryptor(
        self.cryptoParams.local_cipher_type,
        self.cryptoParams.local_key,
        self.cryptoParams.local_iv
    )
    self.dialerMsgDecryptor = utils:makeMsgDecryptor(
        self.cryptoParams.remote_cipher_type,
        self.cryptoParams.remote_key,
        self.cryptoParams.remote_iv
    )
end

return SecioState
