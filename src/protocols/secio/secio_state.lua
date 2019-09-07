-- prevent wireshark loading this file as a plugin
if not _G['secio_dissector'] then return end

local config = require ("config")
local utils = require ("secio_misc")

local SecioState = {
    listener = {},
    dialer = {},
    listenerProposePacketId = -1,
    dialerProposePacketId = -1,
    listenerExchangePacketId = -1,
    dialerExchangePacketId = -1,
    decryptedPayloads = {},
    listener_hmac_size = -1,
    dialer_hmac_size = -1,
    listenerMsgDecryptor = nil,
    dialerMsgDecryptor = nil,
    crypto_params = {},
    handshaked = false
}

function SecioState:init_with_private(private_table)
    self.listener["ip"] = private_table["listener_ip"]
    self.listener["port"] = private_table["listener_port"]
    self.dialer["ip"] = private_table["dialer_ip"]
    self.dialer["port"] = private_table["dialer_port"]
end

function SecioState:init_crypto_params(pinfo)
    print("secio dissector: crypto init")
    self.crypto_params = config:load_config_for(pinfo.src, pinfo.src_port, pinfo.dst, pinfo.dst_port)
    assert(next(self.crypto_params) ~= nil, "secio dissector: error while reading config file")

    self.listener_hmac_size = utils:hashSize(self.crypto_params.local_hmac_type)
    self.dialer_hmac_size = utils:hashSize(self.crypto_params.remote_hmac_type)
    self.listenerMsgDecryptor = utils:makeMsgDecryptor(
        self.crypto_params.local_cipher_type,
        self.crypto_params.local_key,
        self.crypto_params.local_iv
    )
    self.dialerMsgDecryptor = utils:makeMsgDecryptor(
        self.crypto_params.remote_cipher_type,
        self.crypto_params.remote_key,
        self.crypto_params.remote_iv
    )
end

return SecioState
