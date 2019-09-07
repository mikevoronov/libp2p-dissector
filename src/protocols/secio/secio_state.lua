-- prevent wireshark loading this file as a plugin
if not _G['secio_dissector'] then return end

local SecioState = {
    listener = {},
    dialer = {},
    listenerProposePacketId = -1,
    dialerProposePacketId = -1,
    listenerExchangePacketId = -1,
    dialerExchangePacketId = -1,
    decryptedPayloads = {},
    crypto_params = nil,
    listener_hmac_size = -1,
    dialer_hmac_size = -1,
    listenerMsgDecryptor = nil,
    dialerMsgDecryptor = nil
}

return SecioState
