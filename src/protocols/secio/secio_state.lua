-- prevent wireshark loading this file as a plugin
if not _G['secio_dissector'] then return end

local SecioState = {
    listenerProposePacketId = -1,
    dialerProposePacketId = -1,
    listenerExchangePacketId = -1,
    dialerExchangePacketId = -1,
    decryptedPayloads = {},
}

return SecioState
