-- prevent wireshark loading this file as a plugin
if not _G['secio_dissector'] then return end

local MSState = {
    dialer = {},
    listener = {},
    listenerMSver = nil,
    dialerMSver = nil,
    protocol = nil,
    supported = false,
    helloPacketId = -1,
    selectPacketId = -1,
    ackPacketId = -1,
    handshaked = false,
}

return MSState
