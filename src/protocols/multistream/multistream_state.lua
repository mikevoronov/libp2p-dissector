-- prevent wireshark loading this file as a plugin
if not _G['secio_dissector'] then return end

local MSState = {
    -- address of a listener peer
    listener = {},

    -- address of a dialer peer
    dialer = {},

    -- multistream protocol version of a listener peer
    listenerMSver = nil,

    -- multistream protocol version of a dieler peer
    dialerMSver = nil,

    -- synchronized protocol version
    protocol = nil,

    -- true, if dialer supports proposal protocol
    supported = false,

    -- number of a hello packet
    helloPacketId = -1,

    -- number of a select packet
    selectPacketId = -1,

    -- number of a ack packet
    ackPacketId = -1,

    -- true, if all of hello, select and ack packets have been seen
    handshaked = false,
}

return MSState
