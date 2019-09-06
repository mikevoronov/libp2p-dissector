-- prevent wireshark loading this file as a plugin
if not _G['secio_dissector'] then return end

local MultistreamState = {
    handshaked = false,
    dialer = "",
    listener = "",
    listenerMSver = "",
    dialerMSver = "",
    protocol = "",
    supported = false,

}

-- function MultistreamState:
