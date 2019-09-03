-- prevent wireshark loading this file as a plugin
if not _G['secio_dissector'] then return end

local Config = require("config")

MULTISTREAM = Proto ("multistream", "multistream 1.0.0 protocol")

function MULTISTREAM.dissector (buffer, pinfo, tree)
    pinfo.cols.protocol = MULTISTREAM.name

    local subtree = tree:add(MULTISTREAM, MULTISTREAM.description)

end

tcp_table = DissectorTable.get ("tcp.port")
tcp_table:add(Config.src_port, MULTISTREAM)
tcp_table:add(Config.dst_port, MULTISTREAM)
