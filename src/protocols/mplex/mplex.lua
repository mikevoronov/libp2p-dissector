-- prevent wireshark loading this file as a plugin
if not _G['secio_dissector'] then return end

require ("uvarint")
local bit = require ("bit32")

local band = bit.band
local rshift = bit.rshift

MPLEX = Proto ("mplex", "MPLEX protocol")

function MPLEX.dissector (buffer, pinfo, tree)
    pinfo.cols.protocol = "MPLEX"
    pinfo.cols.info = "MPLEX Body"

    local header, headerSize = extractUvarint(buffer)
    local headerTree = tree:add(buffer(0, headerSize), string.format("MPLEX header: uvarint decoded 0x%X", header))
    headerTree:add(buffer(0, headerSize), string.format("flags 0x%x", band(header, 0x7)))
    headerTree:add(buffer(0, headerSize), string.format("stream id 0x%x", rshift(header, 3)))

    local len, lenSize = extractUvarint(buffer(headerSize, buffer:len() - headerSize))
    local lenTree = tree:add(buffer(headerSize, lenSize), string.format("MPLEX len: uvarint decoded 0x%X", len))

end
