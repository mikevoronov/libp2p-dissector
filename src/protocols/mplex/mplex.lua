-- prevent wireshark loading this file as a plugin
if not _G['secio_dissector'] then return end

require ("uvarint")
local bit = require ("bit32")

local band = bit.band
local rshift = bit.rshift

local MPLEX_UVARINT_MAX_SIZE = 10

mplex_proto = Proto ("mplex", "MPLEX protocol")

function mplex_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "MPLEX"
    pinfo.cols.info = "MPLEX Body"

    local plain_text = pinfo.private["plain_text"]
    if (plain_text == nil) then
        print("mplex dissector: error while getting plain_text from private field")
        return
    end

    plain_text = ByteArray.new(plain_text)
    plain_text = ByteArray.tvb(plain_text, "plain text")

    local header, headerSize = extractUvarint(plain_text, MPLEX_UVARINT_MAX_SIZE)
    local headerTree = tree:add(buffer(4, headerSize), string.format("MPLEX header: uvarint decoded 0x%X", header))
    headerTree:add(buffer(4, headerSize), string.format("flags 0x%x", band(header, 0x7)))
    headerTree:add(buffer(4, headerSize), string.format("stream id 0x%x", rshift(header, 3)))

    local len, lenSize = extractUvarint(plain_text(headerSize, plain_text:len() - headerSize), MPLEX_UVARINT_MAX_SIZE)
    tree:add(buffer(4 + headerSize, lenSize), string.format("MPLEX len: uvarint decoded 0x%X", len))
    tree:add(buffer(4 + headerSize + lenSize, plain_text:len() - lenSize - headerSize), "content")

end
