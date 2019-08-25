-- prevent wireshark loading this file as a plugin
if not _G['secio_dissector'] then return end

local bor = bit.bor
local band = bit.band
local lshift = bit.lshift
local rshift = bit.rshift

MPLEX = Proto ("mplex", "MPLEX protocol")

-- TODO: under constructions
function MPLEX.dissector (buffer, pinfo, tree)
    pinfo.cols.protocol = "MPLEX"
    pinfo.cols.info = "MPLEX Body"

    local tt = band(buffer(0, 1):uint(), 0xFF)
    -- print("stream_id " .. rshift(tt, 3))
    -- print("flags " .. band(tt, 0x7))

end
