-- prevent wireshark loading this file as a plugin
if not _G['secio_dissector'] then return end

-- TODO: maybe make it a separate lib?

local bit = require ("bit32")

local bor = bit.bor
local band = bit.band
local lshift = bit.lshift

-- extracts uvarint from given byte stream
-- returns uvarint and read bytes count
function extractUvarint(byteStream)
    local offset = 0
    local result = 0

    while true do
        local byte = byteStream(offset, 1):uint()
        offset = offset + 1
        byte = band(byte, 0x7F)
        result = bor(result, lshift(byte, offset * 7))
        if byte < 0x80 then
            break
        end
    end

    return result, offset
end
