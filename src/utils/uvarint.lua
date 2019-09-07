-- prevent wireshark loading this file as a plugin
if not _G['secio_dissector'] then return end

-- TODO: maybe make it a separate lib?

local bit = require ("bit32")

local bor = bit.bor
local band = bit.band
local lshift = bit.lshift

-- extracts uvarint from given byte stream
-- returns uvarint and read bytes count
function extractUvarint(byte_stream, max_len)
    local result = 0

    for offset=0, max_len do
        local byte = byte_stream(offset, 1):uint()
        local cut_byte = band(byte, 0x7F)
        result = bor(result, lshift(cut_byte, offset * 7))
        if byte < 0x80 then
            return result, offset + 1
        end
    end

    -- max byte count handled, but a byte with unset msb hasn't met
    return nil, 0
end
