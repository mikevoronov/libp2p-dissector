-- prevent wireshark loading this file as a plugin
if not _G['secio_dissector'] then return end

require("uvarint")

local VARIANT_MAX_LEN = 8

-- extracts length prefixed buffer from the given buffer
function extract_lp(buffer)
    local string_len, bytes_count = extractUvarint(buffer, VARIANT_MAX_LEN)
    if (string_len == nil) then
        -- return both buffer and resulted varint for debug purpouses
        return nil, bytes_count
    end

    if (buffer:len() < bytes_count + string_len) then
        -- TODO: check variant with reassembling
        return nil, bytes_count
    end

    return buffer(bytes_count, string_len), bytes_count + string_len
end

-- extracts length prefixed string from the given buffer
function extract_lp_string(buffer)
    local extracted_lp, bytes_count = extract_lp(buffer)
    return tostring(extracted_lp), bytes_count
end

-- extracts length prefixed hex string from the given buffer
function extract_lp_hex_string(buffer)
    local function fromhex(str)
        return (str:gsub('..', function (cc)
            return string.char(tonumber(cc, 16))
        end))
    end

    local extracted_lp, bytes_count = extract_lp(buffer)
    return fromhex(tostring(extracted_lp)), bytes_count
end
