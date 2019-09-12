-- prevent wireshark loading this file as a plugin
if not _G['libp2p_dissector'] then return end

function is_same_addresses(table, ip, port)
    return next(table) ~= nil and table["ip"] == tostring(ip) and table["port"] == tostring(port)
end

function is_same_src_address(table, pinfo)
    return is_same_addresses(table, pinfo.src, pinfo.src_port)
end

function is_same_dst_address(table, pinfo)
    return is_same_addresses(table, pinfo.dst, pinfo.dst_port)
end

function set_address(table, ip, port)
    table["ip"] = tostring(ip)
    table["port"] = tostring(port)
end

function transform_pinfo_to_keys(pinfo)
    local key_1 = string.format("%s:%s:%s:%s", pinfo.src, pinfo.src_port, pinfo.dst, pinfo.dst_port)
    local key_2 = string.format("%s:%s:%s:%s", pinfo.dst, pinfo.dst_port, pinfo.src, pinfo.src_port)
    return key_1, key_2
end
