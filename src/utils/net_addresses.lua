-- prevent wireshark loading this file as a plugin
if not _G['secio_dissector'] then return end

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
