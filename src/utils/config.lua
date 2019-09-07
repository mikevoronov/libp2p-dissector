-- prevent wireshark loading this file as a plugin
if not _G['secio_dissector'] then return end

local csv = require("csv")
local base64 = require ("base64")

local Config = {}

function Config:load_config_for(src_ip, src_port, dst_ip, dst_port)
    -- the env variable already checked on the plugin loading stage
    local key_file_path = os.getenv("LIBP2P_SECIO_KEYLOG")
    local key_file = csv.open(key_file_path, {separator = ",", header = true})
    if(key_file == nil) then
        print("libp2p dissector: config reading error")
        return nil
    end

    local src_addr = string.format("%s:%s", tostring(src_ip), tostring(src_port))
    local dst_addr = string.format("%s:%s", tostring(dst_ip), tostring(dst_port))

    local result_record = {}
    for record in key_file:lines() do
        if(
            (record["local_addr"] == src_addr and record["remote_addr"] == dst_addr) or
            (record["remote_addr"] == src_addr and record["local_addr"] == dst_addr)
        ) then
            result_record = record
        end
    end

    if next(result_record) == nil then
        return result_record
    end

    result_record["local_key"] = base64.decode(result_record["local_key"])
    result_record["local_iv"] = base64.decode(result_record["local_iv"])
    result_record["local_mac"] = base64.decode(result_record["local_mac"])
    result_record["remote_key"] = base64.decode(result_record["remote_key"])
    result_record["remote_iv"] = base64.decode(result_record["remote_iv"])
    result_record["remote_mac"] = base64.decode(result_record["remote_mac"])

    return result_record
end

return Config
