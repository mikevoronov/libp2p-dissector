-- prevent wireshark loading this file as a plugin
if not _G['secio_dissector'] then return end

local csv = require("csv")
local base64 = require ("base64")

local Config = {
    -- source port
    src_port = "",

    -- destination port
    dst_port = "",

    -- secret key for outgoing connections
    local_key = "",

    -- IV for outgoing connections
    local_iv = "",

    -- MAC for outgoing connections
    local_mac = "",

    -- Cipher type for outgoing connections
    local_ct = "",

    -- Secret key for incomning connections
    remote_key = "",

    -- IV for incomning connections
    remote_iv = "",

    -- Mac for incomning connections
    remote_mac = "",

    -- Cipher type for incomning connections
    remote_ct = ""
}

function Config:load_config(key_file_path)
    local key_file = csv.open(key_file_path)

    for fields in key_file:lines() do
        -- TODO: improve the "algo"
        for i, v in ipairs(fields) do
            if i == 1 then
                self.src_port = v
            elseif i == 2 then
                self.dst_port = v
            elseif i == 3 then
                self.local_key = v
            elseif i == 4 then
                self.local_iv = v
            elseif i == 5 then
                self.local_mac = v
            elseif i == 6 then
                self.local_ct = v
            elseif i == 7 then
                self.remote_key = v
            elseif i == 8 then
                self.remote_iv = v
            elseif i == 9 then
                self.remote_mac = v
            elseif i == 10 then
                self.remote_ct = v
            end
        end
    end

    -- these fields given in the ip:port format
    self.src_port = string.format("%d", string.match(self.src_port, ":(%d+)"))
    self.dst_port = string.format("%d", string.match(self.dst_port, ":(%d+)"))
    self.src_port = tonumber(self.src_port)
    self.dst_port = tonumber(self.dst_port)

    print(self.src_port .. " will be used as the src port")
    print(self.dst_port .. " will be used as the dst port")
    print(self.local_key .. ' will be used as the local key')
    print(self.remote_key .. ' will be used as the remote key')

    self.local_key = base64.decode(self.local_key)
    self.local_iv = base64.decode(self.local_iv)
    self.local_mac = base64.decode(self.local_mac)
    self.remote_key = base64.decode(self.remote_key)
    self.remote_iv = base64.decode(self.remote_iv)
    self.remote_mac = base64.decode(self.remote_mac)
end

return Config
