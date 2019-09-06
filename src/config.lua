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

    -- HMAC type for outgoing connections
    local_hmac_type = "",

    -- Cipher type for outgoing connections
    local_cipher_type = "",

    -- Secret key for incomning connections
    remote_key = "",

    -- IV for incomning connections
    remote_iv = "",

    -- Mac for incomning connections
    remote_mac = "",

    -- Cipher type for incomning connections
    remote_cipher_type = "",

    -- HMAC type for incomning connections
    remote_hmac_type = ""
}

function Config:load_config(key_file_path)
    local key_file = csv.open(key_file_path, {separator = ",", header = true})

    for record in key_file:lines() do
        -- there are several emtpy strings on valid file - looks like a bug in the csv lib
        if(record["local_addr"] ~= "") then
            self.src_port = record["local_addr"]
            self.dst_port = record["remote_addr"]
            self.local_key = record["local_key"]
            self.local_iv = record["local_iv"]
            self.local_cipher_type = record["local_cipher_type"]
            self.local_mac = record["local_mac"]
            self.local_hmac_type = record["local_hmac_type"]
            self.remote_key = record["remote_key"]
            self.remote_iv = record["remote_iv"]
            self.remote_cipher_type = record["remote_cipher_type"]
            self.remote_mac = record["local_mac"]
            self.remote_hmac_type = record["local_hmac_type"]
        end
    end

    -- local_addr and remote_addr are given in the ip:port format
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
