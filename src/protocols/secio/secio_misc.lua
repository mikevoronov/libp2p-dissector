-- prevent wireshark loading this file as a plugin
if not _G['secio_dissector'] then return end

require("openssl_ffi")
local ffi = require("ffi")
local C = ffi.C
ffi.load("ssl")

local Utils = {}

-- returns lamdba that can decrypt SECIO messages based on the provided cipher settings
function Utils:makeMsgDecryptor(cipher_type, key, iv)
    -- returns lamdba that can decrypt raw cipher text based on the provided parameters
    local function makeDecryptor(cipher_type, key, iv)
        -- initialize the cipher context
        local ctx = C.EVP_CIPHER_CTX_new()
        assert(ctx ~= nil)

        -- set up the cipher type
        if "AES-128" == cipher_type then
            -- EVP_DecryptInit_ex returns 1 if succeed and 0 otherwise
            assert(1 == C.EVP_DecryptInit_ex(ctx, C.EVP_aes_128_ctr(), nil, key, iv))
        elseif "AES-256" == cipher_type then
            -- EVP_DecryptInit_ex returns 1 if succeed and 0 otherwise
            assert(1 == C.EVP_DecryptInit_ex(ctx, C.EVP_aes_256_ctr(), nil, key, iv))
        else
            error('Unsupported cipher type: ' .. cipher_type .. ". At now, only AES-128, AES-256 are supported")
        end

        -- return lamdba that can decrypt supplied cipher text
        return function(cipher_text)
            if not cipher_text then
                print("EVP_CIPHER_CTX_free")
                C.EVP_CIPHER_CTX_free(ctx)
                return
            end

            local cipher_text_len = #cipher_text
            local plain_text = ffi.new("unsigned char[?]", cipher_text_len)
            local ffi_len = ffi.new 'int[1]'
            assert(1 == C.EVP_DecryptUpdate(ctx, plain_text, ffi_len, cipher_text, cipher_text_len))
            return ffi.string(plain_text, ffi_len[0])
        end
    end

    local decryptor = makeDecryptor(cipher_type, key, iv)

    -- return lamdba that can decrypt supplied message
    return function (msg)
        --print("enc len " .. #msg)
        return decryptor(msg)
    end
end

function Utils:hashSize(hmac_type)
    if "SHA256" == hmac_type then
        return 32
    elseif "SHA512" == hmac_type then
        return 64
    else
        error('Unsupported HMAC type: ' .. hmac_type .. ". At now, only SHA256, SHA512 are supported")
    end
end

return Utils
